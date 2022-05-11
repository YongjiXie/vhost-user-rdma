/*
 * Vhost-user RDMA device demo: udp/ip stack
 *
 * Copyright (C) 2022 Bytedance Inc. and/or its affiliates. All rights reserved.
 *
 * Author: Wei Junji <weijunji@bytedance.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include "vhost_rdma.h"
#include "vhost_rdma_hdr.h"
#include "vhost_rdma_loc.h"

static __rte_always_inline
void default_gid_to_mac(struct vhost_rdma_dev *dev, char *mac) {
	struct vhost_rdma_gid *gid = &dev->gid_tbl[0];

	mac[0] = gid->gid[8];
	mac[1] = gid->gid[9];
	mac[2] = gid->gid[10];
	mac[3] = gid->gid[13];
	mac[4] = gid->gid[14];
	mac[5] = gid->gid[15];
}

/**************** pkt recv ******************/

static __rte_always_inline int
vhost_rdma_recv_udp(struct vhost_rdma_dev *dev, struct rte_mbuf *mbuf)
{
	struct rte_udp_hdr *udph;
	struct vhost_rdma_pkt_info *pkt = MBUF_TO_PKT(mbuf);

	if (rte_pktmbuf_linearize(mbuf)) {
		RDMA_LOG_ERR("pktmbuf_linearize failed");
		goto drop;
	}

	udph = rte_pktmbuf_mtod(mbuf, struct rte_udp_hdr *);
	rte_pktmbuf_adj(mbuf, sizeof(struct rte_udp_hdr));
	pkt->dev = dev;
	pkt->port_num = 1;
	pkt->hdr = (uint8_t *)(udph + 1);
	pkt->mask = VHOST_GRH_MASK;
	pkt->paylen = rte_be_to_cpu_16(udph->dgram_len) - sizeof(*udph);

	vhost_rdma_rcv(mbuf);

	return 0;
drop:
	rte_pktmbuf_free(mbuf);

	return 0;
}

static __rte_always_inline void
vhost_rdma_recv_ipv4(struct vhost_rdma_dev *dev, struct rte_mbuf *pkt)
{
	struct rte_ipv4_hdr *hdr;

	hdr = rte_pktmbuf_mtod(pkt, struct rte_ipv4_hdr *);
	rte_pktmbuf_adj(pkt, rte_ipv4_hdr_len(hdr));

	if (hdr->next_proto_id == IPPROTO_UDP) {
		uint32_t plen, trim;
		// remove tail padding
		plen = rte_be_to_cpu_16(hdr->total_length);
		if (plen < pkt->pkt_len) {
			trim = pkt->pkt_len - plen;
			rte_pktmbuf_trim(pkt, trim);
		}
		pkt->l3_type = VHOST_NETWORK_TYPE_IPV4;
		vhost_rdma_recv_udp(dev, pkt);
	} else {
		RDMA_LOG_INFO("not udp pkt should not be here");
		rte_pktmbuf_free(pkt);
	}
}

static __rte_always_inline void
vhost_rdma_recv_ipv6(struct vhost_rdma_dev *dev, struct rte_mbuf *pkt)
{
	struct rte_ipv6_hdr *hdr;

	hdr = rte_pktmbuf_mtod(pkt, struct rte_ipv6_hdr *);
	rte_pktmbuf_adj(pkt, sizeof(struct rte_ipv6_hdr));

	if (hdr->proto == IPPROTO_UDP) {
		uint32_t plen, trim;
		// remove tail padding
		plen = rte_be_to_cpu_16(hdr->payload_len) + sizeof(*hdr);
		if (plen < pkt->pkt_len) {
			trim = pkt->pkt_len - plen;
			rte_pktmbuf_trim(pkt, trim);
		}
		pkt->l3_type = VHOST_NETWORK_TYPE_IPV6;
		vhost_rdma_recv_udp(dev, pkt);
	} else {
		RDMA_LOG_ERR("not udp pkt should not be here");
		rte_pktmbuf_free(pkt);
	}
}

void
vhost_rdma_net_recv(struct vhost_rdma_dev *dev, struct rte_mbuf *pkt)
{
	struct rte_ether_hdr *hdr;
	uint16_t type;

	hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	rte_pktmbuf_adj(pkt, sizeof(struct rte_ether_hdr));

	type = rte_be_to_cpu_16(hdr->ether_type);

	if (type == RTE_ETHER_TYPE_IPV4) {
		vhost_rdma_recv_ipv4(dev, pkt);
	} else if (type == RTE_ETHER_TYPE_IPV6) {
		vhost_rdma_recv_ipv6(dev, pkt);
	} else {
		// not rdma pkts
		RDMA_LOG_ERR("not ip pkt should not be here");
		rte_pktmbuf_free(pkt);
	}
}

/**************** pkt send ******************/

static int
ip_out(struct vhost_rdma_pkt_info *pkt, struct rte_mbuf* mbuf, uint16_t type)
{
	struct rte_ether_hdr *ether;

	ether = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*ether));

	ether->ether_type = rte_cpu_to_be_16(type);
	default_gid_to_mac(pkt->dev, (char*)&ether->s_addr);
	rte_memcpy(&ether->d_addr, vhost_rdma_get_av(pkt)->dmac, 6);

	// IP checksum offload
	mbuf->ol_flags = PKT_TX_IP_CKSUM;
	if (type == RTE_ETHER_TYPE_IPV4) {
		mbuf->ol_flags |= PKT_TX_IPV4;
		mbuf->l3_len = sizeof(struct rte_ipv4_hdr);
	} else {
		mbuf->ol_flags |= PKT_TX_IPV6;
		mbuf->l3_len = sizeof(struct rte_ipv6_hdr);
	}
	mbuf->l4_len = sizeof(struct rte_udp_hdr);
	mbuf->l2_len = sizeof(struct rte_ether_hdr);

	rte_ring_enqueue(pkt->dev->tx_ring, mbuf);

	return 0;
}

int
vhost_rdma_send(struct vhost_rdma_pkt_info *pkt, struct rte_mbuf *mbuf)
{
	int err;
	int mbuf_out;
	struct vhost_rdma_qp *qp = pkt->qp;

	RDMA_LOG_DEBUG_DP("vhost rdma send packet: qpn: %u qp type: %u opcode: %u psn: %u\n",
			  qp->qpn, qp->type, pkt->opcode, pkt->psn);

	vhost_rdma_add_ref(qp);
	rte_atomic32_inc(&pkt->qp->mbuf_out);

	if (mbuf->l3_type == VHOST_NETWORK_TYPE_IPV4) {
		err = ip_out(pkt, mbuf, RTE_ETHER_TYPE_IPV4);
	} else if (mbuf->l3_type == VHOST_NETWORK_TYPE_IPV6) {
		err = ip_out(pkt, mbuf, RTE_ETHER_TYPE_IPV6);
	} else {
		RDMA_LOG_ERR_DP("Unknown layer 3 protocol: %u\n", mbuf->l3_type);
		vhost_rdma_drop_ref(qp, qp->dev, qp);
		rte_pktmbuf_free(mbuf);
		return -EINVAL;
	}

	mbuf_out = rte_atomic32_sub_return(&pkt->qp->mbuf_out, 1);
	if (unlikely(pkt->qp->need_req_mbuf &&
			mbuf_out < VHOST_INFLIGHT_SKBS_PER_QP_LOW))
		vhost_rdma_run_task(&pkt->qp->req.task, 1);

	vhost_rdma_drop_ref(qp, qp->dev, qp);

	if (unlikely(err)) {
		RDMA_LOG_ERR_DP("ip out failed");
		return -EAGAIN;
	}

	return 0;
}

void
vhost_rdma_loopback(struct rte_mbuf *m)
{
	if (m->l3_type == VHOST_NETWORK_TYPE_IPV4)
		rte_pktmbuf_adj(m, sizeof(struct rte_ipv4_hdr));
	else
		rte_pktmbuf_adj(m, sizeof(struct rte_ipv6_hdr));

	vhost_rdma_rcv(m);
}

/****************** pkt init ******************/

struct rte_mbuf*
vhost_rdma_init_packet(struct vhost_rdma_dev *dev, struct vhost_rdma_av *av,
				int paylen, struct vhost_rdma_pkt_info *pkt)
{
	unsigned int hdr_len;
	struct rte_mbuf *mbuf = NULL;
	const struct vhost_rdma_gid *attr;
	const int port_num = 1;
	uint16_t data_room;

	attr = &dev->gid_tbl[av->grh.sgid_index];
	
	if (attr->type == VHOST_RDMA_GID_TYPE_ILLIGAL)
		return NULL;

	if (av->network_type == VHOST_NETWORK_TYPE_IPV4)
		hdr_len = ETH_HLEN + sizeof(struct rte_udp_hdr) +
			sizeof(struct rte_ipv4_hdr);
	else
		hdr_len = ETH_HLEN + sizeof(struct rte_udp_hdr) +
			sizeof(struct rte_ipv6_hdr);

	hdr_len += sizeof(struct rte_ether_hdr);

	mbuf = rte_pktmbuf_alloc(dev->mbuf_pool);

	if (unlikely(mbuf == NULL)) {
		goto out;
	}

	if (unlikely(hdr_len > rte_pktmbuf_headroom(mbuf))) {
		RDMA_LOG_ERR_DP("no enough head room %u > %u", hdr_len,
			rte_pktmbuf_headroom(mbuf));
		rte_pktmbuf_free(mbuf);
		return NULL;
	}

	data_room = mbuf->buf_len - rte_pktmbuf_headroom(mbuf);
	if (unlikely(paylen > data_room)) {
		RDMA_LOG_ERR_DP("no enough data room %u > %u", paylen, data_room);
		rte_pktmbuf_free(mbuf);
		return NULL;
	}

	if (av->network_type == VHOST_NETWORK_TYPE_IPV4)
		mbuf->l3_type = VHOST_NETWORK_TYPE_IPV4;
	else
		mbuf->l3_type = VHOST_NETWORK_TYPE_IPV6;

	pkt->dev	= dev;
	pkt->port_num	= port_num;
	pkt->hdr	= (uint8_t *)rte_pktmbuf_adj(mbuf, 0);
	pkt->mask	|= VHOST_GRH_MASK;

	rte_pktmbuf_data_len(mbuf) = paylen;

out:
	return mbuf;
}

static void prepare_udp_hdr(struct rte_mbuf *m, rte_be16_t src_port,
				rte_be16_t dst_port)
{
	struct rte_udp_hdr *udph;

	udph = (struct rte_udp_hdr *)rte_pktmbuf_prepend(m, sizeof(*udph));

	udph->dst_port = dst_port;
	udph->src_port = src_port;
	udph->dgram_len = rte_cpu_to_be_16(m->data_len);
	udph->dgram_cksum = 0;
}

static void prepare_ipv4_hdr(struct rte_mbuf *m, rte_be32_t saddr,
	rte_be32_t daddr, uint8_t proto, uint8_t tos, uint8_t ttl, rte_be16_t df)
{
	struct rte_ipv4_hdr *iph;

	iph = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(m, sizeof(*iph));

	iph->version_ihl		=	RTE_IPV4_VHL_DEF;
	iph->total_length		=	rte_cpu_to_be_16(m->data_len);
	iph->fragment_offset	=	df;
	iph->next_proto_id		=	proto;
	iph->type_of_service	=	tos;
	iph->dst_addr			=	daddr;
	iph->src_addr			=	saddr;
	iph->time_to_live		=	ttl;
}

static inline void ip6_flow_hdr(struct rte_ipv6_hdr *hdr, unsigned int tclass,
				rte_be32_t flowlabel)
{
	*(rte_be32_t *)hdr = rte_cpu_to_be_32(0x60000000 | (tclass << 20))|flowlabel;
}

static void
prepare_ipv6_hdr(struct rte_mbuf *m, struct in6_addr *saddr,
		struct in6_addr *daddr, uint8_t proto, uint8_t prio, uint8_t ttl)
{
	struct rte_ipv6_hdr *ip6h;

	ip6h = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(m, sizeof(*ip6h));

	ip6_flow_hdr(ip6h, prio, rte_cpu_to_be_32(0));
	ip6h->proto     = proto;
	ip6h->hop_limits   = ttl;
	rte_memcpy(ip6h->dst_addr, daddr, sizeof(*daddr));
	rte_memcpy(ip6h->src_addr, saddr, sizeof(*daddr));
	ip6h->payload_len = rte_cpu_to_be_16(m->data_len - sizeof(*ip6h));
}

static int
prepare4(struct vhost_rdma_pkt_info *pkt, struct rte_mbuf *m)
{
	struct vhost_rdma_qp *qp = pkt->qp;
	struct vhost_rdma_av *av = vhost_rdma_get_av(pkt);
	struct in_addr *saddr = &av->sgid_addr._sockaddr_in.sin_addr;
	struct in_addr *daddr = &av->dgid_addr._sockaddr_in.sin_addr;
	rte_be16_t df = rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG);

	prepare_udp_hdr(m, rte_cpu_to_be_16(qp->src_port),
			rte_cpu_to_be_16(ROCE_V2_UDP_DPORT));

	// FIXME: check addr
	prepare_ipv4_hdr(m, saddr->s_addr, daddr->s_addr, IPPROTO_UDP,
			 av->grh.traffic_class, av->grh.hop_limit, df);

	return 0;
}

static int
prepare6(struct vhost_rdma_pkt_info *pkt, struct rte_mbuf *m)
{
	struct vhost_rdma_qp *qp = pkt->qp;
	struct vhost_rdma_av *av = vhost_rdma_get_av(pkt);
	struct in6_addr *saddr = &av->sgid_addr._sockaddr_in6.sin6_addr;
	struct in6_addr *daddr = &av->dgid_addr._sockaddr_in6.sin6_addr;

	prepare_udp_hdr(m, rte_cpu_to_be_16(qp->src_port),
			rte_cpu_to_be_16(ROCE_V2_UDP_DPORT));

	prepare_ipv6_hdr(m, saddr, daddr, IPPROTO_UDP,
			 av->grh.traffic_class,
			 av->grh.hop_limit);

	return 0;
}

int
vhost_rdma_prepare(struct vhost_rdma_pkt_info *pkt, struct rte_mbuf *m,
				uint32_t *crc)
{
	int err = 0;
	char dev_mac[6];

	if (m->l3_type == VHOST_NETWORK_TYPE_IPV4)
		err = prepare4(pkt, m);
	else if (m->l3_type == VHOST_NETWORK_TYPE_IPV6)
		err = prepare6(pkt, m);

	*crc = vhost_rdma_icrc_hdr(pkt, m);

	default_gid_to_mac(pkt->dev, dev_mac);

	if (memcmp(dev_mac, vhost_rdma_get_av(pkt)->dmac, 6) == 0) {
		pkt->mask |= VHOST_LOOPBACK_MASK;
	}

	return err;
}
