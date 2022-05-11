/*
 * Vhost-user RDMA device demo: rocev2 pkt pre check
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

#include  <arpa/inet.h>

#include "vhost_rdma.h"
#include "vhost_rdma_ib.h"
#include "vhost_rdma_loc.h"
#include "vhost_rdma_hdr.h"

const struct vhost_rdma_gid *
rdma_find_gid_by_port(struct vhost_rdma_dev *dev,
		      uint8_t *gid,
		      enum ib_gid_type gid_type,
		      uint32_t port)
{
	struct vhost_rdma_gid *attr;

	if (port != 1)
		return NULL;

	for (int i = 0; i < VHOST_MAX_GID_TBL_LEN; i++) {
		attr = &dev->gid_tbl[i];
		if (attr->type != gid_type)
			continue;

		if (memcmp(attr->gid, gid, sizeof(attr->gid)) == 0)
			return attr;
	}

	return NULL;
}

static int
vhost_rdma_chk_dgid(struct vhost_rdma_dev *dev, struct rte_mbuf *mbuf)
{
	struct vhost_rdma_pkt_info *pkt = MBUF_TO_PKT(mbuf);
	const struct vhost_rdma_gid *gid_attr;
	uint8_t dgid[16];
	uint8_t *pdgid;

	if (pkt->mask & VHOST_LOOPBACK_MASK)
		return 0;

	if (mbuf->l3_type == VHOST_NETWORK_TYPE_IPV4) {
		// RDMA_LOG_DEBUG_DP("dest ip address: %s",
		//		inet_ntoa(*(struct in_addr*)&ip_hdr(pkt)->dst_addr));
		ipv6_addr_set_v4mapped(ip_hdr(pkt)->dst_addr,
						(struct in6_addr *)dgid);
		pdgid = &dgid[0];
	} else {
		pdgid = &(ipv6_hdr(pkt)->dst_addr[0]);
	}

	if (rdma_is_multicast_addr((struct in6_addr *)pdgid))
		return 0;

	gid_attr = rdma_find_gid_by_port(dev, pdgid, IB_GID_TYPE_ROCE_UDP_ENCAP, 1);
	if (gid_attr == NULL)
		return -ENOENT;

	return 0;
}

static int check_type_state(struct vhost_rdma_pkt_info *pkt,
				struct vhost_rdma_qp *qp)
{
	unsigned int pkt_type;

	if (unlikely(!qp->valid))
		goto err1;

	pkt_type = pkt->opcode & 0xe0;

	switch (qp->type) {
	case VIRTIO_IB_QPT_RC:
		if (unlikely(pkt_type != IB_OPCODE_RC)) {
			RDMA_LOG_ERR_DP("bad qp type\n");
			goto err1;
		}
		break;
	case VIRTIO_IB_QPT_UC:
		if (unlikely(pkt_type != IB_OPCODE_UC)) {
			RDMA_LOG_ERR_DP("bad qp type\n");
			goto err1;
		}
		break;
	case VIRTIO_IB_QPT_UD:
	case VIRTIO_IB_QPT_SMI:
	case VIRTIO_IB_QPT_GSI:
		if (unlikely(pkt_type != IB_OPCODE_UD)) {
			RDMA_LOG_ERR_DP("bad qp type\n");
			goto err1;
		}
		break;
	default:
		RDMA_LOG_ERR_DP("unsupported qp type\n");
		goto err1;
	}

	if (pkt->mask & VHOST_REQ_MASK) {
		if (unlikely(qp->resp.state != QP_STATE_READY))
			goto err1;
	} else if (unlikely(qp->req.state < QP_STATE_READY ||
				qp->req.state > QP_STATE_DRAINED)) {
		goto err1;
	}

	return 0;

err1:
	return -EINVAL;
}

static inline int pkey_match(uint16_t key1, uint16_t key2)
{
	return (((key1 & 0x7fff) != 0) &&
		((key1 & 0x7fff) == (key2 & 0x7fff)) &&
		((key1 & 0x8000) || (key2 & 0x8000))) ? 1 : 0;
}

static void set_bad_pkey_cntr(struct vhost_rdma_dev *dev)
{
	rte_spinlock_lock(&dev->port_lock);
	dev->port_attr.bad_pkey_cntr = RTE_MIN((uint32_t)0xffff,
						dev->port_attr.bad_pkey_cntr + 1);
	rte_spinlock_unlock(&dev->port_lock);
}

static void set_qkey_viol_cntr(struct vhost_rdma_dev *dev)
{
	rte_spinlock_lock(&dev->port_lock);
	dev->port_attr.qkey_viol_cntr = RTE_MIN((uint32_t)0xffff,
					dev->port_attr.qkey_viol_cntr + 1);
	rte_spinlock_unlock(&dev->port_lock);
}

static int
check_keys(struct vhost_rdma_dev *dev, struct vhost_rdma_pkt_info *pkt,
	   uint32_t qpn, struct vhost_rdma_qp *qp)
{
	uint16_t pkey = bth_pkey(pkt);

	pkt->pkey_index = 0;

	if (!pkey_match(pkey, IB_DEFAULT_PKEY_FULL)) {
		RDMA_LOG_ERR_DP("bad pkey = 0x%x\n", pkey);
		set_bad_pkey_cntr(dev);
		goto err1;
	}

	if (qp->type == VIRTIO_IB_QPT_UD || qp->type == VIRTIO_IB_QPT_GSI) {
		uint32_t qkey = (qpn == 1) ? GSI_QKEY : qp->attr.qkey;

		if (unlikely(deth_qkey(pkt) != qkey)) {
			RDMA_LOG_ERR_DP("bad qkey, got 0x%x expected 0x%x for qpn 0x%x\n",
					    deth_qkey(pkt), qkey, qpn);
			set_qkey_viol_cntr(dev);
			goto err1;
		}
	}

	return 0;

err1:
	return -EINVAL;
}

static int
check_addr(struct vhost_rdma_pkt_info *pkt, struct vhost_rdma_qp *qp)
{
	struct rte_mbuf *mbuf = PKT_TO_MBUF(pkt);

	if (qp->type != VIRTIO_IB_QPT_RC && qp->type != VIRTIO_IB_QPT_UC)
		goto done;

	if (unlikely(pkt->port_num != 1)) {
		RDMA_LOG_ERR_DP("invalid port %d\n", pkt->port_num);
		goto err1;
	}

	if (mbuf->l3_type == VHOST_NETWORK_TYPE_IPV4) {
		struct in_addr *saddr =
			&qp->av.sgid_addr._sockaddr_in.sin_addr;
		struct in_addr *daddr =
			&qp->av.dgid_addr._sockaddr_in.sin_addr;

		if (ip_hdr(pkt)->dst_addr != saddr->s_addr) {
			RDMA_LOG_ERR_DP("dst addr %s != qp source addr %s\n",
					    inet_ntoa(*(struct in_addr*)&ip_hdr(pkt)->dst_addr),
					    inet_ntoa(*(struct in_addr*)&saddr->s_addr));
			goto err1;
		}

		if (ip_hdr(pkt)->src_addr != daddr->s_addr) {
			RDMA_LOG_ERR_DP("source addr %s != qp dst addr %s\n",
					    inet_ntoa(*(struct in_addr*)&ip_hdr(pkt)->src_addr),
					    inet_ntoa(*(struct in_addr*)&daddr->s_addr));
			goto err1;
		}

	} else if (mbuf->l3_type == VHOST_NETWORK_TYPE_IPV6) {
		struct in6_addr *saddr =
			&qp->av.sgid_addr._sockaddr_in6.sin6_addr;
		struct in6_addr *daddr =
			&qp->av.dgid_addr._sockaddr_in6.sin6_addr;

		if (memcmp(&ipv6_hdr(pkt)->dst_addr, saddr, sizeof(*saddr))) {
			RDMA_LOG_ERR_DP("dst addr != qp source addr\n");
			goto err1;
		}

		if (memcmp(&ipv6_hdr(pkt)->src_addr, daddr, sizeof(*daddr))) {
			RDMA_LOG_ERR_DP("source addr != qp dst addr\n");
			goto err1;
		}
	}

done:
	return 0;

err1:
	return -EINVAL;
}

static int hdr_check(struct vhost_rdma_pkt_info *pkt)
{
	struct vhost_rdma_dev *dev = pkt->dev;
	struct vhost_rdma_qp *qp = NULL;
	uint32_t qpn = bth_qpn(pkt);
	int index;
	int err;

	if (unlikely(bth_tver(pkt) != BTH_TVER)) {
		RDMA_LOG_ERR_DP("bad tver\n");
		goto err1;
	}

	if (unlikely(qpn == 0)) {
		RDMA_LOG_ERR_DP("QP 0 not supported");
		goto err1;
	}

	if (qpn != IB_MULTICAST_QPN) {
		index = qpn;

		qp = vhost_rdma_pool_get(&dev->qp_pool, index);
		if (unlikely(!qp)) {
			RDMA_LOG_ERR_DP("no qp matches qpn 0x%x\n", qpn);
			goto err1;
		}
		vhost_rdma_add_ref(qp);

		err = check_type_state(pkt, qp);
		if (unlikely(err))
			goto err2;

		err = check_addr(pkt, qp);
		if (unlikely(err))
			goto err2;

		err = check_keys(dev, pkt, qpn, qp);
		if (unlikely(err))
			goto err2;
	} else {
		RDMA_LOG_ERR_DP("mcast is not suppported now");
		goto err2;
	}

	pkt->qp = qp;

	return 0;

err2:
	vhost_rdma_drop_ref(qp, dev, qp);
err1:
	RDMA_LOG_ERR_DP("hdr_check failed");
	return -EINVAL;
}

static __rte_always_inline void
vhost_rdma_rcv_pkt(struct vhost_rdma_pkt_info *pkt, struct rte_mbuf *mbuf)
{
	if (pkt->mask & VHOST_REQ_MASK)
		vhost_rdma_resp_queue_pkt(pkt->qp, mbuf);
	else
		vhost_rdma_comp_queue_pkt(pkt->qp, mbuf);
}

/* vhost_rdma_rcv is called from the vhost_rdma_net udp stack */
void
vhost_rdma_rcv(struct rte_mbuf *mbuf)
{
	int err;
	struct vhost_rdma_pkt_info *pkt = MBUF_TO_PKT(mbuf);
	struct vhost_rdma_dev *dev = pkt->dev;
	rte_be32_t *icrcp;
	uint32_t calc_icrc, pack_icrc;

	if (unlikely(mbuf->data_len < VHOST_BTH_BYTES))
		goto drop;

	if (vhost_rdma_chk_dgid(dev, mbuf) < 0) {
		RDMA_LOG_ERR_DP("failed checking dgid\n");
		goto drop;
	}

	pkt->opcode = bth_opcode(pkt);
	pkt->psn = bth_psn(pkt);
	pkt->qp = NULL;
	pkt->mask |= vhost_rdma_opcode[pkt->opcode].mask;

	RDMA_LOG_DEBUG_DP("vhost rdma recv packet: opcode: %u qpn: %u psn: %u",
			  pkt->opcode, bth_qpn(pkt), pkt->psn);

	if (unlikely(mbuf->data_len < header_size(pkt)))
		goto drop;

	err = hdr_check(pkt);
	if (unlikely(err))
		goto drop;

	/* Verify ICRC */
	icrcp = (rte_be32_t *)(pkt->hdr + pkt->paylen - VHOST_ICRC_SIZE);
	pack_icrc = rte_be_to_cpu_32(*icrcp);

	calc_icrc = vhost_rdma_icrc_hdr(pkt, mbuf);
	calc_icrc = crc32(calc_icrc, (uint8_t *)payload_addr(pkt),
			      payload_size(pkt) + bth_pad(pkt));
	calc_icrc = (uint32_t)rte_cpu_to_be_32(~calc_icrc);
	if (unlikely(calc_icrc != pack_icrc)) {
		RDMA_LOG_ERR_DP("bad ICRC %x != %x\n", calc_icrc, pack_icrc);
		goto drop;
	}

	vhost_rdma_counter_inc(dev, VHOST_CNT_RCVD_PKTS);

	if (unlikely(bth_qpn(pkt) == IB_MULTICAST_QPN)) {
		// rxe_rcv_mcast_pkt(rxe, skb);
		RDMA_LOG_ERR_DP("multicast qpn is not supported");
		goto drop;
	} else {
		vhost_rdma_rcv_pkt(pkt, mbuf);
	}

	return;

drop:
	if (pkt->qp)
		vhost_rdma_drop_ref(pkt->qp, dev, qp);
	rte_pktmbuf_free(mbuf);
}
