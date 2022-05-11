/*
 * Vhost-user RDMA device demo: loc header
 *
 * Copyright (C) 2022 Bytedance Inc. and/or its affiliates. All rights reserved.
 *
 * Author: Wei Junji <weijunji@bytedance.com>
 *         Xie Yongji <xieyongji@bytedance.com>
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

#ifndef __VHOST_RDMA_LOC_H__
#define __VHOST_RDMA_LOC_H__

#include <stdint.h>
#include <netinet/in.h>
#include <linux/virtio_net.h>

#include <rte_mbuf.h>

#include "logging.h"
#include "vhost_rdma_ib.h"
#include "vhost_rdma_opcode.h"
#include "vhost_rdma_hdr.h"

#define PKT_TO_MBUF(p) ((struct rte_mbuf *) \
			(RTE_PTR_SUB(p, sizeof(struct rte_mbuf))))
#define MBUF_TO_PKT(m) ((struct vhost_rdma_pkt_info *) \
			(RTE_PTR_ADD(m, sizeof(struct rte_mbuf))))

__rte_always_inline uint32_t
roundup_pow_of_two(uint32_t n)
{
	return n < 2 ? n : (1u << (32 - __builtin_clz (n - 1)));
}

static inline bool ipv6_addr_v4mapped(const struct in6_addr *a)
{
	return IN6_IS_ADDR_V4MAPPED(a);
}

#define ipv4_is_multicast(a) (IN_MULTICAST(a))

static inline void __ipv6_addr_set_half(__be32 *addr,
					__be32 wh, __be32 wl)
{
	addr[0] = wh;
	addr[1] = wl;
}

static inline void ipv6_addr_set(struct in6_addr *addr,
				     __be32 w1, __be32 w2,
				     __be32 w3, __be32 w4)
{
	__ipv6_addr_set_half(&addr->s6_addr32[0], w1, w2);
	__ipv6_addr_set_half(&addr->s6_addr32[2], w3, w4);
}

static inline void ipv6_addr_set_v4mapped(const __be32 addr,
					  struct in6_addr *v4mapped)
{
	ipv6_addr_set(v4mapped, 0, 0, htonl(0x0000FFFF), addr);
}

static inline int rdma_is_multicast_addr(struct in6_addr *addr)
{
	__be32 ipv4_addr;

	if (addr->s6_addr[0] == 0xff)
		return 1;

	ipv4_addr = addr->s6_addr32[3];
	return (ipv6_addr_v4mapped(addr) && ipv4_is_multicast(ipv4_addr));
}

static inline void rdma_gid2ip(struct sockaddr *out, const uint8_t *gid)
{
	if (ipv6_addr_v4mapped((struct in6_addr *)gid)) {
		struct sockaddr_in *out_in = (struct sockaddr_in *)out;
		memset(out_in, 0, sizeof(*out_in));
		out_in->sin_family = AF_INET;
		rte_memcpy(&out_in->sin_addr.s_addr, gid + 12, 4);
	} else {
		struct sockaddr_in6 *out_in = (struct sockaddr_in6 *)out;
		memset(out_in, 0, sizeof(*out_in));
		out_in->sin6_family = AF_INET6;
		rte_memcpy(&out_in->sin6_addr.s6_addr, gid, 16);
	}
}

static inline enum rdma_network_type
rdma_gid_attr_network_type(const struct vhost_rdma_gid *attr)
{
	if (attr->type == IB_GID_TYPE_IB)
		return RDMA_NETWORK_IB;

	if (attr->type == IB_GID_TYPE_ROCE)
		return RDMA_NETWORK_ROCE_V1;

	if (ipv6_addr_v4mapped((struct in6_addr *)&attr->gid))
		return RDMA_NETWORK_IPV4;
	else
		return RDMA_NETWORK_IPV6;
}

/* vhost_rdma_av.c */
void vhost_rdma_av_to_attr(struct vhost_rdma_av *av,
				struct virtio_rdma_ah_attr *attr);
void vhost_rdma_av_from_attr(struct vhost_rdma_av *av,
		     struct virtio_rdma_ah_attr *attr);
int vhost_rdma_av_chk_attr(struct vhost_rdma_dev *dev,
				struct virtio_rdma_ah_attr *attr);
void vhost_rdma_init_av(struct vhost_rdma_dev *dev,
			struct virtio_rdma_ah_attr *attr, struct vhost_rdma_av *av);
void init_av_from_virtio(struct vhost_rdma_dev *dev, struct vhost_rdma_av *dst,
			 uint32_t ah);
struct vhost_rdma_av *vhost_rdma_get_av(struct vhost_rdma_pkt_info *pkt);

/* vhost_rdma_comp.c */
void vhost_rdma_comp_queue_pkt(struct vhost_rdma_qp *qp, struct rte_mbuf *mbuf);
int vhost_rdma_completer(void* arg);
void retransmit_timer(struct rte_timer*, void* arg);

/* vhost_rdma_crc.c */
uint32_t crc32(uint32_t crc, void* buf, uint32_t len);
uint32_t vhost_rdma_icrc_hdr(struct vhost_rdma_pkt_info *pkt,
							struct rte_mbuf *mbuf);

/* vhost_rdma_mr.c */
enum vhost_rdma_mr_copy_dir {
	VHOST_TO_MR_OBJ,
	VHOST_FROM_MR_OBJ,
};

enum vhost_rdma_mr_lookup_type {
	VHOST_LOOKUP_LOCAL,
	VHOST_LOOKUP_REMOTE,
};

uint8_t vhost_rdma_get_next_key(uint32_t last_key);
void vhost_rdma_mr_init_key(struct vhost_rdma_mr *mr, uint32_t mrn);
uint64_t** vhost_rdma_alloc_page_tbl(uint32_t npages);
void vhost_rdma_map_pages(struct rte_vhost_memory *mem, uint64_t *pages,
				uint64_t *dma_pages, uint32_t npages);
struct vhost_rdma_mr* lookup_mr(struct vhost_rdma_pd *pd, int access,
						uint32_t key,enum vhost_rdma_mr_lookup_type type);
int mr_check_range(struct vhost_rdma_mr *mr, uint64_t iova, size_t length);
int vhost_rdma_mr_copy(struct rte_vhost_memory *mem, struct vhost_rdma_mr *mr,
		uint64_t iova, void *addr, uint64_t length, enum vhost_rdma_mr_copy_dir dir,
		uint32_t *crcp);
int copy_data( struct vhost_rdma_pd *pd, int access,
		struct vhost_rdma_dma_info *dma, void *addr, int length,
		enum vhost_rdma_mr_copy_dir dir, uint32_t *crcp);
void* iova_to_vaddr(struct vhost_rdma_mr *mr, uint64_t iova, int length);
int vhost_rdma_invalidate_mr(struct vhost_rdma_qp *qp, uint32_t rkey);
int advance_dma_data(struct vhost_rdma_dma_info *dma, unsigned int length);
void vhost_rdma_mr_cleanup(void* arg);

/* vhost_rdma_net.c */
#define ip_hdr(p) ((struct rte_ipv4_hdr*) \
	(RTE_PTR_SUB(p->hdr, \
		sizeof(struct rte_udp_hdr) + sizeof(struct rte_ipv4_hdr))))
#define ipv6_hdr(p) ((struct rte_ipv6_hdr*) \
	(RTE_PTR_SUB(p->hdr, \
		sizeof(struct rte_udp_hdr) + sizeof(struct rte_ipv6_hdr))))

void vhost_rdma_net_recv(struct vhost_rdma_dev *dev, struct rte_mbuf *pkt);
struct rte_mbuf* vhost_rdma_init_packet(struct vhost_rdma_dev *dev,
	struct vhost_rdma_av *av, int paylen, struct vhost_rdma_pkt_info *pkt);

void vhost_rdma_loopback(struct rte_mbuf *m);
int vhost_rdma_send(struct vhost_rdma_pkt_info *pkt, struct rte_mbuf *mbuf);
int vhost_rdma_prepare(struct vhost_rdma_pkt_info *pkt, struct rte_mbuf *m,
				uint32_t *crc);

static __rte_always_inline int
vhost_rdma_xmit_packet(struct vhost_rdma_qp *qp,
					struct vhost_rdma_pkt_info *pkt, struct rte_mbuf *m)
{
	int err;
	int is_request = pkt->mask & VHOST_REQ_MASK;
	struct vhost_rdma_dev *dev = qp->dev;

	if ((is_request && (qp->req.state != QP_STATE_READY)) ||
	    (!is_request && (qp->resp.state != QP_STATE_READY))) {
		RDMA_LOG_ERR_DP("Packet dropped. QP is not in ready state\n");
		goto drop;
	}

	if (pkt->mask & VHOST_LOOPBACK_MASK) {
		rte_memcpy(MBUF_TO_PKT(m), pkt, sizeof(*pkt));
		vhost_rdma_loopback(m);
		err = 0;
	} else {
		err = vhost_rdma_send(pkt, m);
	}

	if (err) {
		vhost_rdma_counter_inc(dev, VHOST_CNT_SEND_ERR);
		return err;
	}

	if ((qp->type != VIRTIO_IB_QPT_RC) &&
	    (pkt->mask & VHOST_END_MASK)) {
		pkt->wqe->state = wqe_state_done;
		vhost_rdma_run_task(&qp->comp.task, 1);
	}

	vhost_rdma_counter_inc(dev, VHOST_CNT_SENT_PKTS);
	goto done;

drop:
	rte_pktmbuf_free(m);
	err = 0;
done:
	return err;
}

/* vhost_rdma_opcode */
static inline unsigned int wr_opcode_mask(int opcode, struct vhost_rdma_qp *qp)
{
	return vhost_rdma_wr_opcode_info[opcode].mask[qp->type];
}

/* vhost_rdma_qp.c */
int vhost_rdma_qp_init(struct vhost_rdma_dev *dev, struct vhost_rdma_qp *qp,
			struct virtio_rdma_cmd_create_qp *cmd);
void vhost_rdma_qp_destroy(struct vhost_rdma_qp *qp);
int vhost_rdma_qp_query(struct vhost_rdma_qp *qp,
			struct virtio_rdma_ack_query_qp *rsp);
int vhost_rdma_qp_validate(struct vhost_rdma_dev *dev, struct vhost_rdma_qp *qp,
			   struct virtio_rdma_cmd_modify_qp *cmd);
int vhost_rdma_qp_modify(struct vhost_rdma_dev *dev, struct vhost_rdma_qp *qp,
			 struct virtio_rdma_cmd_modify_qp *cmd);
void free_rd_atomic_resource(struct vhost_rdma_qp *qp, struct resp_res *res);
void vhost_rdma_qp_error(struct vhost_rdma_qp *qp);
void vhost_rdma_qp_cleanup(void* arg);

static inline void vhost_rdma_advance_resp_resource(struct vhost_rdma_qp *qp)
{
	qp->resp.res_head++;
	if (unlikely(qp->resp.res_head == qp->attr.max_dest_rd_atomic))
		qp->resp.res_head = 0;
}

/* vhost_rdma_req.c */
void rnr_nak_timer(struct rte_timer *timer, void* arg);
int vhost_rdma_requester(void* arg);

/* vhost_rdma_resp.c */
int vhost_rdma_responder(void* arg);
void vhost_rdma_resp_queue_pkt(struct vhost_rdma_qp *qp, struct rte_mbuf *mbuf);

/* vhost_rdma_recv.c */
void vhost_rdma_rcv(struct rte_mbuf *mbuf);

static inline int psn_compare(uint32_t psn_a, uint32_t psn_b)
{
	int32_t diff;

	diff = (psn_a - psn_b) << 8;
	return diff;
}

#endif
