/*
 * Vhost-user RDMA device demo: ib ops
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

#ifndef __VHOST_RDMA_IB_H__
#define __VHOST_RDMA_IB_H__

#include <netinet/in.h>
#include <linux/virtio_net.h>

#include <rte_spinlock.h>
#include <rte_atomic.h>
#include <rte_timer.h>

#include "verbs.h"
#include "vhost_rdma.h"
#include "vhost_rdma_queue.h"
#include "vhost_rdma_task.h"

#define OPCODE_NONE		(-1)

struct vhost_rdma_pd {
	struct vhost_rdma_dev *dev;
	uint32_t pdn;
	rte_atomic32_t refcnt;
};

enum vhost_rdma_mr_type {
	VHOST_MR_TYPE_NONE,
	VHOST_MR_TYPE_DMA,
	VHOST_MR_TYPE_MR,
};

enum vhost_rdma_mr_state {
	VHOST_MR_STATE_ZOMBIE,
	VHOST_MR_STATE_INVALID,
	VHOST_MR_STATE_FREE,
	VHOST_MR_STATE_VALID,
};

struct vhost_rdma_mr {
	struct vhost_rdma_pd *pd;
	enum vhost_rdma_mr_type	type;
	enum vhost_rdma_mr_state state;
	uint64_t va;
	uint64_t iova;
	size_t length;
	uint32_t offset;
	int access;

	uint32_t lkey;
	uint32_t rkey;

	uint32_t npages;
	uint32_t max_pages;

	uint64_t *pages;

	uint32_t mrn;
	rte_atomic32_t refcnt;
};

struct vhost_rdma_cq {
	struct vhost_queue *vq;
	rte_spinlock_t cq_lock;
	uint8_t notify;
	bool is_dying;

	uint32_t cqn;
	rte_atomic32_t refcnt;
};

struct vhost_rdma_av {
	/* From RXE_NETWORK_TYPE_* */
	uint8_t network_type;
	uint8_t	dmac[6];
	struct virtio_rdma_global_route	grh;
	union {
		struct sockaddr_in _sockaddr_in;
		struct sockaddr_in6 _sockaddr_in6;
	} sgid_addr, dgid_addr;
};

struct vhost_rdma_dma_info {
	uint32_t length;
	uint32_t resid;
	uint32_t cur_sge;
	uint32_t num_sge;
	uint32_t sge_offset;
	uint32_t reserved;
	union {
		uint8_t *inline_data;
		struct virtio_rdma_sge *sge;
		void *raw;
	};
};

enum wqe_state {
	wqe_state_posted,
	wqe_state_processing,
	wqe_state_pending,
	wqe_state_done,
	wqe_state_error,
};

struct vhost_rdma_send_wqe {
	struct virtio_rdma_sq_req *wr;
	struct vhost_rdma_av av;
	__u32 status;
	__u32 state;
	__aligned_u64 iova;
	__u32 mask;
	__u32 first_psn;
	__u32 last_psn;
	__u32 ack_length;
	__u32 ssn;
	__u32 has_rd_atomic;
	struct vhost_rdma_dma_info dma;
};

struct vhost_rdma_recv_wqe {
	__aligned_u64 wr_id;
	__u32 num_sge;
	__u32 padding;
	struct vhost_rdma_dma_info dma;
};

struct vhost_rdma_sq {
	rte_spinlock_t lock; /* guard queue */
	struct vhost_rdma_queue queue;
};

struct vhost_rdma_rq {
	rte_spinlock_t lock; /* guard queue */
	struct vhost_rdma_queue queue;
};

enum vhost_rdma_qp_state {
	QP_STATE_RESET,
	QP_STATE_INIT,
	QP_STATE_READY,
	QP_STATE_DRAIN,		/* req only */
	QP_STATE_DRAINED,	/* req only */
	QP_STATE_ERROR
};

struct vhost_rdma_req_info {
	enum vhost_rdma_qp_state state;
	int wqe_index;
	uint32_t psn;
	int opcode;
	rte_atomic32_t rd_atomic;
	int wait_fence;
	int need_rd_atomic;
	int wait_psn;
	int need_retry;
	int noack_pkts;
	struct vhost_rdma_task task;
};

struct vhost_rdma_comp_info {
	uint32_t psn;
	int opcode;
	int timeout;
	int timeout_retry;
	int started_retry;
	uint32_t retry_cnt;
	uint32_t rnr_retry;
	struct vhost_rdma_task task;
};

enum rdatm_res_state {
	rdatm_res_state_next,
	rdatm_res_state_new,
	rdatm_res_state_replay,
};

struct resp_res {
	int type;
	int replay;
	uint32_t first_psn;
	uint32_t last_psn;
	uint32_t cur_psn;
	enum rdatm_res_state state;

	union {
		struct {
			struct rte_mbuf *mbuf;
		} atomic;
		struct {
			struct vhost_rdma_mr *mr;
			uint64_t va_org;
			uint32_t rkey;
			uint32_t length;
			uint64_t va;
			uint32_t resid;
		} read;
	};
};

struct vhost_rdma_resp_info {
	enum vhost_rdma_qp_state state;
	uint32_t msn;
	uint32_t psn;
	uint32_t ack_psn;
	int opcode;
	int drop_msg;
	int goto_error;
	int sent_psn_nak;
	enum virtio_ib_wc_status status;
	uint8_t aeth_syndrome;

	/* Receive only */
	struct vhost_rdma_recv_wqe *wqe;

	/* RDMA read / atomic only */
	uint64_t va;
	uint64_t offset;
	struct vhost_rdma_mr *mr;
	uint32_t resid;
	uint32_t rkey;
	uint32_t length;
	uint64_t atomic_orig;

	/* Responder resources. It's a circular list where the oldest
	 * resource is dropped first.
	 */
	struct resp_res *resources;
	unsigned int res_head;
	unsigned int res_tail;
	struct resp_res *res;
	struct vhost_rdma_task task;
};

struct vhost_rdma_qp_attr {
	enum virtio_ib_qp_state qp_state;
	enum virtio_ib_qp_state cur_qp_state;
	enum virtio_ib_mtu path_mtu;
	uint32_t qkey;
	uint32_t rq_psn;
	uint32_t sq_psn;
	uint32_t dest_qp_num;
	uint32_t qp_access_flags;
	uint8_t sq_draining;
	uint8_t max_rd_atomic;
	uint8_t max_dest_rd_atomic;
	uint8_t min_rnr_timer;
	uint8_t timeout;
	uint8_t retry_cnt;
	uint8_t rnr_retry;
	uint32_t rate_limit;
	struct virtio_rdma_qp_cap cap;
	struct virtio_rdma_ah_attr ah_attr;
};

struct vhost_rdma_qp {
	struct vhost_rdma_dev *dev;
	struct vhost_rdma_qp_attr attr;
	uint32_t qpn;
	uint8_t type;
	unsigned int valid;
	unsigned int mtu;

	struct vhost_rdma_pd *pd;
	struct vhost_rdma_cq *scq;
	struct vhost_rdma_cq *rcq;

	uint8_t	sq_sig_all;

	struct vhost_rdma_sq sq;
	struct vhost_rdma_rq rq;
	void *srq; // reversed

	uint32_t dst_cookie;
	uint16_t src_port;

	struct vhost_rdma_av av;

	struct rte_ring	*req_pkts;
	struct rte_mbuf *req_pkts_head; // use this to support peek
	struct rte_ring *resp_pkts;

	struct vhost_rdma_req_info req;
	struct vhost_rdma_comp_info comp;
	struct vhost_rdma_resp_info resp;

	rte_atomic32_t ssn;
	rte_atomic32_t mbuf_out;
	int need_req_mbuf;

	/* Timer for retranmitting packet when ACKs have been lost. RC
	 * only. The requester sets it when it is not already
	 * started. The responder resets it whenever an ack is
	 * received.
	 */
	struct rte_timer retrans_timer;
	uint64_t qp_timeout_ticks;

	/* Timer for handling RNR NAKS. */
	struct rte_timer rnr_nak_timer;

	rte_spinlock_t state_lock; /* guard requester and completer */

	rte_atomic32_t refcnt;
};

static inline int ib_mtu_enum_to_int(enum virtio_ib_mtu mtu)
{
	switch (mtu) {
	case VIRTIO_IB_MTU_256:  return  256;
	case VIRTIO_IB_MTU_512:  return  512;
	case VIRTIO_IB_MTU_1024: return 1024;
	case VIRTIO_IB_MTU_2048: return 2048;
	case VIRTIO_IB_MTU_4096: return 4096;
	default: 	  return -1;
	}
}

enum {
	VHOST_NETWORK_TYPE_IPV4 = 1,
	VHOST_NETWORK_TYPE_IPV6 = 2,
};

enum {
	IB_MULTICAST_QPN = 0xffffff
};

void vhost_rdma_handle_ctrl(void* arg);
void vhost_rdma_init_ib(struct vhost_rdma_dev *dev);
void vhost_rdma_destroy_ib(struct vhost_rdma_dev *dev);

#endif
