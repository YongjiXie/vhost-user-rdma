/*
 * Vhost-user RDMA device demo: sq/rq queue and intr handler
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

#include <rte_interrupts.h>
#include <rte_malloc.h>
#include <rte_vhost.h>

#include "virtio_rdma_abi.h"
#include "vhost_rdma_loc.h"
#include "vhost_rdma_queue.h"

static int
desc_payload_to_iovs(struct rte_vhost_memory *mem, struct iovec *iovs,
			uint32_t *iov_index, uintptr_t payload, uint64_t remaining,
			uint16_t num_iovs)
{
	void *vva;
	uint64_t len;

	do {
		if (*iov_index >= num_iovs) {
			RDMA_LOG_ERR("MAX_IOVS reached");
			return -1;
		}
		len = remaining;
		vva = (void *)(uintptr_t)gpa_to_vva(mem, payload, &len);
		if (!vva || !len) {
			RDMA_LOG_ERR("failed to translate desc address.");
			return -1;
		}

		iovs[*iov_index].iov_base = vva;
		iovs[*iov_index].iov_len = len;
		payload += len;
		remaining -= len;
		(*iov_index)++;
	} while (remaining);

	return 0;
}

int
setup_iovs_from_descs(struct rte_vhost_memory *mem, struct vhost_queue *vq,
		      uint16_t req_idx, struct iovec *iovs, uint16_t num_iovs,
		      uint16_t *num_in, uint16_t* num_out)
{
	struct vring_desc *desc = &vq->vring.desc[req_idx];
	struct vring_desc *desc_table;
	uint32_t iovs_idx = 0;
	uint64_t len;
	uint16_t in = 0, out = 0;

	if (desc->flags & VRING_DESC_F_INDIRECT) {
		len = desc->len;
		desc_table = (struct vring_desc *)(uintptr_t)gpa_to_vva(mem, 
							desc->addr, &len);
		if (!desc_table || !len) {
			RDMA_LOG_ERR("failed to translate desc address.");
			return -1;
		}
		assert(len == desc->len);

		/* first is loacted at index 0 */
		desc = desc_table;
	} else {
		desc_table = vq->vring.desc;
	}

	do {
		if (iovs_idx >= num_iovs) {
			RDMA_LOG_ERR("MAX_IOVS reached\n");
			return -1;
		}

		if (desc->flags & VRING_DESC_F_WRITE) {
			in++;
		} else {
			out++;
		}

		if (desc_payload_to_iovs(mem, iovs, &iovs_idx,
			desc->addr, desc->len, num_iovs) != 0) {
			RDMA_LOG_ERR("Failed to convert desc payload to iovs");
			return -1;
		}

		desc = vring_get_next_desc(desc_table, desc);
	} while (desc != NULL);

	*num_in = in;
	*num_out = out;

	return iovs_idx;
}

static void
init_send_wqe(struct vhost_rdma_qp *qp, struct virtio_rdma_sq_req *wr,
	      unsigned int mask, unsigned int length,
	      struct vhost_rdma_send_wqe *wqe)
{
	int num_sge = wr->num_sge;

	wqe->wr = wr;
	wqe->mask = mask;

	/* local operation */
	if (unlikely(mask & WR_LOCAL_OP_MASK)) {
		wqe->state = wqe_state_posted;
		return;
	}

	if (qp->type == VIRTIO_IB_QPT_UD ||
		qp->type == VIRTIO_IB_QPT_SMI ||
		qp->type == VIRTIO_IB_QPT_GSI)
		init_av_from_virtio(qp->dev, &wqe->av, wr->ud.ah);

	wqe->iova = mask & WR_READ_OR_WRITE_MASK ? wr->rdma.remote_addr : 0;
	wqe->dma.length		= length;
	wqe->dma.resid		= length;
	wqe->dma.num_sge	= num_sge;
	wqe->dma.cur_sge	= 0;
	wqe->dma.sge_offset	= 0;
	if (wr->send_flags & VIRTIO_IB_SEND_INLINE)
		wqe->dma.inline_data = wr->inline_data;
	else
		wqe->dma.sge = wr->sg_list;
	wqe->state		= wqe_state_posted;
	wqe->ssn		= rte_atomic32_add_return(&qp->ssn, 1);
}

static void
vhost_rdma_handle_sq(void *arg)
{
	struct vhost_rdma_qp *qp = (struct vhost_rdma_qp *)arg;
	struct vhost_rdma_queue *queue = &qp->sq.queue;
	struct rte_vhost_vring *vring = &queue->vq->vring;
	int kick_fd;
	eventfd_t kick_data;

	kick_fd = queue->vq->vring.kickfd;
	eventfd_read(kick_fd, &kick_data);

	while(queue->producer_index != vring->avail->idx) {
		uint16_t last_avail_idx = queue->producer_index & (vring->size - 1);
		uint16_t desc_idx = vring->avail->ring[last_avail_idx];
		struct iovec iov;
		uint16_t num_in, num_out;
		struct virtio_rdma_sq_req *wr;
		unsigned int mask, length;

		setup_iovs_from_descs(qp->dev->mem, queue->vq, desc_idx, &iov, 1,
				&num_in, &num_out);

		assert(num_in == 0);
		assert(num_out == 1);

		if (iov.iov_len < sizeof(*wr)) {
			RDMA_LOG_ERR_DP("got bad send wqe");
			continue;
		}
		wr = iov.iov_base;

		mask = wr_opcode_mask(wr->opcode, qp);

		RDMA_LOG_DEBUG_DP("got send wqe qpn: %u type: %d wr_id: %llu opcode: %d mask: %u",
				  qp->qpn, qp->type, wr->wr_id, wr->opcode, mask);

		length = 0;
		if (unlikely(wr->send_flags & VIRTIO_IB_SEND_INLINE)) {
			length = wr->inline_len;
		} else {
			struct virtio_rdma_sge *sg_list = wr->sg_list;
			for (uint32_t i = 0; i < wr->num_sge; i++)
				length += sg_list[i].length;
		}

		init_send_wqe(qp, wr, mask, length,
				vhost_rdma_queue_get_data(queue, desc_idx));

		queue->producer_index++;
	}

	vhost_rdma_run_task(&qp->req.task, 1);
	if (unlikely(qp->req.state == QP_STATE_ERROR))
		vhost_rdma_run_task(&qp->comp.task, 1);
}

static void
vhost_rdma_handle_rq(__rte_unused void *arg)
{
	struct vhost_rdma_qp *qp = (struct vhost_rdma_qp *)arg;
	struct vhost_rdma_queue *queue = &qp->rq.queue;
	struct rte_vhost_vring *vring = &queue->vq->vring;
	int kick_fd;
	eventfd_t kick_data;

	kick_fd = queue->vq->vring.kickfd;
	eventfd_read(kick_fd, &kick_data);

	while(queue->producer_index != vring->avail->idx) {
		uint16_t last_avail_idx = queue->producer_index & (vring->size - 1);
		uint16_t desc_idx = vring->avail->ring[last_avail_idx];
		struct iovec iov;
		uint16_t num_in, num_out;
		struct virtio_rdma_rq_req *wr;
		struct virtio_rdma_sge *sg_list;
		struct vhost_rdma_recv_wqe *recv_wqe;
		unsigned int length;

		setup_iovs_from_descs(qp->dev->mem, queue->vq, desc_idx, &iov, 1,
				&num_in, &num_out);

		assert(num_in == 0);
		assert(num_out == 1);

		if (iov.iov_len < sizeof(*wr)) {
			RDMA_LOG_ERR_DP("got bad recv wqe");
			continue;
		}
		wr = iov.iov_base;

		RDMA_LOG_DEBUG_DP("got recv wqe qpn: %u type: %d wr_id: %llu",
				  qp->qpn, qp->type, wr->wr_id);

		length = 0;
		sg_list = wr->sg_list;
		for (uint32_t i = 0; i < wr->num_sge; i++)
			length += sg_list[i].length;

		recv_wqe = vhost_rdma_queue_get_data(queue, desc_idx);

		recv_wqe->wr_id = wr->wr_id;
		recv_wqe->num_sge = wr->num_sge;
		recv_wqe->dma.length		= length;
		recv_wqe->dma.resid		= length;
		recv_wqe->dma.num_sge		= wr->num_sge;
		recv_wqe->dma.cur_sge		= 0;
		recv_wqe->dma.sge_offset	= 0;
		recv_wqe->dma.raw = sg_list;

		queue->producer_index++;
	}

	if (qp->resp.state == QP_STATE_ERROR)
		vhost_rdma_run_task(&qp->resp.task, 1);
}

int
vhost_rdma_cq_post(struct vhost_rdma_dev *dev, struct vhost_rdma_cq *cq,
			struct virtio_rdma_cq_req *cqe, int solicited)
{
	bool avail;
	uint16_t desc_idx;
	struct iovec iovs[1];
	uint16_t num_in, num_out;

	rte_spinlock_lock(&cq->cq_lock);

	avail = vhost_vq_is_avail(cq->vq);

	if (unlikely(!avail)) {
		rte_spinlock_unlock(&cq->cq_lock);
		// if (cq->ibcq.event_handler) {
		// 	ev.device = cq->ibcq.device;
		// 	ev.element.cq = &cq->ibcq;
		// 	ev.event = IB_EVENT_CQ_ERR;
		// 	cq->ibcq.event_handler(&ev, cq->ibcq.cq_context);
		// }
		// TODO: event
		return -EBUSY;
	}

	desc_idx = vq_get_desc_idx(cq->vq);

	if (setup_iovs_from_descs(dev->mem, cq->vq, desc_idx, iovs, 1,
			&num_in, &num_out) < 0) {
		rte_spinlock_unlock(&cq->cq_lock);
		RDMA_LOG_ERR_DP("get from cq failed");
		return -EBUSY;
	}

	if (iovs[0].iov_len < sizeof(*cqe)) {
		RDMA_LOG_ERR_DP("cqe size is too small");
		return -EIO;
	}
	rte_memcpy(iovs[0].iov_base, cqe, sizeof(*cqe));

	RDMA_LOG_DEBUG_DP("poll cqe cqn: %u wr_id: %llu opcode: %d status: %d",
			  cq->cqn, cqe->wr_id, cqe->opcode, cqe->status);

	vhost_queue_push(cq->vq, desc_idx, sizeof(*cqe));

	rte_spinlock_unlock(&cq->cq_lock);

	if ((cq->notify == VIRTIO_IB_CQ_NEXT_COMP) ||
		(cq->notify == VIRTIO_IB_CQ_SOLICITED && solicited)) {
		cq->notify = 0;
		vhost_queue_notify(dev->vid, cq->vq);
	}

	return 0;
}

int
vhost_rdma_queue_init(struct vhost_rdma_qp *qp, struct vhost_rdma_queue* queue, char* name,
			struct vhost_queue* vq, size_t elem_size, enum queue_type type)
{
	queue->data = rte_zmalloc(name, elem_size * vq->vring.size, RTE_CACHE_LINE_SIZE);
	if (queue->data == NULL)
		return -ENOMEM;

	queue->vq = vq;
	queue->num_elems = vq->vring.size;
	queue->elem_size = elem_size;
	queue->consumer_index = vq->last_avail_idx;
	queue->producer_index = vq->last_avail_idx;

	switch (type) {
	case VHOST_RDMA_QUEUE_SQ:
		queue->cb = vhost_rdma_handle_sq;
		break;
	case VHOST_RDMA_QUEUE_RQ:
		queue->cb = vhost_rdma_handle_rq;
		break;
	default:
		RDMA_LOG_ERR("Unknown queue type");
	}

	queue->intr_handle.fd = vq->vring.kickfd;
	queue->intr_handle.type = RTE_INTR_HANDLE_EXT;
	rte_intr_callback_register(&queue->intr_handle, queue->cb, qp);

	return 0;
}

// FIXME: queue not free
void
vhost_rdma_queue_cleanup(struct vhost_rdma_qp *qp, struct vhost_rdma_queue* queue)
{
	rte_intr_callback_unregister(&queue->intr_handle, queue->cb, qp);
	rte_free(queue->data);
}
