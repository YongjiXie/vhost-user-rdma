/*
 * Vhost-user RDMA device demo: task requester
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

#include <rte_mbuf.h>

#include "vhost_rdma_loc.h"

void rnr_nak_timer(__rte_unused struct rte_timer *timer, void* arg)
{
	struct vhost_rdma_qp *qp = arg;

	RDMA_LOG_DEBUG_DP("qp#%d rnr nak timer fired", qp->qpn);
	vhost_rdma_run_task(&qp->req.task, 1);
}

static int
next_opcode_rc(struct vhost_rdma_qp *qp, uint32_t opcode, int fits)
{
	switch (opcode) {
	case VIRTIO_IB_WR_RDMA_WRITE:
		if (qp->req.opcode == IB_OPCODE_RC_RDMA_WRITE_FIRST ||
		    qp->req.opcode == IB_OPCODE_RC_RDMA_WRITE_MIDDLE)
			return fits ?
				IB_OPCODE_RC_RDMA_WRITE_LAST :
				IB_OPCODE_RC_RDMA_WRITE_MIDDLE;
		else
			return fits ?
				IB_OPCODE_RC_RDMA_WRITE_ONLY :
				IB_OPCODE_RC_RDMA_WRITE_FIRST;

	case VIRTIO_IB_WR_RDMA_WRITE_WITH_IMM:
		if (qp->req.opcode == IB_OPCODE_RC_RDMA_WRITE_FIRST ||
		    qp->req.opcode == IB_OPCODE_RC_RDMA_WRITE_MIDDLE)
			return fits ?
				IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE :
				IB_OPCODE_RC_RDMA_WRITE_MIDDLE;
		else
			return fits ?
				IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE :
				IB_OPCODE_RC_RDMA_WRITE_FIRST;

	case VIRTIO_IB_WR_SEND:
		if (qp->req.opcode == IB_OPCODE_RC_SEND_FIRST ||
		    qp->req.opcode == IB_OPCODE_RC_SEND_MIDDLE)
			return fits ?
				IB_OPCODE_RC_SEND_LAST :
				IB_OPCODE_RC_SEND_MIDDLE;
		else
			return fits ?
				IB_OPCODE_RC_SEND_ONLY :
				IB_OPCODE_RC_SEND_FIRST;

	case VIRTIO_IB_WR_SEND_WITH_IMM:
		if (qp->req.opcode == IB_OPCODE_RC_SEND_FIRST ||
		    qp->req.opcode == IB_OPCODE_RC_SEND_MIDDLE)
			return fits ?
				IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE :
				IB_OPCODE_RC_SEND_MIDDLE;
		else
			return fits ?
				IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE :
				IB_OPCODE_RC_SEND_FIRST;

	case VIRTIO_IB_WR_RDMA_READ:
		return IB_OPCODE_RC_RDMA_READ_REQUEST;
	}

	return -EINVAL;
}

static int
next_opcode_uc(struct vhost_rdma_qp *qp, uint32_t opcode, int fits)
{
	switch (opcode) {
	case VIRTIO_IB_WR_RDMA_WRITE:
		if (qp->req.opcode == IB_OPCODE_UC_RDMA_WRITE_FIRST ||
		    qp->req.opcode == IB_OPCODE_UC_RDMA_WRITE_MIDDLE)
			return fits ?
				IB_OPCODE_UC_RDMA_WRITE_LAST :
				IB_OPCODE_UC_RDMA_WRITE_MIDDLE;
		else
			return fits ?
				IB_OPCODE_UC_RDMA_WRITE_ONLY :
				IB_OPCODE_UC_RDMA_WRITE_FIRST;

	case VIRTIO_IB_WR_RDMA_WRITE_WITH_IMM:
		if (qp->req.opcode == IB_OPCODE_UC_RDMA_WRITE_FIRST ||
		    qp->req.opcode == IB_OPCODE_UC_RDMA_WRITE_MIDDLE)
			return fits ?
				IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE :
				IB_OPCODE_UC_RDMA_WRITE_MIDDLE;
		else
			return fits ?
				IB_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE :
				IB_OPCODE_UC_RDMA_WRITE_FIRST;

	case VIRTIO_IB_WR_SEND:
		if (qp->req.opcode == IB_OPCODE_UC_SEND_FIRST ||
		    qp->req.opcode == IB_OPCODE_UC_SEND_MIDDLE)
			return fits ?
				IB_OPCODE_UC_SEND_LAST :
				IB_OPCODE_UC_SEND_MIDDLE;
		else
			return fits ?
				IB_OPCODE_UC_SEND_ONLY :
				IB_OPCODE_UC_SEND_FIRST;

	case VIRTIO_IB_WR_SEND_WITH_IMM:
		if (qp->req.opcode == IB_OPCODE_UC_SEND_FIRST ||
		    qp->req.opcode == IB_OPCODE_UC_SEND_MIDDLE)
			return fits ?
				IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE :
				IB_OPCODE_UC_SEND_MIDDLE;
		else
			return fits ?
				IB_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE :
				IB_OPCODE_UC_SEND_FIRST;
	}

	return -EINVAL;
}

static int
next_opcode(struct vhost_rdma_qp *qp, struct vhost_rdma_send_wqe *wqe,
		       uint32_t opcode)
{
	int fits = (wqe->dma.resid <= qp->mtu);

	switch (qp->type) {
	case VIRTIO_IB_QPT_RC:
		return next_opcode_rc(qp, opcode, fits);

	case VIRTIO_IB_QPT_UC:
		return next_opcode_uc(qp, opcode, fits);

	case VIRTIO_IB_QPT_SMI:
	case VIRTIO_IB_QPT_UD:
	case VIRTIO_IB_QPT_GSI:
		switch (opcode) {
		case VIRTIO_IB_WR_SEND:
			return IB_OPCODE_UD_SEND_ONLY;

		case VIRTIO_IB_WR_SEND_WITH_IMM:
			return IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE;
		}
		break;

	default:
		break;
	}

	return -EINVAL;
}

static __rte_always_inline void
retry_first_write_send(struct vhost_rdma_qp *qp,
					  struct vhost_rdma_send_wqe *wqe,
					  unsigned int mask, int npsn)
{
	int i;

	for (i = 0; i < npsn; i++) {
		int to_send = (wqe->dma.resid > qp->mtu) ?
				qp->mtu : wqe->dma.resid;

		qp->req.opcode = next_opcode(qp, wqe,
					     wqe->wr->opcode);

		if (wqe->wr->send_flags & VIRTIO_IB_SEND_INLINE) {
			wqe->dma.resid -= to_send;
			wqe->dma.sge_offset += to_send;
		} else {
			advance_dma_data(&wqe->dma, to_send);
		}
		if (mask & WR_WRITE_MASK)
			wqe->iova += qp->mtu;
	}
}

static void req_retry(struct vhost_rdma_qp *qp)
{
	struct vhost_rdma_send_wqe *wqe;
	unsigned int wqe_index;
	unsigned int mask;
	int npsn;
	int first = 1;
	struct vhost_rdma_queue *q = &qp->sq.queue;
	unsigned int cons;
	unsigned int prod;

	cons = q->consumer_index;
	prod = q->producer_index;

	qp->req.wqe_index	= cons;
	qp->req.psn		= qp->comp.psn;
	qp->req.opcode		= -1;

	for (wqe_index = cons; wqe_index != prod; wqe_index++) {
		wqe = addr_from_index(&qp->sq.queue, wqe_index);
		mask = wr_opcode_mask(wqe->wr->opcode, qp);

		if (wqe->state == wqe_state_posted)
			break;

		if (wqe->state == wqe_state_done)
			continue;

		wqe->iova = (mask & WR_READ_OR_WRITE_MASK) ?
				 wqe->wr->rdma.remote_addr :
				 0;

		if (!first || (mask & WR_READ_MASK) == 0) {
			wqe->dma.resid = wqe->dma.length;
			wqe->dma.cur_sge = 0;
			wqe->dma.sge_offset = 0;
		}

		if (first) {
			first = 0;

			if (mask & WR_WRITE_OR_SEND_MASK) {
				npsn = (qp->comp.psn - wqe->first_psn) &
					BTH_PSN_MASK;
				retry_first_write_send(qp, wqe, mask, npsn);
			}

			if (mask & WR_READ_MASK) {
				npsn = (wqe->dma.length - wqe->dma.resid) /
					qp->mtu;
				wqe->iova += npsn * qp->mtu;
			}
		}

		wqe->state = wqe_state_posted;
	}
}

static struct vhost_rdma_send_wqe*
req_next_wqe(struct vhost_rdma_qp *qp)
{
	struct vhost_rdma_send_wqe *wqe;
	struct vhost_rdma_queue *q = &qp->sq.queue;
	unsigned int index = qp->req.wqe_index;
	unsigned int cons;
	unsigned int prod;

	wqe = queue_head(q);
	cons = q->consumer_index;
	prod = q->producer_index;

	if (unlikely(qp->req.state == QP_STATE_DRAIN)) {
		/* check to see if we are drained;
		 * state_lock used by requester and completer
		 */
		rte_spinlock_lock(&qp->state_lock);
		do {
			if (qp->req.state != QP_STATE_DRAIN) {
				/* comp just finished */
				rte_spinlock_unlock(&qp->state_lock);
				break;
			}

			if (wqe && ((index != cons) ||
				(wqe->state != wqe_state_posted))) {
				/* comp not done yet */
				rte_spinlock_unlock(&qp->state_lock);
				break;
			}

			qp->req.state = QP_STATE_DRAINED;
			rte_spinlock_unlock(&qp->state_lock);

			// TODO: event
			// if (qp->ibqp.event_handler) {
			// 	struct ib_event ev;

			// 	ev.device = qp->ibqp.device;
			// 	ev.element.qp = &qp->ibqp;
			// 	ev.event = IB_EVENT_SQ_DRAINED;
			// 	qp->ibqp.event_handler(&ev,
			// 		qp->ibqp.qp_context);
			// }
		} while (0);
	}

	if (index == prod)
		return NULL;

	wqe = addr_from_index(q, index);

	if (unlikely((qp->req.state == QP_STATE_DRAIN ||
		      qp->req.state == QP_STATE_DRAINED) &&
		     (wqe->state != wqe_state_processing)))
		return NULL;

	if (unlikely((wqe->wr->send_flags & VIRTIO_IB_SEND_FENCE) &&
						     (index != cons))) {
		qp->req.wait_fence = 1;
		return NULL;
	}

	wqe->mask = wr_opcode_mask(wqe->wr->opcode, qp);
	return wqe;
}

static __rte_always_inline int
check_init_depth(struct vhost_rdma_qp *qp, struct vhost_rdma_send_wqe *wqe)
{
	int depth;

	if (wqe->has_rd_atomic)
		return 0;

	qp->req.need_rd_atomic = 1;
	depth = rte_atomic32_sub_return(&qp->req.rd_atomic, 1);

	if (depth >= 0) {
		qp->req.need_rd_atomic = 0;
		wqe->has_rd_atomic = 1;
		return 0;
	}

	rte_atomic32_inc(&qp->req.rd_atomic);
	return -EAGAIN;
}

static __rte_always_inline int
get_mtu(struct vhost_rdma_qp *qp)
{
	struct vhost_rdma_dev *dev = qp->dev;

	if (qp->type == VIRTIO_IB_QPT_RC || qp->type == VIRTIO_IB_QPT_UC)
		return qp->mtu;

	return dev->mtu_cap;
}

static struct rte_mbuf*
init_req_packet(struct vhost_rdma_qp *qp, struct vhost_rdma_send_wqe *wqe,
				int opcode, int payload, struct vhost_rdma_pkt_info *pkt)
{
	struct vhost_rdma_dev *dev = qp->dev;
	struct rte_mbuf *mbuf;
	struct virtio_rdma_sq_req *wr = wqe->wr;
	struct vhost_rdma_av *av;
	int pad = (-payload) & 0x3;
	int paylen;
	int solicited;
	uint16_t pkey;
	uint32_t qp_num;
	int ack_req;

	/* length from start of bth to end of icrc */
	paylen = vhost_rdma_opcode[opcode].length + payload + pad + VHOST_ICRC_SIZE;

	/* pkt->hdr, rxe, port_num and mask are initialized in ifc
	 * layer
	 */
	pkt->opcode	= opcode;
	pkt->qp		= qp;
	pkt->psn	= qp->req.psn;
	pkt->mask	= vhost_rdma_opcode[opcode].mask;
	pkt->paylen	= paylen;
	pkt->wqe	= wqe;

	/* init mbuf */
	av = vhost_rdma_get_av(pkt);
	mbuf = vhost_rdma_init_packet(dev, av, paylen, pkt);
	if (unlikely(!mbuf))
		return NULL;

	/* init bth */
	solicited = (wr->send_flags & VIRTIO_IB_SEND_SOLICITED) &&
			(pkt->mask & VHOST_END_MASK) &&
			((pkt->mask & (VHOST_SEND_MASK)) ||
			(pkt->mask & (VHOST_WRITE_MASK | VHOST_IMMDT_MASK)) ==
			(VHOST_WRITE_MASK | VHOST_IMMDT_MASK));

	pkey = IB_DEFAULT_PKEY_FULL;

	qp_num = (pkt->mask & VHOST_DETH_MASK) ? wr->ud.remote_qpn :
					 qp->attr.dest_qp_num;

	ack_req = ((pkt->mask & VHOST_END_MASK) ||
		(qp->req.noack_pkts++ > VHOST_MAX_PKT_PER_ACK));
	if (ack_req)
		qp->req.noack_pkts = 0;

	bth_init(pkt, pkt->opcode, solicited, 0, pad, pkey, qp_num,
		 ack_req, pkt->psn);

	/* init optional headers */
	if (pkt->mask & VHOST_RETH_MASK) {
		reth_set_rkey(pkt, wr->rdma.rkey);
		reth_set_va(pkt, wqe->iova);
		reth_set_len(pkt, wqe->dma.resid);
	}

	if (pkt->mask & VHOST_IMMDT_MASK)
		immdt_set_imm(pkt, wr->imm_data);
	if (pkt->mask & VHOST_DETH_MASK) {
		if (qp->qpn == 1)
			deth_set_qkey(pkt, GSI_QKEY);
		else
			deth_set_qkey(pkt, wr->ud.remote_qkey);
		deth_set_sqp(pkt, qp->qpn);
	}

	return mbuf;
}

static int
finish_packet(struct vhost_rdma_qp *qp, struct vhost_rdma_send_wqe *wqe,
			struct vhost_rdma_pkt_info *pkt, struct rte_mbuf *skb, int paylen)
{
	uint32_t crc = 0;
	uint32_t *p;
	int err;

	err = vhost_rdma_prepare(pkt, skb, &crc);
	if (err)
		return err;

	if (pkt->mask & VHOST_WRITE_OR_SEND) {
		if (wqe->wr->send_flags & VIRTIO_IB_SEND_INLINE) {
			uint8_t *tmp = &wqe->dma.inline_data[wqe->dma.sge_offset];

			crc = crc32(crc, tmp, paylen);
			memcpy(payload_addr(pkt), tmp, paylen);

			wqe->dma.resid -= paylen;
			wqe->dma.sge_offset += paylen;
		} else {
			err = copy_data(qp->pd, 0, &wqe->dma,
					payload_addr(pkt), paylen,
					VHOST_FROM_MR_OBJ,
					&crc);
			if (err)
				return err;
		}
		if (bth_pad(pkt)) {
			uint8_t *pad = payload_addr(pkt) + paylen;

			memset(pad, 0, bth_pad(pkt));
			crc = crc32(crc, pad, bth_pad(pkt));
		}
	}
	p = payload_addr(pkt) + paylen + bth_pad(pkt);

	*p = ~crc;

	return 0;
}

static void
save_state(struct vhost_rdma_send_wqe *wqe, struct vhost_rdma_qp *qp,
			struct vhost_rdma_send_wqe *rollback_wqe, uint32_t *rollback_psn)
{
	rollback_wqe->state     = wqe->state;
	rollback_wqe->first_psn = wqe->first_psn;
	rollback_wqe->last_psn  = wqe->last_psn;
	*rollback_psn		= qp->req.psn;
}

static void
rollback_state(struct vhost_rdma_send_wqe *wqe, struct vhost_rdma_qp *qp,
			struct vhost_rdma_send_wqe *rollback_wqe, uint32_t rollback_psn)
{
	wqe->state     = rollback_wqe->state;
	wqe->first_psn = rollback_wqe->first_psn;
	wqe->last_psn  = rollback_wqe->last_psn;
	qp->req.psn    = rollback_psn;
}

static void
update_state(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt)
{
	qp->req.opcode = pkt->opcode;

	if (pkt->mask & VHOST_END_MASK)
		qp->req.wqe_index += 1;

	qp->need_req_mbuf = 0;

	if (qp->qp_timeout_ticks && !rte_timer_pending(&qp->retrans_timer))
		rte_timer_reset(&qp->retrans_timer, qp->qp_timeout_ticks, SINGLE,
						rte_lcore_id(), retransmit_timer, qp);
}

static __rte_always_inline void
update_wqe_state(struct vhost_rdma_qp *qp, struct vhost_rdma_send_wqe *wqe,
		struct vhost_rdma_pkt_info *pkt)
{
	if (pkt->mask & VHOST_END_MASK) {
		if (qp->type == VIRTIO_IB_QPT_RC)
			wqe->state = wqe_state_pending;
	} else {
		wqe->state = wqe_state_processing;
	}
}

static __rte_always_inline void
update_wqe_psn(struct vhost_rdma_qp *qp, struct vhost_rdma_send_wqe *wqe,
				struct vhost_rdma_pkt_info *pkt, int payload)
{
	/* number of packets left to send including current one */
	int num_pkt = (wqe->dma.resid + payload + qp->mtu - 1) / qp->mtu;

	/* handle zero length packet case */
	if (num_pkt == 0)
		num_pkt = 1;

	if (pkt->mask & VHOST_START_MASK) {
		wqe->first_psn = qp->req.psn;
		wqe->last_psn = (qp->req.psn + num_pkt - 1) & BTH_PSN_MASK;
	}

	if (pkt->mask & VHOST_READ_MASK)
		qp->req.psn = (wqe->first_psn + num_pkt) & BTH_PSN_MASK;
	else
		qp->req.psn = (qp->req.psn + 1) & BTH_PSN_MASK;
}

int vhost_rdma_requester(void *arg)
{
	struct vhost_rdma_qp *qp = (struct vhost_rdma_qp *)arg;
	struct vhost_rdma_pkt_info pkt;
	struct rte_mbuf *mbuf;
	struct vhost_rdma_send_wqe *wqe;
	enum vhost_rdma_hdr_mask mask;
	int payload;
	int mtu;
	int opcode;
	int ret;
	struct vhost_rdma_send_wqe rollback_wqe;
	uint32_t rollback_psn;
	struct vhost_rdma_queue *q = &qp->sq.queue;

	vhost_rdma_add_ref(qp);

next_wqe:
	if (unlikely(!qp->valid || qp->req.state == QP_STATE_ERROR))
		goto exit;

	if (unlikely(qp->req.state == QP_STATE_RESET)) {
		qp->req.wqe_index = q->consumer_index;
		qp->req.opcode = -1;
		qp->req.need_rd_atomic = 0;
		qp->req.wait_psn = 0;
		qp->req.need_retry = 0;
		goto exit;
	}

	if (unlikely(qp->req.need_retry)) {
		req_retry(qp);
		qp->req.need_retry = 0;
	}

	wqe = req_next_wqe(qp);
	if (unlikely(!wqe))
		goto exit;

	assert(!(wqe->mask & WR_LOCAL_OP_MASK));

	if (unlikely(qp->type == VIRTIO_IB_QPT_RC &&
		psn_compare(qp->req.psn, (qp->comp.psn +
				VHOST_MAX_UNACKED_PSNS)) > 0)) {
		qp->req.wait_psn = 1;
		goto exit;
	}

	/* Limit the number of inflight SKBs per QP */
	if (unlikely(rte_atomic32_read(&qp->mbuf_out) >
			 VHOST_INFLIGHT_SKBS_PER_QP_HIGH)) {
		qp->need_req_mbuf = 1;
		goto exit;
	}

	opcode = next_opcode(qp, wqe, wqe->wr->opcode);
	if (unlikely(opcode < 0)) {
		wqe->status = VIRTIO_IB_WC_LOC_QP_OP_ERR;
		goto exit;
	}

	mask = vhost_rdma_opcode[opcode].mask;
	if (unlikely(mask & VHOST_READ_OR_ATOMIC)) {
		if (check_init_depth(qp, wqe))
			goto exit;
	}

	mtu = get_mtu(qp);
	payload = (mask & VHOST_WRITE_OR_SEND) ? wqe->dma.resid : 0;
	if (payload > mtu) {
		if (qp->type == VIRTIO_IB_QPT_UD) {
			/* C10-93.1.1: If the total sum of all the buffer lengths specified for a
			 * UD message exceeds the MTU of the port as returned by QueryHCA, the CI
			 * shall not emit any packets for this message. Further, the CI shall not
			 * generate an error due to this condition.
			 */

			/* fake a successful UD send */
			wqe->first_psn = qp->req.psn;
			wqe->last_psn = qp->req.psn;
			qp->req.psn = (qp->req.psn + 1) & BTH_PSN_MASK;
			qp->req.opcode = IB_OPCODE_UD_SEND_ONLY;
			qp->req.wqe_index += 1;
			wqe->state = wqe_state_done;
			wqe->status = VIRTIO_IB_WC_SUCCESS;
			__vhost_rdma_do_task(&qp->comp.task);
			vhost_rdma_drop_ref(qp, qp->dev, qp);
			return 0;
		}
		payload = mtu;
	}

	mbuf = init_req_packet(qp, wqe, opcode, payload, &pkt);
	if (unlikely(!mbuf)) {
		RDMA_LOG_ERR_DP("qp#%d Failed allocating mbuf", qp->qpn);
		wqe->status = VIRTIO_IB_WC_LOC_QP_OP_ERR;
		goto err;
	}

	ret = finish_packet(qp, wqe, &pkt, mbuf, payload);
	if (unlikely(ret)) {
		RDMA_LOG_DEBUG_DP("qp#%d Error during finish packet", qp->qpn);
		if (ret == -EFAULT)
			wqe->status = VIRTIO_IB_WC_LOC_PROT_ERR;
		else
			wqe->status = VIRTIO_IB_WC_LOC_QP_OP_ERR;
		rte_pktmbuf_free(mbuf);
		goto err;
	}

	/*
	 * To prevent a race on wqe access between requester and completer,
	 * wqe members state and psn need to be set before calling
	 * rxe_xmit_packet().
	 * Otherwise, completer might initiate an unjustified retry flow.
	 */
	save_state(wqe, qp, &rollback_wqe, &rollback_psn);
	update_wqe_state(qp, wqe, &pkt);
	update_wqe_psn(qp, wqe, &pkt, payload);
	ret = vhost_rdma_xmit_packet(qp, &pkt, mbuf);
	if (ret) {
		qp->need_req_mbuf = 1;

		rollback_state(wqe, qp, &rollback_wqe, rollback_psn);

		if (ret == -EAGAIN) {
			vhost_rdma_run_task(&qp->req.task, 1);
			goto exit;
		}

		wqe->status = VIRTIO_IB_WC_LOC_QP_OP_ERR;
		goto err;
	}

	update_state(qp, &pkt);

	goto next_wqe;

err:
	wqe->state = wqe_state_error;
	__vhost_rdma_do_task(&qp->comp.task);

exit:
	vhost_rdma_drop_ref(qp, qp->dev, qp);
	return -EAGAIN;
}
