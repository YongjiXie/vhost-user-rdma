/*
 * Vhost-user RDMA device demo: task completer
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
#include "virtio_rdma_abi.h"

enum comp_state {
	COMPST_GET_ACK,
	COMPST_GET_WQE,
	COMPST_COMP_WQE,
	COMPST_COMP_ACK,
	COMPST_CHECK_PSN,
	COMPST_CHECK_ACK,
	COMPST_READ,
	COMPST_ATOMIC,
	COMPST_WRITE_SEND,
	COMPST_UPDATE_COMP,
	COMPST_ERROR_RETRY,
	COMPST_RNR_RETRY,
	COMPST_ERROR,
	COMPST_EXIT, /* We have an issue, and we want to rerun the completer */
	COMPST_DONE, /* The completer finished successflly */
};

static char *comp_state_name[] =  {
	[COMPST_GET_ACK]		= "GET ACK",
	[COMPST_GET_WQE]		= "GET WQE",
	[COMPST_COMP_WQE]		= "COMP WQE",
	[COMPST_COMP_ACK]		= "COMP ACK",
	[COMPST_CHECK_PSN]		= "CHECK PSN",
	[COMPST_CHECK_ACK]		= "CHECK ACK",
	[COMPST_READ]			= "READ",
	[COMPST_ATOMIC]			= "ATOMIC",
	[COMPST_WRITE_SEND]		= "WRITE/SEND",
	[COMPST_UPDATE_COMP]		= "UPDATE COMP",
	[COMPST_ERROR_RETRY]		= "ERROR RETRY",
	[COMPST_RNR_RETRY]		= "RNR RETRY",
	[COMPST_ERROR]			= "ERROR",
	[COMPST_EXIT]			= "EXIT",
	[COMPST_DONE]			= "DONE",
};

static unsigned long rnrnak_usec[32] = {
	[IB_RNR_TIMER_655_36] = 655360,
	[IB_RNR_TIMER_000_01] = 10,
	[IB_RNR_TIMER_000_02] = 20,
	[IB_RNR_TIMER_000_03] = 30,
	[IB_RNR_TIMER_000_04] = 40,
	[IB_RNR_TIMER_000_06] = 60,
	[IB_RNR_TIMER_000_08] = 80,
	[IB_RNR_TIMER_000_12] = 120,
	[IB_RNR_TIMER_000_16] = 160,
	[IB_RNR_TIMER_000_24] = 240,
	[IB_RNR_TIMER_000_32] = 320,
	[IB_RNR_TIMER_000_48] = 480,
	[IB_RNR_TIMER_000_64] = 640,
	[IB_RNR_TIMER_000_96] = 960,
	[IB_RNR_TIMER_001_28] = 1280,
	[IB_RNR_TIMER_001_92] = 1920,
	[IB_RNR_TIMER_002_56] = 2560,
	[IB_RNR_TIMER_003_84] = 3840,
	[IB_RNR_TIMER_005_12] = 5120,
	[IB_RNR_TIMER_007_68] = 7680,
	[IB_RNR_TIMER_010_24] = 10240,
	[IB_RNR_TIMER_015_36] = 15360,
	[IB_RNR_TIMER_020_48] = 20480,
	[IB_RNR_TIMER_030_72] = 30720,
	[IB_RNR_TIMER_040_96] = 40960,
	[IB_RNR_TIMER_061_44] = 61410,
	[IB_RNR_TIMER_081_92] = 81920,
	[IB_RNR_TIMER_122_88] = 122880,
	[IB_RNR_TIMER_163_84] = 163840,
	[IB_RNR_TIMER_245_76] = 245760,
	[IB_RNR_TIMER_327_68] = 327680,
	[IB_RNR_TIMER_491_52] = 491520,
};

static __rte_always_inline unsigned long
rnrnak_ticks(uint8_t timeout)
{
	uint64_t ticks_per_us = rte_get_timer_hz() / 1000000;
	return RTE_MAX(rnrnak_usec[timeout] * ticks_per_us, 1);
}

static enum virtio_ib_wc_opcode
wr_to_wc_opcode(enum virtio_ib_wr_opcode opcode)
{
	switch (opcode) {
	case VIRTIO_IB_WR_RDMA_WRITE:		return VIRTIO_IB_WC_RDMA_WRITE;
	case VIRTIO_IB_WR_RDMA_WRITE_WITH_IMM:	return VIRTIO_IB_WC_RDMA_WRITE;
	case VIRTIO_IB_WR_SEND:			return VIRTIO_IB_WC_SEND;
	case VIRTIO_IB_WR_SEND_WITH_IMM:	return VIRTIO_IB_WC_SEND;
	case VIRTIO_IB_WR_RDMA_READ:		return VIRTIO_IB_WC_RDMA_READ;
	default:
		return 0xff;
	}
}

void
retransmit_timer(__rte_unused struct rte_timer *timer, void* arg)
{
	struct vhost_rdma_qp *qp = arg;

	if (qp->valid) {
		qp->comp.timeout = 1;
		vhost_rdma_run_task(&qp->comp.task, 1);
	}
}

void
vhost_rdma_comp_queue_pkt(struct vhost_rdma_qp *qp, struct rte_mbuf *mbuf)
{
	int must_sched;

	if (unlikely(rte_ring_enqueue(qp->resp_pkts, mbuf) != 0)) {
		rte_pktmbuf_free(mbuf);
	}

	must_sched = rte_ring_count(qp->resp_pkts) > 1;
	if (must_sched != 0)
		vhost_rdma_counter_inc(MBUF_TO_PKT(mbuf)->dev,
								VHOST_CNT_COMPLETER_SCHED);

	vhost_rdma_run_task(&qp->comp.task, must_sched);
}

static __rte_always_inline enum comp_state
get_wqe(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt,
		struct vhost_rdma_send_wqe **wqe_p)
{
	struct vhost_rdma_send_wqe *wqe;

	/* we come here whether or not we found a response packet to see if
	 * there are any posted WQEs
	 */
	wqe = queue_head(&qp->sq.queue);
	*wqe_p = wqe;

	/* no WQE or requester has not started it yet */
	if (!wqe || wqe->state == wqe_state_posted)
		return pkt ? COMPST_DONE : COMPST_EXIT;

	/* WQE does not require an ack */
	if (wqe->state == wqe_state_done)
		return COMPST_COMP_WQE;

	/* WQE caused an error */
	if (wqe->state == wqe_state_error)
		return COMPST_ERROR;

	/* we have a WQE, if we also have an ack check its PSN */
	return pkt ? COMPST_CHECK_PSN : COMPST_EXIT;
}

static __rte_always_inline void
reset_retry_counters(struct vhost_rdma_qp *qp)
{
	qp->comp.retry_cnt = qp->attr.retry_cnt;
	qp->comp.rnr_retry = qp->attr.rnr_retry;
	qp->comp.started_retry = 0;
}

static __rte_always_inline enum comp_state
check_psn(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt,
			struct vhost_rdma_send_wqe *wqe)
{
	int32_t diff;

	/* check to see if response is past the oldest WQE. if it is, complete
	 * send/write or error read/atomic
	 */
	diff = psn_compare(pkt->psn, wqe->last_psn);
	if (diff > 0) {
		if (wqe->state == wqe_state_pending) {
			if (wqe->mask & WR_ATOMIC_OR_READ_MASK)
				return COMPST_ERROR_RETRY;

			reset_retry_counters(qp);
			return COMPST_COMP_WQE;
		} else {
			return COMPST_DONE;
		}
	}

	/* compare response packet to expected response */
	diff = psn_compare(pkt->psn, qp->comp.psn);
	if (diff < 0) {
		/* response is most likely a retried packet if it matches an
		 * uncompleted WQE go complete it else ignore it
		 */
		if (pkt->psn == wqe->last_psn)
			return COMPST_COMP_ACK;
		else
			return COMPST_DONE;
	} else if ((diff > 0) && (wqe->mask & WR_ATOMIC_OR_READ_MASK)) {
		return COMPST_DONE;
	} else {
		return COMPST_CHECK_ACK;
	}
}

static __rte_always_inline enum comp_state
check_ack(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt,
			struct vhost_rdma_send_wqe *wqe)
{
	unsigned int mask = pkt->mask;
	uint8_t syn;
	struct vhost_rdma_dev *dev = qp->dev;

	/* Check the sequence only */
	switch (qp->comp.opcode) {
	case -1:
		/* Will catch all *_ONLY cases. */
		if (!(mask & VHOST_START_MASK))
			return COMPST_ERROR;

		break;

	case IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST:
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE:
		if (pkt->opcode != IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE &&
		    pkt->opcode != IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST) {
			/* read retries of partial data may restart from
			 * read response first or response only.
			 */
			if ((pkt->psn == wqe->first_psn &&
			     pkt->opcode ==
			     IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST) ||
			    (wqe->first_psn == wqe->last_psn &&
			     pkt->opcode ==
			     IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY))
				break;

			return COMPST_ERROR;
		}
		break;
	default:
		RDMA_LOG_ERR_DP("%s should not reach here", __func__);
	}

	/* Check operation validity. */
	switch (pkt->opcode) {
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST:
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST:
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY:
		syn = aeth_syn(pkt);

		if ((syn & AETH_TYPE_MASK) != AETH_ACK)
			return COMPST_ERROR;

		// fallthrough
		/* (IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE doesn't have an AETH)
		 */
	case IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE:
		if (wqe->wr->opcode != VIRTIO_IB_WR_RDMA_READ) {
			wqe->status = VIRTIO_IB_WC_FATAL_ERR;
			return COMPST_ERROR;
		}
		reset_retry_counters(qp);
		return COMPST_READ;

	case IB_OPCODE_RC_ACKNOWLEDGE:
		syn = aeth_syn(pkt);
		switch (syn & AETH_TYPE_MASK) {
		case AETH_ACK:
			reset_retry_counters(qp);
			return COMPST_WRITE_SEND;

		case AETH_RNR_NAK:
			vhost_rdma_counter_inc(dev, VHOST_CNT_RCV_RNR);
			return COMPST_RNR_RETRY;

		case AETH_NAK:
			switch (syn) {
			case AETH_NAK_PSN_SEQ_ERROR:
				/* a nak implicitly acks all packets with psns
				 * before
				 */
				if (psn_compare(pkt->psn, qp->comp.psn) > 0) {
					vhost_rdma_counter_inc(dev, VHOST_CNT_RCV_SEQ_ERR);
					qp->comp.psn = pkt->psn;
					if (qp->req.wait_psn) {
						qp->req.wait_psn = 0;
						vhost_rdma_run_task(&qp->req.task, 0);
					}
				}
				return COMPST_ERROR_RETRY;

			case AETH_NAK_INVALID_REQ:
				wqe->status = VIRTIO_IB_WC_REM_INV_REQ_ERR;
				return COMPST_ERROR;

			case AETH_NAK_REM_ACC_ERR:
				wqe->status = VIRTIO_IB_WC_REM_ACCESS_ERR;
				return COMPST_ERROR;

			case AETH_NAK_REM_OP_ERR:
				wqe->status = VIRTIO_IB_WC_REM_OP_ERR;
				return COMPST_ERROR;

			default:
				RDMA_LOG_ERR_DP("unexpected nak %x", syn);
				wqe->status = VIRTIO_IB_WC_REM_OP_ERR;
				return COMPST_ERROR;
			}

		default:
			return COMPST_ERROR;
		}
		break;

	default:
		RDMA_LOG_ERR_DP("unexpected opcode: %u\n", pkt->opcode);
	}

	return COMPST_ERROR;
}

static __rte_always_inline enum comp_state
do_read(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt,
		struct vhost_rdma_send_wqe *wqe)
{
	int ret;

	ret = copy_data(qp->pd, VIRTIO_IB_ACCESS_LOCAL_WRITE,
			&wqe->dma, payload_addr(pkt),
			payload_size(pkt), VHOST_TO_MR_OBJ, NULL);
	if (ret) {
		wqe->status = VIRTIO_IB_WC_LOC_PROT_ERR;
		return COMPST_ERROR;
	}

	if (wqe->dma.resid == 0 && (pkt->mask & VHOST_END_MASK))
		return COMPST_COMP_ACK;

	return COMPST_UPDATE_COMP;
}

static __rte_always_inline enum comp_state
do_atomic(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt,
		struct vhost_rdma_send_wqe *wqe)
{
	int ret;

	uint64_t atomic_orig = atmack_orig(pkt);

	ret = copy_data(qp->pd, VIRTIO_IB_ACCESS_LOCAL_WRITE,
			&wqe->dma, &atomic_orig,
			sizeof(uint64_t), VHOST_TO_MR_OBJ, NULL);
	if (ret) {
		wqe->status = VIRTIO_IB_WC_LOC_PROT_ERR;
		return COMPST_ERROR;
	}

	return COMPST_COMP_ACK;
}

static void
make_send_cqe(struct vhost_rdma_qp *qp, struct vhost_rdma_send_wqe *wqe,
		struct virtio_rdma_cq_req *cqe)
{
	memset(cqe, 0, sizeof(*cqe));

	cqe->wr_id		= wqe->wr->wr_id;
	cqe->status		= wqe->status;
	cqe->opcode		= wr_to_wc_opcode(wqe->wr->opcode);
	if (wqe->wr->opcode == VIRTIO_IB_WR_RDMA_WRITE_WITH_IMM ||
		wqe->wr->opcode == VIRTIO_IB_WR_SEND_WITH_IMM)
		cqe->wc_flags = VIRTIO_IB_WC_WITH_IMM;
	cqe->byte_len		= wqe->dma.length;
	cqe->qp_num		= qp->qpn;
}

/*
 * IBA Spec. Section 10.7.3.1 SIGNALED COMPLETIONS
 * ---------8<---------8<-------------
 * ...Note that if a completion error occurs, a Work Completion
 * will always be generated, even if the signaling
 * indicator requests an Unsignaled Completion.
 * ---------8<---------8<-------------
 */
static void
do_complete(struct vhost_rdma_qp *qp, struct vhost_rdma_send_wqe *wqe)
{
	struct vhost_rdma_dev *dev = qp->dev;
	struct virtio_rdma_cq_req cqe;
	bool post;

	/* do we need to post a completion */
	post = (qp->sq_sig_all ||
		(wqe->wr->send_flags & VIRTIO_IB_SEND_SIGNALED) ||
		wqe->status != VIRTIO_IB_WC_SUCCESS);

	if (post)
		make_send_cqe(qp, wqe, &cqe);

	advance_consumer(&qp->sq.queue);

	if (post)
		vhost_rdma_cq_post(dev, qp->scq, &cqe, 0);

	if (wqe->wr->opcode == VIRTIO_IB_WR_SEND ||
	    wqe->wr->opcode == VIRTIO_IB_WR_SEND_WITH_IMM)
		vhost_rdma_counter_inc(dev, VHOST_CNT_RDMA_SEND);

	/*
	 * we completed something so let req run again
	 * if it is trying to fence
	 */
	if (qp->req.wait_fence) {
		qp->req.wait_fence = 0;
		vhost_rdma_run_task(&qp->req.task, 0);
	}
}

static __rte_always_inline enum comp_state
complete_ack(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt,
			struct vhost_rdma_send_wqe *wqe)
{
	if (wqe->has_rd_atomic) {
		wqe->has_rd_atomic = 0;
		rte_atomic32_inc(&qp->req.rd_atomic);
		if (qp->req.need_rd_atomic) {
			qp->comp.timeout_retry = 0;
			qp->req.need_rd_atomic = 0;
			vhost_rdma_run_task(&qp->req.task, 0);
		}
	}

	if (unlikely(qp->req.state == QP_STATE_DRAIN)) {
		/* state_lock used by requester & completer */
		rte_spinlock_lock(&qp->state_lock);
		if ((qp->req.state == QP_STATE_DRAIN) &&
		    (qp->comp.psn == qp->req.psn)) {
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
		} else {
			rte_spinlock_unlock(&qp->state_lock);
		}
	}

	do_complete(qp, wqe);

	if (psn_compare(pkt->psn, qp->comp.psn) >= 0)
		return COMPST_UPDATE_COMP;
	else
		return COMPST_DONE;
}

static __rte_always_inline enum comp_state
complete_wqe(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt,
			struct vhost_rdma_send_wqe *wqe)
{
	if (pkt && wqe->state == wqe_state_pending) {
		if (psn_compare(wqe->last_psn, qp->comp.psn) >= 0) {
			qp->comp.psn = (wqe->last_psn + 1) & BTH_PSN_MASK;
			qp->comp.opcode = -1;
		}

		if (qp->req.wait_psn) {
			qp->req.wait_psn = 0;
			vhost_rdma_run_task(&qp->req.task, 1);
		}
	}

	do_complete(qp, wqe);

	return COMPST_GET_WQE;
}

static void
vhost_rdma_drain_resp_pkts(struct vhost_rdma_qp *qp, bool notify)
{
	struct rte_mbuf *mbuf;
	struct vhost_rdma_send_wqe *wqe;
	struct vhost_rdma_queue *q = &qp->sq.queue;

	while (rte_ring_dequeue(qp->resp_pkts, (void**)&mbuf) == 0) {
		vhost_rdma_drop_ref(qp, qp->dev, qp);
		rte_pktmbuf_free(mbuf);
	}

	while ((wqe = queue_head(q))) {
		if (notify) {
			wqe->status = VIRTIO_IB_WC_WR_FLUSH_ERR;
			do_complete(qp, wqe);
		} else {
			advance_consumer(q);
		}
	}
}

static __rte_always_inline void
free_pkt(struct vhost_rdma_pkt_info *pkt)
{
	struct rte_mbuf *mbuf = PKT_TO_MBUF(pkt);

	vhost_rdma_drop_ref(pkt->qp, pkt->qp->dev, qp);
	rte_pktmbuf_free(mbuf);
}

int
vhost_rdma_completer(void* arg)
{
	struct vhost_rdma_qp *qp = arg;
	struct vhost_rdma_dev *dev = qp->dev;
	struct vhost_rdma_send_wqe *wqe = NULL;
	struct rte_mbuf *mbuf = NULL;
	struct vhost_rdma_pkt_info *pkt = NULL;
	enum comp_state state;
	int ret = 0;

	vhost_rdma_add_ref(qp);

	if (!qp->valid || qp->req.state == QP_STATE_ERROR ||
	    qp->req.state == QP_STATE_RESET) {
		vhost_rdma_drain_resp_pkts(qp, qp->valid &&
				    qp->req.state == QP_STATE_ERROR);
		ret = -EAGAIN;
		goto done;
	}

	if (qp->comp.timeout) {
		qp->comp.timeout_retry = 1;
		qp->comp.timeout = 0;
	} else {
		qp->comp.timeout_retry = 0;
	}

	if (qp->req.need_retry) {
		ret = -EAGAIN;
		goto done;
	}

	state = COMPST_GET_ACK;

	while (1) {
		RDMA_LOG_DEBUG_DP("qp#%d state = %s\n", qp->qpn,
			 comp_state_name[state]);
		switch (state) {
		case COMPST_GET_ACK:
			if (rte_ring_dequeue(qp->resp_pkts, (void**)&mbuf) == 0) {
				pkt = MBUF_TO_PKT(mbuf);
				qp->comp.timeout_retry = 0;
			} else {
				mbuf = NULL;
			}
			state = COMPST_GET_WQE;
			break;

		case COMPST_GET_WQE:
			state = get_wqe(qp, pkt, &wqe);
			break;

		case COMPST_CHECK_PSN:
			state = check_psn(qp, pkt, wqe);
			break;

		case COMPST_CHECK_ACK:
			state = check_ack(qp, pkt, wqe);
			break;

		case COMPST_READ:
			state = do_read(qp, pkt, wqe);
			break;

		case COMPST_ATOMIC:
			state = do_atomic(qp, pkt, wqe);
			break;

		case COMPST_WRITE_SEND:
			if (wqe->state == wqe_state_pending &&
			    wqe->last_psn == pkt->psn)
				state = COMPST_COMP_ACK;
			else
				state = COMPST_UPDATE_COMP;
			break;

		case COMPST_COMP_ACK:
			state = complete_ack(qp, pkt, wqe);
			break;

		case COMPST_COMP_WQE:
			state = complete_wqe(qp, pkt, wqe);
			break;

		case COMPST_UPDATE_COMP:
			if (pkt->mask & VHOST_END_MASK)
				qp->comp.opcode = -1;
			else
				qp->comp.opcode = pkt->opcode;

			if (psn_compare(pkt->psn, qp->comp.psn) >= 0)
				qp->comp.psn = (pkt->psn + 1) & BTH_PSN_MASK;

			if (qp->req.wait_psn) {
				qp->req.wait_psn = 0;
				vhost_rdma_run_task(&qp->req.task, 1);
			}

			state = COMPST_DONE;
			break;

		case COMPST_DONE:
			goto done;

		case COMPST_EXIT:
			if (qp->comp.timeout_retry && wqe) {
				state = COMPST_ERROR_RETRY;
				break;
			}

			/* re reset the timeout counter if
			 * (1) QP is type RC
			 * (2) the QP is alive
			 * (3) there is a packet sent by the requester that
			 *     might be acked (we still might get spurious
			 *     timeouts but try to keep them as few as possible)
			 * (4) the timeout parameter is set
			 */
			if ((qp->type == VIRTIO_IB_QPT_RC) &&
			    (qp->req.state == QP_STATE_READY) &&
			    (psn_compare(qp->req.psn, qp->comp.psn) > 0) &&
			    qp->qp_timeout_ticks)
				rte_timer_reset(&qp->retrans_timer, qp->qp_timeout_ticks,
								SINGLE, rte_lcore_id(), retransmit_timer, qp);
			ret = -EAGAIN;
			goto done;

		case COMPST_ERROR_RETRY:
			/* we come here if the retry timer fired and we did
			 * not receive a response packet. try to retry the send
			 * queue if that makes sense and the limits have not
			 * been exceeded. remember that some timeouts are
			 * spurious since we do not reset the timer but kick
			 * it down the road or let it expire
			 */

			/* there is nothing to retry in this case */
			if (!wqe || (wqe->state == wqe_state_posted)) {
				ret = -EAGAIN;
				goto done;
			}

			/* if we've started a retry, don't start another
			 * retry sequence, unless this is a timeout.
			 */
			if (qp->comp.started_retry &&
			    !qp->comp.timeout_retry)
				goto done;

			if (qp->comp.retry_cnt > 0) {
				if (qp->comp.retry_cnt != 7)
					qp->comp.retry_cnt--;

				/* no point in retrying if we have already
				 * seen the last ack that the requester could
				 * have caused
				 */
				if (psn_compare(qp->req.psn,
						qp->comp.psn) > 0) {
					/* tell the requester to retry the
					 * send queue next time around
					 */
					vhost_rdma_counter_inc(dev, VHOST_CNT_COMP_RETRY);
					qp->req.need_retry = 1;
					qp->comp.started_retry = 1;
					vhost_rdma_run_task(&qp->req.task, 0);
				}
				goto done;

			} else {
				vhost_rdma_counter_inc(dev, VHOST_CNT_RETRY_EXCEEDED);
				wqe->status = VIRTIO_IB_WC_RETRY_EXC_ERR;
				state = COMPST_ERROR;
			}
			break;

		case COMPST_RNR_RETRY:
			if (qp->comp.rnr_retry > 0) {
				if (qp->comp.rnr_retry != 7)
					qp->comp.rnr_retry--;

				qp->req.need_retry = 1;
				RDMA_LOG_DEBUG_DP("qp#%d set rnr nak timer", qp->qpn);
				rte_timer_reset(&qp->rnr_nak_timer,
								rnrnak_ticks(aeth_syn(pkt) & ~AETH_TYPE_MASK),
								SINGLE, rte_lcore_id(), rnr_nak_timer, qp);
				ret = -EAGAIN;
				goto done;
			} else {
				vhost_rdma_counter_inc(dev, VHOST_CNT_RNR_RETRY_EXCEEDED);
				wqe->status = VIRTIO_IB_WC_RNR_RETRY_EXC_ERR;
				state = COMPST_ERROR;
			}
			break;

		case COMPST_ERROR:
			RDMA_LOG_ERR_DP("WQE Error: %u", wqe->status);
			do_complete(qp, wqe);
			vhost_rdma_qp_error(qp);
			ret = -EAGAIN;
			goto done;
		}
	}

done:
	if (pkt)
		free_pkt(pkt);
	vhost_rdma_drop_ref(qp, qp->dev, qp);

	return ret;
}
