/*
 * Vhost-user RDMA device demo: task responder
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
#include <rte_spinlock.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include "vhost_rdma_loc.h"
#include "verbs.h"

enum resp_states {
	RESPST_NONE,
	RESPST_GET_REQ,
	RESPST_CHK_PSN,
	RESPST_CHK_OP_SEQ,
	RESPST_CHK_OP_VALID,
	RESPST_CHK_RESOURCE,
	RESPST_CHK_LENGTH,
	RESPST_CHK_RKEY,
	RESPST_EXECUTE,
	RESPST_READ_REPLY,
	RESPST_COMPLETE,
	RESPST_ACKNOWLEDGE,
	RESPST_CLEANUP,
	RESPST_DUPLICATE_REQUEST,
	RESPST_ERR_MALFORMED_WQE,
	RESPST_ERR_UNSUPPORTED_OPCODE,
	RESPST_ERR_MISALIGNED_ATOMIC,
	RESPST_ERR_PSN_OUT_OF_SEQ,
	RESPST_ERR_MISSING_OPCODE_FIRST,
	RESPST_ERR_MISSING_OPCODE_LAST_C,
	RESPST_ERR_MISSING_OPCODE_LAST_D1E,
	RESPST_ERR_TOO_MANY_RDMA_ATM_REQ,
	RESPST_ERR_RNR,
	RESPST_ERR_RKEY_VIOLATION,
	RESPST_ERR_INVALIDATE_RKEY,
	RESPST_ERR_LENGTH,
	RESPST_ERR_CQ_OVERFLOW,
	RESPST_ERROR,
	RESPST_RESET,
	RESPST_DONE,
	RESPST_EXIT,
};

static char *resp_state_name[] = {
	[RESPST_NONE]				= "NONE",
	[RESPST_GET_REQ]			= "GET_REQ",
	[RESPST_CHK_PSN]			= "CHK_PSN",
	[RESPST_CHK_OP_SEQ]			= "CHK_OP_SEQ",
	[RESPST_CHK_OP_VALID]			= "CHK_OP_VALID",
	[RESPST_CHK_RESOURCE]			= "CHK_RESOURCE",
	[RESPST_CHK_LENGTH]			= "CHK_LENGTH",
	[RESPST_CHK_RKEY]			= "CHK_RKEY",
	[RESPST_EXECUTE]			= "EXECUTE",
	[RESPST_READ_REPLY]			= "READ_REPLY",
	[RESPST_COMPLETE]			= "COMPLETE",
	[RESPST_ACKNOWLEDGE]			= "ACKNOWLEDGE",
	[RESPST_CLEANUP]			= "CLEANUP",
	[RESPST_DUPLICATE_REQUEST]		= "DUPLICATE_REQUEST",
	[RESPST_ERR_MALFORMED_WQE]		= "ERR_MALFORMED_WQE",
	[RESPST_ERR_UNSUPPORTED_OPCODE]		= "ERR_UNSUPPORTED_OPCODE",
	[RESPST_ERR_MISALIGNED_ATOMIC]		= "ERR_MISALIGNED_ATOMIC",
	[RESPST_ERR_PSN_OUT_OF_SEQ]		= "ERR_PSN_OUT_OF_SEQ",
	[RESPST_ERR_MISSING_OPCODE_FIRST]	= "ERR_MISSING_OPCODE_FIRST",
	[RESPST_ERR_MISSING_OPCODE_LAST_C]	= "ERR_MISSING_OPCODE_LAST_C",
	[RESPST_ERR_MISSING_OPCODE_LAST_D1E]	= "ERR_MISSING_OPCODE_LAST_D1E",
	[RESPST_ERR_TOO_MANY_RDMA_ATM_REQ]	= "ERR_TOO_MANY_RDMA_ATM_REQ",
	[RESPST_ERR_RNR]			= "ERR_RNR",
	[RESPST_ERR_RKEY_VIOLATION]		= "ERR_RKEY_VIOLATION",
	[RESPST_ERR_INVALIDATE_RKEY]		= "ERR_INVALIDATE_RKEY_VIOLATION",
	[RESPST_ERR_LENGTH]			= "ERR_LENGTH",
	[RESPST_ERR_CQ_OVERFLOW]		= "ERR_CQ_OVERFLOW",
	[RESPST_ERROR]				= "ERROR",
	[RESPST_RESET]				= "RESET",
	[RESPST_DONE]				= "DONE",
	[RESPST_EXIT]				= "EXIT",
};

void
vhost_rdma_resp_queue_pkt(struct vhost_rdma_qp *qp, struct rte_mbuf *mbuf)
{
	int must_sched;
	struct vhost_rdma_pkt_info *pkt = MBUF_TO_PKT(mbuf);

	if (unlikely(rte_ring_enqueue(qp->req_pkts, mbuf) != 0)) {
		rte_pktmbuf_free(mbuf);
		return;
	}

	must_sched = (pkt->opcode == IB_OPCODE_RC_RDMA_READ_REQUEST) ||
			(rte_ring_count(qp->req_pkts) > 1);

	vhost_rdma_run_task(&qp->resp.task, must_sched);
}

static __rte_always_inline enum resp_states
get_req(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info **pkt_p)
{
	struct rte_mbuf *mbuf;

	if (qp->resp.state == QP_STATE_ERROR) {
		if (qp->req_pkts_head != NULL) {
			vhost_rdma_drop_ref(qp, qp->dev, qp);
			rte_pktmbuf_free(qp->req_pkts_head);
			qp->req_pkts_head = NULL;
		}
		while (rte_ring_dequeue(qp->req_pkts, (void**)&mbuf) == 0) {
			vhost_rdma_drop_ref(qp, qp->dev, qp);
			rte_pktmbuf_free(mbuf);
		}
		/* go drain recv wr queue */
		return RESPST_CHK_RESOURCE;
	}

	if (qp->req_pkts_head != NULL) {
		mbuf = qp->req_pkts_head;
	} else {
		if (rte_ring_dequeue(qp->req_pkts, (void**)&mbuf) == 0) {
			qp->req_pkts_head = mbuf;
		} else {
			return RESPST_EXIT;
		}
	}
	// skb = skb_peek(&qp->req_pkts);
	// if (!mbuf)
	// 	return RESPST_EXIT;

	*pkt_p = MBUF_TO_PKT(mbuf);

	return (qp->resp.res) ? RESPST_READ_REPLY : RESPST_CHK_PSN;
}

static enum resp_states
check_psn(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt)
{
	int diff = psn_compare(pkt->psn, qp->resp.psn);
	struct vhost_rdma_dev *dev = qp->dev;

	switch (qp->type) {
	case VIRTIO_IB_QPT_RC:
		if (diff > 0) {
			if (qp->resp.sent_psn_nak)
				return RESPST_CLEANUP;

			qp->resp.sent_psn_nak = 1;
			vhost_rdma_counter_inc(dev, VHOST_CNT_OUT_OF_SEQ_REQ);
			return RESPST_ERR_PSN_OUT_OF_SEQ;

		} else if (diff < 0) {
			vhost_rdma_counter_inc(dev, VHOST_CNT_DUP_REQ);
			return RESPST_DUPLICATE_REQUEST;
		}

		if (qp->resp.sent_psn_nak)
			qp->resp.sent_psn_nak = 0;

		break;

	case VIRTIO_IB_QPT_UC:
		if (qp->resp.drop_msg || diff != 0) {
			if (pkt->mask & VHOST_START_MASK) {
				qp->resp.drop_msg = 0;
				return RESPST_CHK_OP_SEQ;
			}

			qp->resp.drop_msg = 1;
			return RESPST_CLEANUP;
		}
		break;
	default:
		break;
	}

	return RESPST_CHK_OP_SEQ;
}

static enum resp_states
check_op_seq(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt)
{
	switch (qp->type) {
	case VIRTIO_IB_QPT_RC:
		switch (qp->resp.opcode) {
		case IB_OPCODE_RC_SEND_FIRST:
		case IB_OPCODE_RC_SEND_MIDDLE:
			switch (pkt->opcode) {
			case IB_OPCODE_RC_SEND_MIDDLE:
			case IB_OPCODE_RC_SEND_LAST:
			case IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE:
			case IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE:
				return RESPST_CHK_OP_VALID;
			default:
				return RESPST_ERR_MISSING_OPCODE_LAST_C;
			}

		case IB_OPCODE_RC_RDMA_WRITE_FIRST:
		case IB_OPCODE_RC_RDMA_WRITE_MIDDLE:
			switch (pkt->opcode) {
			case IB_OPCODE_RC_RDMA_WRITE_MIDDLE:
			case IB_OPCODE_RC_RDMA_WRITE_LAST:
			case IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
				return RESPST_CHK_OP_VALID;
			default:
				return RESPST_ERR_MISSING_OPCODE_LAST_C;
			}

		default:
			switch (pkt->opcode) {
			case IB_OPCODE_RC_SEND_MIDDLE:
			case IB_OPCODE_RC_SEND_LAST:
			case IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE:
			case IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE:
			case IB_OPCODE_RC_RDMA_WRITE_MIDDLE:
			case IB_OPCODE_RC_RDMA_WRITE_LAST:
			case IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
				return RESPST_ERR_MISSING_OPCODE_FIRST;
			default:
				return RESPST_CHK_OP_VALID;
			}
		}
		break;

	case VIRTIO_IB_QPT_UC:
		switch (qp->resp.opcode) {
		case IB_OPCODE_UC_SEND_FIRST:
		case IB_OPCODE_UC_SEND_MIDDLE:
			switch (pkt->opcode) {
			case IB_OPCODE_UC_SEND_MIDDLE:
			case IB_OPCODE_UC_SEND_LAST:
			case IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE:
				return RESPST_CHK_OP_VALID;
			default:
				return RESPST_ERR_MISSING_OPCODE_LAST_D1E;
			}

		case IB_OPCODE_UC_RDMA_WRITE_FIRST:
		case IB_OPCODE_UC_RDMA_WRITE_MIDDLE:
			switch (pkt->opcode) {
			case IB_OPCODE_UC_RDMA_WRITE_MIDDLE:
			case IB_OPCODE_UC_RDMA_WRITE_LAST:
			case IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
				return RESPST_CHK_OP_VALID;
			default:
				return RESPST_ERR_MISSING_OPCODE_LAST_D1E;
			}

		default:
			switch (pkt->opcode) {
			case IB_OPCODE_UC_SEND_MIDDLE:
			case IB_OPCODE_UC_SEND_LAST:
			case IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE:
			case IB_OPCODE_UC_RDMA_WRITE_MIDDLE:
			case IB_OPCODE_UC_RDMA_WRITE_LAST:
			case IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE:
				qp->resp.drop_msg = 1;
				return RESPST_CLEANUP;
			default:
				return RESPST_CHK_OP_VALID;
			}
		}
		break;

	default:
		return RESPST_CHK_OP_VALID;
	}
}

static enum resp_states
check_op_valid(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt)
{
	switch (qp->type) {
	case VIRTIO_IB_QPT_RC:
		if (((pkt->mask & VHOST_READ_MASK) &&
		     !(qp->attr.qp_access_flags & VIRTIO_IB_ACCESS_REMOTE_READ)) ||
		    ((pkt->mask & VHOST_WRITE_MASK) &&
		     !(qp->attr.qp_access_flags & VIRTIO_IB_ACCESS_REMOTE_WRITE))) {
			return RESPST_ERR_UNSUPPORTED_OPCODE;
		}

		break;

	case VIRTIO_IB_QPT_UC:
		if ((pkt->mask & VHOST_WRITE_MASK) &&
		    !(qp->attr.qp_access_flags & VIRTIO_IB_ACCESS_REMOTE_WRITE)) {
			qp->resp.drop_msg = 1;
			return RESPST_CLEANUP;
		}

		break;

	case VIRTIO_IB_QPT_UD:
	case VIRTIO_IB_QPT_SMI:
	case VIRTIO_IB_QPT_GSI:
		break;

	default:
		RDMA_LOG_ERR_DP("%s: qp type not support", __func__);
		break;
	}

	return RESPST_CHK_RESOURCE;
}

static enum resp_states
check_resource(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt)
{
	struct vhost_rdma_srq *srq = qp->srq;

	if (qp->resp.state == QP_STATE_ERROR) {
		if (qp->resp.wqe) {
			qp->resp.status = VIRTIO_IB_WC_WR_FLUSH_ERR;
			return RESPST_COMPLETE;
		} else if (!srq) {
			qp->resp.wqe = queue_head(&qp->rq.queue);
			if (qp->resp.wqe) {
				qp->resp.status = VIRTIO_IB_WC_WR_FLUSH_ERR;
				return RESPST_COMPLETE;
			} else {
				return RESPST_EXIT;
			}
		} else {
			return RESPST_EXIT;
		}
	}

	if (pkt->mask & VHOST_READ_OR_ATOMIC) {
		/* it is the requesters job to not send
		 * too many read/atomic ops, we just
		 * recycle the responder resource queue
		 */
		if (likely(qp->attr.max_dest_rd_atomic > 0))
			return RESPST_CHK_LENGTH;
		else
			return RESPST_ERR_TOO_MANY_RDMA_ATM_REQ;
	}

	if (pkt->mask & VHOST_RWR_MASK) {
		if (srq)
			RDMA_LOG_ERR_DP("srq is not supported");
			// return get_srq_wqe(qp);

		qp->resp.wqe = queue_head(&qp->rq.queue);
		return (qp->resp.wqe) ? RESPST_CHK_LENGTH : RESPST_ERR_RNR;
	}

	return RESPST_CHK_LENGTH;
}

static enum resp_states
check_length(struct vhost_rdma_qp *qp, __rte_unused struct vhost_rdma_pkt_info *pkt)
{
	switch (qp->type) {
	case VIRTIO_IB_QPT_RC:
		return RESPST_CHK_RKEY;

	case VIRTIO_IB_QPT_UC:
		return RESPST_CHK_RKEY;

	default:
		return RESPST_CHK_RKEY;
	}
}

static enum resp_states
check_rkey(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt)
{
	struct vhost_rdma_mr *mr = NULL;
	uint64_t va;
	uint32_t rkey;
	uint32_t resid;
	uint32_t pktlen;
	uint32_t mtu = qp->mtu;
	enum resp_states state;
	int access;

	if (pkt->mask & (VHOST_READ_MASK | VHOST_WRITE_MASK)) {
		if (pkt->mask & VHOST_RETH_MASK) {
			qp->resp.va = reth_va(pkt);
			qp->resp.offset = 0;
			qp->resp.rkey = reth_rkey(pkt);
			qp->resp.resid = reth_len(pkt);
			qp->resp.length = reth_len(pkt);
		}
		access = (pkt->mask & VHOST_READ_MASK) ? VIRTIO_IB_ACCESS_REMOTE_READ
						     : VIRTIO_IB_ACCESS_REMOTE_WRITE;
	} else {
		return RESPST_EXECUTE;
	}

	/* A zero-byte op is not required to set an addr or rkey. */
	if ((pkt->mask & (VHOST_READ_MASK | VHOST_WRITE_OR_SEND)) &&
	    (pkt->mask & VHOST_RETH_MASK) &&
	    reth_len(pkt) == 0) {
		return RESPST_EXECUTE;
	}

	va	= qp->resp.va;
	rkey	= qp->resp.rkey;
	resid	= qp->resp.resid;
	pktlen	= payload_size(pkt);

	mr = lookup_mr(qp->pd, access, rkey, VHOST_LOOKUP_REMOTE);
	if (!mr) {
		RDMA_LOG_ERR_DP("%s: no MR matches rkey %#x\n", __func__, rkey);
		state = RESPST_ERR_RKEY_VIOLATION;
		goto err;
	}

	if (mr_check_range(mr, va + qp->resp.offset, resid)) {
		RDMA_LOG_ERR_DP("bad MR range");
		state = RESPST_ERR_RKEY_VIOLATION;
		goto err;
	}

	if (pkt->mask & VHOST_WRITE_MASK)	 {
		if (resid > mtu) {
			if (pktlen != mtu || bth_pad(pkt)) {
				state = RESPST_ERR_LENGTH;
				goto err;
			}
		} else {
			if (pktlen != resid) {
				state = RESPST_ERR_LENGTH;
				goto err;
			}
			if ((bth_pad(pkt) != (0x3 & (-resid)))) {
				/* This case may not be exactly that
				 * but nothing else fits.
				 */
				state = RESPST_ERR_LENGTH;
				goto err;
			}
		}
	}

	// WARN_ON_ONCE(qp->resp.mr);
	if (qp->resp.mr) {
		RDMA_LOG_ERR_DP("%s WARN on qp->resp.mr", __func__);
	}

	qp->resp.mr = mr;
	return RESPST_EXECUTE;

err:
	if (mr)
		vhost_rdma_drop_ref(mr, qp->dev, mr);
	return state;
}

static enum resp_states
send_data_in(struct vhost_rdma_qp *qp, void *data_addr, int data_len)
{
	int err;

	err = copy_data(qp->pd, VIRTIO_IB_ACCESS_LOCAL_WRITE, &qp->resp.wqe->dma,
			data_addr, data_len, VHOST_TO_MR_OBJ, NULL);
	if (unlikely(err))
		return (err == -ENOSPC) ? RESPST_ERR_LENGTH
					: RESPST_ERR_MALFORMED_WQE;

	return RESPST_NONE;
}

static enum resp_states
write_data_in(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt)
{
	enum resp_states rc = RESPST_NONE;
	int	err;
	int data_len = payload_size(pkt);

	err = vhost_rdma_mr_copy(qp->dev->mem, qp->resp.mr, qp->resp.va + qp->resp.offset,
			  payload_addr(pkt), data_len, VHOST_TO_MR_OBJ, NULL);
	if (err) {
		rc = RESPST_ERR_RKEY_VIOLATION;
		goto out;
	}

	qp->resp.va += data_len;
	qp->resp.resid -= data_len;

out:
	return rc;
}

/* Guarantee atomicity of atomic operations at the machine level. */
static rte_spinlock_t atomic_ops_lock = RTE_SPINLOCK_INITIALIZER;

static enum resp_states
process_atomic(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt)
{
	uint64_t *vaddr;
	enum resp_states ret;
	struct vhost_rdma_mr *mr = qp->resp.mr;

	if (mr->state != VHOST_MR_STATE_VALID) {
		ret = RESPST_ERR_RKEY_VIOLATION;
		goto out;
	}

	vaddr = iova_to_vaddr(mr, qp->resp.va + qp->resp.offset, sizeof(uint64_t));

	/* check vaddr is 8 bytes aligned. */
	if (!vaddr || (uintptr_t)vaddr & 7) {
		ret = RESPST_ERR_MISALIGNED_ATOMIC;
		goto out;
	}

	rte_spinlock_lock(&atomic_ops_lock);

	qp->resp.atomic_orig = *vaddr;

	if (pkt->opcode == IB_OPCODE_RC_COMPARE_SWAP ||
	    pkt->opcode == IB_OPCODE_RD_COMPARE_SWAP) {
		if (*vaddr == atmeth_comp(pkt))
			*vaddr = atmeth_swap_add(pkt);
	} else {
		*vaddr += atmeth_swap_add(pkt);
	}

	rte_spinlock_unlock(&atomic_ops_lock);

	ret = RESPST_NONE;
out:
	return ret;
}

static struct rte_mbuf*
prepare_ack_packet(struct vhost_rdma_qp *qp, __rte_unused struct vhost_rdma_pkt_info *pkt,
	struct vhost_rdma_pkt_info *ack, int opcode, int payload, uint32_t psn,
	uint8_t syndrome, uint32_t *crcp)
{
	struct vhost_rdma_dev *dev = qp->dev;
	struct rte_mbuf *mbuf;
	uint32_t crc = 0;
	uint32_t *p;
	int paylen;
	int pad;
	int err;

	/*
	 * allocate packet
	 */
	pad = (-payload) & 0x3;
	paylen = vhost_rdma_opcode[opcode].length + payload + pad + VHOST_ICRC_SIZE;

	mbuf = vhost_rdma_init_packet(dev, &qp->av, paylen, ack);
	if (!mbuf)
		return NULL;

	ack->qp = qp;
	ack->opcode = opcode;
	ack->mask = vhost_rdma_opcode[opcode].mask;
	ack->paylen = paylen;
	ack->psn = psn;

	bth_init(ack, opcode, 0, 0, pad, IB_DEFAULT_PKEY_FULL,
		 qp->attr.dest_qp_num, 0, psn);

	if (ack->mask & VHOST_AETH_MASK) {
		aeth_set_syn(ack, syndrome);
		aeth_set_msn(ack, qp->resp.msn);
	}

	if (ack->mask & VHOST_ATMACK_MASK)
		atmack_set_orig(ack, qp->resp.atomic_orig);

	err = vhost_rdma_prepare(ack, mbuf, &crc);
	if (err) {
		rte_pktmbuf_free(mbuf);
		return NULL;
	}

	if (crcp) {
		/* CRC computation will be continued by the caller */
		*crcp = crc;
	} else {
		p = payload_addr(ack) + payload + bth_pad(ack);
		*p = ~crc;
	}

	return mbuf;
}

/* RDMA read response. If res is not NULL, then we have a current RDMA request
 * being processed or replayed.
 */
static enum resp_states
read_reply(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *req_pkt)
{
	struct vhost_rdma_pkt_info ack_pkt;
	struct rte_mbuf *mbuf;
	uint32_t mtu = qp->mtu;
	enum resp_states state;
	int payload;
	int opcode;
	int err;
	struct resp_res *res = qp->resp.res;
	uint32_t icrc;
	uint32_t *p;

	if (!res) {
		/* This is the first time we process that request. Get a
		 * resource
		 */
		res = &qp->resp.resources[qp->resp.res_head];

		free_rd_atomic_resource(qp, res);
		vhost_rdma_advance_resp_resource(qp);

		res->type		= VHOST_READ_MASK;
		res->replay		= 0;

		res->read.va		= qp->resp.va +
					  qp->resp.offset;
		res->read.va_org	= qp->resp.va +
					  qp->resp.offset;

		res->first_psn		= req_pkt->psn;

		if (reth_len(req_pkt)) {
			res->last_psn	= (req_pkt->psn +
					   (reth_len(req_pkt) + mtu - 1) /
					   mtu - 1) & BTH_PSN_MASK;
		} else {
			res->last_psn	= res->first_psn;
		}
		res->cur_psn		= req_pkt->psn;

		res->read.resid		= qp->resp.resid;
		res->read.length	= qp->resp.resid;
		res->read.rkey		= qp->resp.rkey;

		/* note res inherits the reference to mr from qp */
		res->read.mr		= qp->resp.mr;
		qp->resp.mr		= NULL;

		qp->resp.res		= res;
		res->state		= rdatm_res_state_new;
	}

	if (res->state == rdatm_res_state_new) {
		if (res->read.resid <= mtu)
			opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY;
		else
			opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST;
	} else {
		if (res->read.resid > mtu)
			opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE;
		else
			opcode = IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST;
	}

	res->state = rdatm_res_state_next;

	payload = RTE_MIN(res->read.resid, mtu);

	mbuf = prepare_ack_packet(qp, req_pkt, &ack_pkt, opcode, payload,
				 res->cur_psn, AETH_ACK_UNLIMITED, &icrc);
	if (!mbuf)
		return RESPST_ERR_RNR;

	err = vhost_rdma_mr_copy(qp->dev->mem, res->read.mr, res->read.va,
				payload_addr(&ack_pkt), payload, VHOST_FROM_MR_OBJ, &icrc);
	if (err)
		RDMA_LOG_ERR_DP("Failed copying memory\n");

	if (bth_pad(&ack_pkt)) {
		uint8_t *pad = payload_addr(&ack_pkt) + payload;

		memset(pad, 0, bth_pad(&ack_pkt));
		icrc = crc32(icrc, pad, bth_pad(&ack_pkt));
	}
	p = payload_addr(&ack_pkt) + payload + bth_pad(&ack_pkt);
	*p = ~icrc;

	err = vhost_rdma_xmit_packet(qp, &ack_pkt, mbuf);
	if (err) {
		RDMA_LOG_ERR_DP("Failed sending RDMA reply.\n");
		return RESPST_ERR_RNR;
	}

	res->read.va += payload;
	res->read.resid -= payload;
	res->cur_psn = (res->cur_psn + 1) & BTH_PSN_MASK;

	if (res->read.resid > 0) {
		state = RESPST_DONE;
	} else {
		qp->resp.res = NULL;
		if (!res->replay)
			qp->resp.opcode = -1;
		if (psn_compare(res->cur_psn, qp->resp.psn) >= 0)
			qp->resp.psn = res->cur_psn;
		state = RESPST_CLEANUP;
	}

	return state;
}

union rdma_network_hdr {
	struct {
		/* The IB spec states that if it's IPv4, the header
		 * is located in the last 20 bytes of the header.
		 */
		uint8_t		reserved[20];
		struct rte_ipv4_hdr	roce4grh;
	};
};

/* Executes a new request. A retried request never reach that function (send
 * and writes are discarded, and reads and atomics are retried elsewhere.
 */
static enum resp_states
execute(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt)
{
	enum resp_states err;
	struct rte_mbuf *mbuf = PKT_TO_MBUF(pkt);
	union rdma_network_hdr hdr;

	if (pkt->mask & VHOST_SEND_MASK) {
		if (qp->type == VIRTIO_IB_QPT_UD ||
		    qp->type == VIRTIO_IB_QPT_SMI ||
		    qp->type == VIRTIO_IB_QPT_GSI) {
			// UD need to write header to the buf
			if (mbuf->l3_type == VHOST_NETWORK_TYPE_IPV4) {
				memset(&hdr.reserved, 0,
						sizeof(hdr.reserved));
				rte_memcpy(&hdr.roce4grh, ip_hdr(pkt),
						sizeof(hdr.roce4grh));
				err = send_data_in(qp, &hdr, sizeof(hdr));
			} else {
				err = send_data_in(qp, ipv6_hdr(pkt),
						sizeof(hdr));
			}
			if (err)
				return err;
		}
		err = send_data_in(qp, payload_addr(pkt), payload_size(pkt));
		if (err)
			return err;
	} else if (pkt->mask & VHOST_WRITE_MASK) {
		err = write_data_in(qp, pkt);
		if (err)
			return err;
	} else if (pkt->mask & VHOST_READ_MASK) {
		/* For RDMA Read we can increment the msn now. See C9-148. */
		qp->resp.msn++;
		return RESPST_READ_REPLY;
	} else if (pkt->mask & VHOST_ATOMIC_MASK) {
		err = process_atomic(qp, pkt);
		if (err)
			return err;
	} else {
		/* Unreachable */
		RDMA_LOG_ERR_DP("%s should be unreachable", __func__);
	}

	/* next expected psn, read handles this separately */
	qp->resp.psn = (pkt->psn + 1) & BTH_PSN_MASK;
	qp->resp.ack_psn = qp->resp.psn;

	qp->resp.opcode = pkt->opcode;
	qp->resp.status = VIRTIO_IB_WC_SUCCESS;

	if (pkt->mask & VHOST_COMP_MASK) {
		/* We successfully processed this new request. */
		qp->resp.msn++;
		return RESPST_COMPLETE;
	} else if (qp->type == VIRTIO_IB_QPT_RC)
		return RESPST_ACKNOWLEDGE;
	else
		return RESPST_CLEANUP;
}

static enum resp_states
do_complete(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt)
{
	struct virtio_rdma_cq_req cqe;
	struct vhost_rdma_recv_wqe *wqe = qp->resp.wqe;
	struct vhost_rdma_dev *dev = qp->dev;

	if (!wqe)
		goto finish;

	memset(&cqe, 0, sizeof(cqe));

	cqe.status = qp->resp.status;
	cqe.qp_num = qp->qpn;
	cqe.wr_id = wqe->wr_id;

	if (cqe.status == VIRTIO_IB_WC_SUCCESS) {
		vhost_rdma_counter_inc(dev, VHOST_CNT_RDMA_RECV);
		cqe.opcode = (pkt->mask & VHOST_IMMDT_MASK &&
				pkt->mask & VHOST_WRITE_MASK) ?
					VIRTIO_IB_WC_RECV_RDMA_WITH_IMM : VIRTIO_IB_WC_RECV;
		cqe.vendor_err = 0;
		cqe.byte_len = (pkt->mask & VHOST_IMMDT_MASK &&
				pkt->mask & VHOST_WRITE_MASK) ?
					qp->resp.length : wqe->dma.length - wqe->dma.resid;

		/* fields after byte_len are different between kernel and user
		 * space
		 */
		cqe.wc_flags = VIRTIO_IB_WC_GRH;
		if (pkt->mask & VHOST_IMMDT_MASK) {
			cqe.wc_flags |= VIRTIO_IB_WC_WITH_IMM;
			cqe.imm_data = immdt_imm(pkt);
		}

		cqe.qp_num = qp->qpn;

		if (pkt->mask & VHOST_DETH_MASK)
			cqe.src_qp = deth_sqp(pkt);
	}

	/* have copy for srq and reference for !srq */
	if (!qp->srq) {
		advance_consumer(&qp->rq.queue);
	}

	qp->resp.wqe = NULL;

	if (vhost_rdma_cq_post(dev, qp->rcq, &cqe, pkt ? bth_se(pkt) : 1))
		return RESPST_ERR_CQ_OVERFLOW;

finish:
	if (unlikely(qp->resp.state == QP_STATE_ERROR))
		return RESPST_CHK_RESOURCE;
	if (unlikely(!pkt))
		return RESPST_DONE;
	if (qp->type == VIRTIO_IB_QPT_RC)
		return RESPST_ACKNOWLEDGE;
	else
		return RESPST_CLEANUP;
}

static int
send_ack(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt,
			uint8_t syndrome, uint32_t psn)
{
	int err = 0;
	struct vhost_rdma_pkt_info ack_pkt;
	struct rte_mbuf *mbuf;

	mbuf = prepare_ack_packet(qp, pkt, &ack_pkt, IB_OPCODE_RC_ACKNOWLEDGE,
				 0, psn, syndrome, NULL);
	if (!mbuf) {
		err = -ENOMEM;
		goto err1;
	}

	err = vhost_rdma_xmit_packet(qp, &ack_pkt, mbuf);
	if (err)
		RDMA_LOG_ERR_DP("Failed sending ack");

err1:
	return err;
}

static int
send_atomic_ack(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt,
				uint8_t syndrome)
{
	int rc = 0;
	struct vhost_rdma_pkt_info ack_pkt;
	struct rte_mbuf *mbuf, *clone;
	struct resp_res *res;

	mbuf = prepare_ack_packet(qp, pkt, &ack_pkt,
				 IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE, 0, pkt->psn,
				 syndrome, NULL);
	if (!mbuf) {
		rc = -ENOMEM;
		goto out;
	}

	res = &qp->resp.resources[qp->resp.res_head];
	free_rd_atomic_resource(qp, res);
	vhost_rdma_advance_resp_resource(qp);

	res->type = VHOST_ATOMIC_MASK;
	// FIXME: skb_get(), is this right?
	clone = rte_pktmbuf_clone(mbuf, qp->dev->mbuf_pool);
	res->atomic.mbuf = mbuf;
	res->first_psn = ack_pkt.psn;
	res->last_psn  = ack_pkt.psn;
	res->cur_psn   = ack_pkt.psn;

	rc = vhost_rdma_xmit_packet(qp, &ack_pkt, clone);
	if (rc) {
		RDMA_LOG_ERR_DP("Failed sending ack");
		// FIXME: when add_ref?
		vhost_rdma_drop_ref(qp, qp->dev, qp);
	}
out:
	return rc;
}

static enum resp_states
acknowledge(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt)
{
	if (qp->type != VIRTIO_IB_QPT_RC)
		return RESPST_CLEANUP;

	if (qp->resp.aeth_syndrome != AETH_ACK_UNLIMITED)
		send_ack(qp, pkt, qp->resp.aeth_syndrome, pkt->psn);
	else if (pkt->mask & VHOST_ATOMIC_MASK)
		send_atomic_ack(qp, pkt, AETH_ACK_UNLIMITED);
	else if (bth_ack(pkt))
		send_ack(qp, pkt, AETH_ACK_UNLIMITED, pkt->psn);

	return RESPST_CLEANUP;
}

static enum resp_states
cleanup(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt)
{
	struct rte_mbuf *mbuf;

	if (pkt) {
		// skb_dequeue
		if (qp->req_pkts_head) {
			mbuf = qp->req_pkts_head;
			qp->req_pkts_head = NULL;
		} else {
			rte_ring_dequeue(qp->req_pkts, (void**)&mbuf);
		}
		vhost_rdma_drop_ref(qp, qp->dev, qp);
		rte_pktmbuf_free(mbuf);
	}

	if (qp->resp.mr) {
		vhost_rdma_drop_ref(qp->resp.mr, qp->dev, mr);
		qp->resp.mr = NULL;
	}

	return RESPST_DONE;
}

static struct resp_res*
find_resource(struct vhost_rdma_qp *qp, uint32_t psn)
{
	int i;

	for (i = 0; i < qp->attr.max_dest_rd_atomic; i++) {
		struct resp_res *res = &qp->resp.resources[i];

		if (res->type == 0)
			continue;

		if (psn_compare(psn, res->first_psn) >= 0 &&
		    psn_compare(psn, res->last_psn) <= 0) {
			return res;
		}
	}

	return NULL;
}

static enum resp_states
duplicate_request(struct vhost_rdma_qp *qp, struct vhost_rdma_pkt_info *pkt)
{
	enum resp_states rc;
	uint32_t prev_psn = (qp->resp.ack_psn - 1) & BTH_PSN_MASK;

	if (pkt->mask & VHOST_SEND_MASK ||
	    pkt->mask & VHOST_WRITE_MASK) {
		/* SEND. Ack again and cleanup. C9-105. */
		send_ack(qp, pkt, AETH_ACK_UNLIMITED, prev_psn);
		return RESPST_CLEANUP;
	} else if (pkt->mask & VHOST_READ_MASK) {
		struct resp_res *res;

		res = find_resource(qp, pkt->psn);
		if (!res) {
			/* Resource not found. Class D error.  Drop the
			 * request.
			 */
			rc = RESPST_CLEANUP;
			goto out;
		} else {
			/* Ensure this new request is the same as the previous
			 * one or a subset of it.
			 */
			uint64_t iova = reth_va(pkt);
			uint32_t resid = reth_len(pkt);

			if (iova < res->read.va_org ||
			    resid > res->read.length ||
			    (iova + resid) > (res->read.va_org +
					      res->read.length)) {
				rc = RESPST_CLEANUP;
				goto out;
			}

			if (reth_rkey(pkt) != res->read.rkey) {
				rc = RESPST_CLEANUP;
				goto out;
			}

			res->cur_psn = pkt->psn;
			res->state = (pkt->psn == res->first_psn) ?
					rdatm_res_state_new :
					rdatm_res_state_replay;
			res->replay = 1;

			/* Reset the resource, except length. */
			res->read.va_org = iova;
			res->read.va = iova;
			res->read.resid = resid;

			/* Replay the RDMA read reply. */
			qp->resp.res = res;
			rc = RESPST_READ_REPLY;
			goto out;
		}
	} else {
		struct resp_res *res;

		/* Find the operation in our list of responder resources. */
		res = find_resource(qp, pkt->psn);
		if (res) {
			// FIXME: skb_get?
			struct rte_mbuf* clone;
			clone = rte_pktmbuf_clone(res->atomic.mbuf, qp->dev->mbuf_pool);
			/* Resend the result. */
			rc = vhost_rdma_xmit_packet(qp, pkt, clone);
			if (rc) {
				RDMA_LOG_ERR_DP("Failed resending result.");
				rc = RESPST_CLEANUP;
				goto out;
			}
		}

		/* Resource not found. Class D error. Drop the request. */
		rc = RESPST_CLEANUP;
		goto out;
	}
out:
	return rc;
}

/* Process a class A or C. Both are treated the same in this implementation. */
static void
do_class_ac_error(struct vhost_rdma_qp *qp, uint8_t syndrome,
				enum virtio_ib_wc_status status)
{
	qp->resp.aeth_syndrome	= syndrome;
	qp->resp.status		= status;

	/* indicate that we should go through the ERROR state */
	qp->resp.goto_error	= 1;
}

static enum resp_states
do_class_d1e_error(struct vhost_rdma_qp *qp)
{
	/* UC */
	if (qp->srq) {
		/* Class E */
		qp->resp.drop_msg = 1;
		if (qp->resp.wqe) {
			qp->resp.status = VIRTIO_IB_WC_REM_INV_REQ_ERR;
			return RESPST_COMPLETE;
		} else {
			return RESPST_CLEANUP;
		}
	} else {
		/* Class D1. This packet may be the start of a
		 * new message and could be valid. The previous
		 * message is invalid and ignored. reset the
		 * recv wr to its original state
		 */
		if (qp->resp.wqe) {
			qp->resp.wqe->dma.resid = qp->resp.wqe->dma.length;
			qp->resp.wqe->dma.cur_sge = 0;
			qp->resp.wqe->dma.sge_offset = 0;
			qp->resp.opcode = -1;
		}

		if (qp->resp.mr) {
			vhost_rdma_drop_ref(qp->resp.mr, qp->dev, mr);
			qp->resp.mr = NULL;
		}

		return RESPST_CLEANUP;
	}
}

static void
vhost_rdma_drain_req_pkts(struct vhost_rdma_qp *qp, bool notify)
{
	struct rte_mbuf *mbuf;
	struct vhost_rdma_queue *q = &qp->rq.queue;

	if (qp->req_pkts_head != NULL) {
		vhost_rdma_drop_ref(qp, qp->dev, qp);
		rte_pktmbuf_free(qp->req_pkts_head);
		qp->req_pkts_head = NULL;
	}

	while (rte_ring_dequeue(qp->req_pkts, (void**)&mbuf) == 0) {
		vhost_rdma_drop_ref(qp, qp->dev, qp);
		rte_pktmbuf_free(mbuf);
	}

	if (notify)
		return;

	while (!qp->srq && q && queue_head(q))
		advance_consumer(q);
}

int
vhost_rdma_responder(void* arg)
{
	struct vhost_rdma_qp *qp = (struct vhost_rdma_qp *)arg;
	struct vhost_rdma_dev *dev = qp->dev;
	enum resp_states state;
	struct vhost_rdma_pkt_info *pkt = NULL;
	int ret = 0;

	vhost_rdma_add_ref(qp);

	qp->resp.aeth_syndrome = AETH_ACK_UNLIMITED;

	if (!qp->valid) {
		ret = -EINVAL;
		goto done;
	}

	switch (qp->resp.state) {
	case QP_STATE_RESET:
		state = RESPST_RESET;
		break;

	default:
		state = RESPST_GET_REQ;
		break;
	}

	while (1) {
		RDMA_LOG_DEBUG_DP("qp#%d state = %s", qp->qpn,
			 resp_state_name[state]);
		switch (state) {
		case RESPST_GET_REQ:
			state = get_req(qp, &pkt);
			break;
		case RESPST_CHK_PSN:
			state = check_psn(qp, pkt);
			break;
		case RESPST_CHK_OP_SEQ:
			state = check_op_seq(qp, pkt);
			break;
		case RESPST_CHK_OP_VALID:
			state = check_op_valid(qp, pkt);
			break;
		case RESPST_CHK_RESOURCE:
			state = check_resource(qp, pkt);
			break;
		case RESPST_CHK_LENGTH:
			state = check_length(qp, pkt);
			break;
		case RESPST_CHK_RKEY:
			state = check_rkey(qp, pkt);
			break;
		case RESPST_EXECUTE:
			state = execute(qp, pkt);
			break;
		case RESPST_COMPLETE:
			state = do_complete(qp, pkt);
			break;
		case RESPST_READ_REPLY:
			state = read_reply(qp, pkt);
			break;
		case RESPST_ACKNOWLEDGE:
			state = acknowledge(qp, pkt);
			break;
		case RESPST_CLEANUP:
			state = cleanup(qp, pkt);
			break;
		case RESPST_DUPLICATE_REQUEST:
			state = duplicate_request(qp, pkt);
			break;
		case RESPST_ERR_PSN_OUT_OF_SEQ:
			/* RC only - Class B. Drop packet. */
			send_ack(qp, pkt, AETH_NAK_PSN_SEQ_ERROR, qp->resp.psn);
			state = RESPST_CLEANUP;
			break;

		case RESPST_ERR_TOO_MANY_RDMA_ATM_REQ:
		case RESPST_ERR_MISSING_OPCODE_FIRST:
		case RESPST_ERR_MISSING_OPCODE_LAST_C:
		case RESPST_ERR_UNSUPPORTED_OPCODE:
		case RESPST_ERR_MISALIGNED_ATOMIC:
			/* RC Only - Class C. */
			do_class_ac_error(qp, AETH_NAK_INVALID_REQ,
					  VIRTIO_IB_WC_REM_INV_REQ_ERR);
			state = RESPST_COMPLETE;
			break;

		case RESPST_ERR_MISSING_OPCODE_LAST_D1E:
			state = do_class_d1e_error(qp);
			break;
		case RESPST_ERR_RNR:
			if (qp->type == VIRTIO_IB_QPT_RC) {
				vhost_rdma_counter_inc(dev, VHOST_CNT_SND_RNR);
				/* RC - class B */
				send_ack(qp, pkt, AETH_RNR_NAK |
					 (~AETH_TYPE_MASK &
					 qp->attr.min_rnr_timer),
					 pkt->psn);
			} else {
				/* UD/UC - class D */
				qp->resp.drop_msg = 1;
			}
			state = RESPST_CLEANUP;
			break;

		case RESPST_ERR_RKEY_VIOLATION:
			if (qp->type == VIRTIO_IB_QPT_RC) {
				/* Class C */
				do_class_ac_error(qp, AETH_NAK_REM_ACC_ERR,
						  VIRTIO_IB_WC_REM_ACCESS_ERR);
				state = RESPST_COMPLETE;
			} else {
				qp->resp.drop_msg = 1;
				if (qp->srq) {
					/* UC/SRQ Class D */
					qp->resp.status = VIRTIO_IB_WC_REM_ACCESS_ERR;
					state = RESPST_COMPLETE;
				} else {
					/* UC/non-SRQ Class E. */
					state = RESPST_CLEANUP;
				}
			}
			break;

		case RESPST_ERR_INVALIDATE_RKEY:
			/* RC - Class J. */
			qp->resp.goto_error = 1;
			qp->resp.status = VIRTIO_IB_WC_REM_INV_REQ_ERR;
			state = RESPST_COMPLETE;
			break;

		case RESPST_ERR_LENGTH:
			if (qp->type == VIRTIO_IB_QPT_RC) {
				/* Class C */
				do_class_ac_error(qp, AETH_NAK_INVALID_REQ,
						  VIRTIO_IB_WC_REM_INV_REQ_ERR);
				state = RESPST_COMPLETE;
			} else if (qp->srq) {
				/* UC/UD - class E */
				qp->resp.status = VIRTIO_IB_WC_REM_INV_REQ_ERR;
				state = RESPST_COMPLETE;
			} else {
				/* UC/UD - class D */
				qp->resp.drop_msg = 1;
				state = RESPST_CLEANUP;
			}
			break;

		case RESPST_ERR_MALFORMED_WQE:
			/* All, Class A. */
			do_class_ac_error(qp, AETH_NAK_REM_OP_ERR,
					  VIRTIO_IB_WC_LOC_QP_OP_ERR);
			state = RESPST_COMPLETE;
			break;

		case RESPST_ERR_CQ_OVERFLOW:
			/* All - Class G */
			state = RESPST_ERROR;
			break;

		case RESPST_DONE:
			if (qp->resp.goto_error) {
				state = RESPST_ERROR;
				break;
			}

			goto done;

		case RESPST_EXIT:
			if (qp->resp.goto_error) {
				state = RESPST_ERROR;
				break;
			}

			goto exit;

		case RESPST_RESET:
			vhost_rdma_drain_req_pkts(qp, false);
			qp->resp.wqe = NULL;
			goto exit;

		case RESPST_ERROR:
			qp->resp.goto_error = 0;
			RDMA_LOG_ERR_DP("qp#%d moved to error state", qp->qpn);
			vhost_rdma_qp_error(qp);
			goto exit;

		default:
			RDMA_LOG_ERR_DP("Unknown RESPST");
		}
	}

exit:
	ret = -EAGAIN;
done:
	vhost_rdma_drop_ref(qp, qp->dev, qp);
	return ret;
}

