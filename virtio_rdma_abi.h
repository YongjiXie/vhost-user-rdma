/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR Linux-OpenIB) */
/*
 * Copyright (C) 2022 Bytedance Inc. and/or its affiliates. All rights reserved.
 *
 * Author: Xie Yongji <xieyongji@bytedance.com>
 *         Wei Junji <weijunji@bytedance.com>
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __VIRTIO_RDMA_ABI_H__
#define __VIRTIO_RDMA_ABI_H__

#include <linux/types.h>

#define VIRTIO_RDMA_ABI_VERSION 1

struct virtio_rdma_alloc_pd_uresp {
	__u32 pdn;
};

struct virtio_rdma_create_qp_uresp {
	__u64 sq_offset;
	__u64 sq_size;
	__u64 sq_phys_addr;
	__u64 svq_used_off;
	__u32 svq_size;
	int num_sqe;
	int num_svqe;
	int sq_idx;

	__u64 rq_offset;
	__u64 rq_size;
	__u64 rq_phys_addr;
	__u64 rvq_used_off;
	__u32 rvq_size;
	int num_rqe;
	int num_rvqe;
	int rq_idx;

	__u32 notifier_size;
	__u32 qpn;
};

struct virtio_rdma_create_cq_uresp {
	__u64 offset;
	__u64 cq_size;
	__u64 cq_phys_addr;
	__u64 used_off;
	__u32 vq_size;
	int num_cqe;
	int num_cvqe;
};

struct virtio_rdma_create_ah_uresp {
	__u32 ah;
};

enum virtio_ib_wc_opcode {
	VIRTIO_IB_WC_SEND,
	VIRTIO_IB_WC_RDMA_WRITE,
	VIRTIO_IB_WC_RDMA_READ,
	VIRTIO_IB_WC_RECV,
	VIRTIO_IB_WC_RECV_RDMA_WITH_IMM,
};

enum virtio_ib_wc_status {
	/* Operation completed successfully */
	VIRTIO_IB_WC_SUCCESS,
	/* Local Length Error */
	VIRTIO_IB_WC_LOC_LEN_ERR,
	/* Local QP Operation Error */
	VIRTIO_IB_WC_LOC_QP_OP_ERR,
	/* Local Protection Error */
	VIRTIO_IB_WC_LOC_PROT_ERR,
	/* Work Request Flushed Error */
	VIRTIO_IB_WC_WR_FLUSH_ERR,
	/* Bad Response Error */
	VIRTIO_IB_WC_BAD_RESP_ERR,
	/* Local Access Error */
	VIRTIO_IB_WC_LOC_ACCESS_ERR,
	/* Remote Invalid Request Error */
	VIRTIO_IB_WC_REM_INV_REQ_ERR,
	/* Remote Access Error */
	VIRTIO_IB_WC_REM_ACCESS_ERR,
	/* Remote Operation Error */
	VIRTIO_IB_WC_REM_OP_ERR,
	/* Transport Retry Counter Exceeded */
	VIRTIO_IB_WC_RETRY_EXC_ERR,
	/* RNR Retry Counter Exceeded */
	VIRTIO_IB_WC_RNR_RETRY_EXC_ERR,
	/* Remote Aborted Error */
	VIRTIO_IB_WC_REM_ABORT_ERR,
	/* Fatal Error */
	VIRTIO_IB_WC_FATAL_ERR,
	/* Response Timeout Error */
	VIRTIO_IB_WC_RESP_TIMEOUT_ERR,
	/* General Error */
	VIRTIO_IB_WC_GENERAL_ERR
};

struct virtio_rdma_cq_req {
	/* User defined WR ID */
	__le64 wr_id;
	/* Work completion status, enum virtio_ib_wc_status */
	__u8 status;
	/* WR opcode, enum virtio_ib_wc_opcode */
	__u8 opcode;
	/* Padding */
	__le16 padding;
	/* Vendor error */
	__le32 vendor_err;
	/* Number of bytes transferred */
	__le32 byte_len;
	/* Immediate data (in network byte order) to send */
	__le32 imm_data;
	/* Local QP number of completed WR */
	__le32 qp_num;
	/* Source QP number (remote QP number) of completed WR (valid only for UD QPs) */
	__le32 src_qp;
#define VIRTIO_IB_WC_GRH         (1 << 0)
#define VIRTIO_IB_WC_WITH_IMM    (1 << 1)
	/* Work completion flag */
	__le32 wc_flags;
	/* Reserved for future */
	__le32 reserved[3];
};

enum virtio_ib_wr_opcode {
	VIRTIO_IB_WR_RDMA_WRITE,
	VIRTIO_IB_WR_RDMA_WRITE_WITH_IMM,
	VIRTIO_IB_WR_SEND,
	VIRTIO_IB_WR_SEND_WITH_IMM,
	VIRTIO_IB_WR_RDMA_READ,
};

struct virtio_rdma_sge {
	__le64 addr;
	__le32 length;
	__le32 lkey;
};

struct virtio_rdma_sq_req {
	/* User defined WR ID */
	__le64 wr_id;
	/* WR opcode, enum virtio_ib_wr_opcode */
	__u8 opcode;
#define VIRTIO_IB_SEND_FENCE        (1 << 0)
#define VIRTIO_IB_SEND_SIGNALED     (1 << 1)
#define VIRTIO_IB_SEND_SOLICITED    (1 << 2)
#define VIRTIO_IB_SEND_INLINE       (1 << 3)
	/* Flags of the WR properties */
	__u8 send_flags;
	/* Padding */
	__le16 padding;
	/* Immediate data (in network byte order) to send */
	__le32 imm_data;
	union {
		struct {
			/* Start address of remote memory buffer */
			__le64 remote_addr;
			/* Key of the remote MR */
			__le32 rkey;
		} rdma;
		struct {
			/* Index of the destination QP */
			__le32 remote_qpn;
			/* Q_Key of the destination QP */
			__le32 remote_qkey;
			/* Address Handle */
			__le32 ah;
		} ud;
		/* Reserved for future */
		__le64 reserved[4];
	};
	/* Inline data */
	__u8 inline_data[512];
	union {
		/* Length of sg_list */
		__le32 num_sge;
		/* Length of inline data */
		__le16 inline_len;
	};
	/* Reserved for future */
	__le32 reserved2[3];
	/* Scatter/gather list */
	struct virtio_rdma_sge sg_list[];
};

struct virtio_rdma_rq_req {
	/* User defined WR ID */
	__le64 wr_id;
	/* Length of sg_list */
	__le32 num_sge;
	/* Reserved for future */
	__le32 reserved[3];
	/* Scatter/gather list */
	struct virtio_rdma_sge sg_list[];
};

#endif
