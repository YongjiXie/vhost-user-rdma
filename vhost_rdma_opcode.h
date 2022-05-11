/*
 * Vhost-user RDMA device demo: rocev2 pkt opcode
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

#ifndef __VHOST_RDMA_OPCODE_H__
#define __VHOST_RDMA_OPCODE_H__

#ifndef BIT
	#define BIT(x)	(1 << (x))
#endif

enum vhost_rdma_wr_mask {
	WR_INLINE_MASK			= BIT(0),
	WR_ATOMIC_MASK			= BIT(1),
	WR_SEND_MASK			= BIT(2),
	WR_READ_MASK			= BIT(3),
	WR_WRITE_MASK			= BIT(4),
	WR_LOCAL_OP_MASK		= BIT(5),

	WR_READ_OR_WRITE_MASK		= WR_READ_MASK | WR_WRITE_MASK,
	WR_READ_WRITE_OR_SEND_MASK	= WR_READ_OR_WRITE_MASK | WR_SEND_MASK,
	WR_WRITE_OR_SEND_MASK		= WR_WRITE_MASK | WR_SEND_MASK,
	WR_ATOMIC_OR_READ_MASK		= WR_ATOMIC_MASK | WR_READ_MASK,
};

#define WR_MAX_QPT		(8)

struct vhost_rdma_wr_opcode_info {
	char			*name;
	enum vhost_rdma_wr_mask	mask[WR_MAX_QPT];
};

extern struct vhost_rdma_wr_opcode_info vhost_rdma_wr_opcode_info[];

enum vhost_rdma_hdr_type {
	VHOST_LRH,
	VHOST_GRH,
	VHOST_BTH,
	VHOST_RETH,
	VHOST_AETH,
	VHOST_ATMETH,
	VHOST_ATMACK,
	VHOST_IETH,
	VHOST_RDETH,
	VHOST_DETH,
	VHOST_IMMDT,
	VHOST_PAYLOAD,
	NUM_HDR_TYPES
};

enum vhost_rdma_hdr_mask {
	VHOST_LRH_MASK			= BIT(VHOST_LRH),
	VHOST_GRH_MASK			= BIT(VHOST_GRH),
	VHOST_BTH_MASK			= BIT(VHOST_BTH),
	VHOST_IMMDT_MASK		= BIT(VHOST_IMMDT),
	VHOST_RETH_MASK			= BIT(VHOST_RETH),
	VHOST_AETH_MASK			= BIT(VHOST_AETH),
	VHOST_ATMETH_MASK		= BIT(VHOST_ATMETH),
	VHOST_ATMACK_MASK		= BIT(VHOST_ATMACK),
	VHOST_IETH_MASK			= BIT(VHOST_IETH),
	VHOST_RDETH_MASK		= BIT(VHOST_RDETH),
	VHOST_DETH_MASK			= BIT(VHOST_DETH),
	VHOST_PAYLOAD_MASK		= BIT(VHOST_PAYLOAD),

	VHOST_REQ_MASK			= BIT(NUM_HDR_TYPES + 0),
	VHOST_ACK_MASK			= BIT(NUM_HDR_TYPES + 1),
	VHOST_SEND_MASK			= BIT(NUM_HDR_TYPES + 2),
	VHOST_WRITE_MASK		= BIT(NUM_HDR_TYPES + 3),
	VHOST_READ_MASK			= BIT(NUM_HDR_TYPES + 4),
	VHOST_ATOMIC_MASK		= BIT(NUM_HDR_TYPES + 5),

	VHOST_RWR_MASK			= BIT(NUM_HDR_TYPES + 6),
	VHOST_COMP_MASK			= BIT(NUM_HDR_TYPES + 7),

	VHOST_START_MASK		= BIT(NUM_HDR_TYPES + 8),
	VHOST_MIDDLE_MASK		= BIT(NUM_HDR_TYPES + 9),
	VHOST_END_MASK			= BIT(NUM_HDR_TYPES + 10),

	VHOST_LOOPBACK_MASK		= BIT(NUM_HDR_TYPES + 12),

	VHOST_READ_OR_ATOMIC		= (VHOST_READ_MASK | VHOST_ATOMIC_MASK),
	VHOST_WRITE_OR_SEND		= (VHOST_WRITE_MASK | VHOST_SEND_MASK),
};

#define OPCODE_NONE		(-1)
#define VHOST_NUM_OPCODE		256

struct vhost_rdma_opcode_info {
	char			*name;
	enum vhost_rdma_hdr_mask	mask;
	int			length;
	int			offset[NUM_HDR_TYPES];
};

extern struct vhost_rdma_opcode_info vhost_rdma_opcode[VHOST_NUM_OPCODE];

#define IB_OPCODE(transport, op) \
	IB_OPCODE_ ## transport ## _ ## op = \
		IB_OPCODE_ ## transport + IB_OPCODE_ ## op

enum {
	/* transport types -- just used to define real constants */
	IB_OPCODE_RC                                = 0x00,
	IB_OPCODE_UC                                = 0x20,
	IB_OPCODE_RD                                = 0x40,
	IB_OPCODE_UD                                = 0x60,
	/* per IBTA 1.3 vol 1 Table 38, A10.3.2 */
	IB_OPCODE_CNP                               = 0x80,
	/* Manufacturer specific */
	IB_OPCODE_MSP                               = 0xe0,

	/* operations -- just used to define real constants */
	IB_OPCODE_SEND_FIRST                        = 0x00,
	IB_OPCODE_SEND_MIDDLE                       = 0x01,
	IB_OPCODE_SEND_LAST                         = 0x02,
	IB_OPCODE_SEND_LAST_WITH_IMMEDIATE          = 0x03,
	IB_OPCODE_SEND_ONLY                         = 0x04,
	IB_OPCODE_SEND_ONLY_WITH_IMMEDIATE          = 0x05,
	IB_OPCODE_RDMA_WRITE_FIRST                  = 0x06,
	IB_OPCODE_RDMA_WRITE_MIDDLE                 = 0x07,
	IB_OPCODE_RDMA_WRITE_LAST                   = 0x08,
	IB_OPCODE_RDMA_WRITE_LAST_WITH_IMMEDIATE    = 0x09,
	IB_OPCODE_RDMA_WRITE_ONLY                   = 0x0a,
	IB_OPCODE_RDMA_WRITE_ONLY_WITH_IMMEDIATE    = 0x0b,
	IB_OPCODE_RDMA_READ_REQUEST                 = 0x0c,
	IB_OPCODE_RDMA_READ_RESPONSE_FIRST          = 0x0d,
	IB_OPCODE_RDMA_READ_RESPONSE_MIDDLE         = 0x0e,
	IB_OPCODE_RDMA_READ_RESPONSE_LAST           = 0x0f,
	IB_OPCODE_RDMA_READ_RESPONSE_ONLY           = 0x10,
	IB_OPCODE_ACKNOWLEDGE                       = 0x11,
	IB_OPCODE_ATOMIC_ACKNOWLEDGE                = 0x12,
	IB_OPCODE_COMPARE_SWAP                      = 0x13,
	IB_OPCODE_FETCH_ADD                         = 0x14,
	/* opcode 0x15 is reserved */
	IB_OPCODE_SEND_LAST_WITH_INVALIDATE         = 0x16,
	IB_OPCODE_SEND_ONLY_WITH_INVALIDATE         = 0x17,

	/* real constants follow -- see comment about above IB_OPCODE()
	   macro for more details */

	/* RC */
	IB_OPCODE(RC, SEND_FIRST),
	IB_OPCODE(RC, SEND_MIDDLE),
	IB_OPCODE(RC, SEND_LAST),
	IB_OPCODE(RC, SEND_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RC, SEND_ONLY),
	IB_OPCODE(RC, SEND_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RC, RDMA_WRITE_FIRST),
	IB_OPCODE(RC, RDMA_WRITE_MIDDLE),
	IB_OPCODE(RC, RDMA_WRITE_LAST),
	IB_OPCODE(RC, RDMA_WRITE_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RC, RDMA_WRITE_ONLY),
	IB_OPCODE(RC, RDMA_WRITE_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RC, RDMA_READ_REQUEST),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_FIRST),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_MIDDLE),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_LAST),
	IB_OPCODE(RC, RDMA_READ_RESPONSE_ONLY),
	IB_OPCODE(RC, ACKNOWLEDGE),
	IB_OPCODE(RC, ATOMIC_ACKNOWLEDGE),
	IB_OPCODE(RC, COMPARE_SWAP),
	IB_OPCODE(RC, FETCH_ADD),
	IB_OPCODE(RC, SEND_LAST_WITH_INVALIDATE),
	IB_OPCODE(RC, SEND_ONLY_WITH_INVALIDATE),

	/* UC */
	IB_OPCODE(UC, SEND_FIRST),
	IB_OPCODE(UC, SEND_MIDDLE),
	IB_OPCODE(UC, SEND_LAST),
	IB_OPCODE(UC, SEND_LAST_WITH_IMMEDIATE),
	IB_OPCODE(UC, SEND_ONLY),
	IB_OPCODE(UC, SEND_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(UC, RDMA_WRITE_FIRST),
	IB_OPCODE(UC, RDMA_WRITE_MIDDLE),
	IB_OPCODE(UC, RDMA_WRITE_LAST),
	IB_OPCODE(UC, RDMA_WRITE_LAST_WITH_IMMEDIATE),
	IB_OPCODE(UC, RDMA_WRITE_ONLY),
	IB_OPCODE(UC, RDMA_WRITE_ONLY_WITH_IMMEDIATE),

	/* RD */
	IB_OPCODE(RD, SEND_FIRST),
	IB_OPCODE(RD, SEND_MIDDLE),
	IB_OPCODE(RD, SEND_LAST),
	IB_OPCODE(RD, SEND_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RD, SEND_ONLY),
	IB_OPCODE(RD, SEND_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RD, RDMA_WRITE_FIRST),
	IB_OPCODE(RD, RDMA_WRITE_MIDDLE),
	IB_OPCODE(RD, RDMA_WRITE_LAST),
	IB_OPCODE(RD, RDMA_WRITE_LAST_WITH_IMMEDIATE),
	IB_OPCODE(RD, RDMA_WRITE_ONLY),
	IB_OPCODE(RD, RDMA_WRITE_ONLY_WITH_IMMEDIATE),
	IB_OPCODE(RD, RDMA_READ_REQUEST),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_FIRST),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_MIDDLE),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_LAST),
	IB_OPCODE(RD, RDMA_READ_RESPONSE_ONLY),
	IB_OPCODE(RD, ACKNOWLEDGE),
	IB_OPCODE(RD, ATOMIC_ACKNOWLEDGE),
	IB_OPCODE(RD, COMPARE_SWAP),
	IB_OPCODE(RD, FETCH_ADD),

	/* UD */
	IB_OPCODE(UD, SEND_ONLY),
	IB_OPCODE(UD, SEND_ONLY_WITH_IMMEDIATE)
};

#endif
