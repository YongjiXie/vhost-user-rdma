/*
 * Vhost-user RDMA device demo: rocev2 header
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

#ifndef __VHOST_RDMA_HDR_H__
#define __VHOST_RDMA_HDR_H__

#include <stdint.h>

#include <rte_byteorder.h>

#include "vhost_rdma_opcode.h"

/* extracted information about a packet carried in an sk_buff struct fits in
 * the skbuff cb array. Must be at most 48 bytes. stored in control block of
 * sk_buff for received packets.
 */
struct vhost_rdma_pkt_info {
	struct vhost_rdma_dev		*dev;		/* device that owns packet */
	struct vhost_rdma_qp		*qp;		/* qp that owns packet */
	struct vhost_rdma_send_wqe	*wqe;		/* send wqe */
	uint8_t				*hdr;		/* points to bth */
	uint32_t			mask;		/* useful info about pkt */
	uint32_t			psn;		/* bth psn of packet */
	uint16_t			pkey_index;	/* partition of pkt */
	uint16_t			paylen;		/* length of bth - icrc */
	uint8_t				port_num;	/* port pkt received on */
	uint8_t				opcode;		/* bth opcode of packet */
};

/* Macros should be used only for received skb */
// static inline struct vhost_rdma_pkt_info *SKB_TO_PKT(struct sk_buff *skb)
// {
// 	BUILD_BUG_ON(sizeof(struct vhost_rdma_pkt_info) > sizeof(skb->cb));
// 	return (void *)skb->cb;
// }

// static inline struct sk_buff *PKT_TO_SKB(struct vhost_rdma_pkt_info *pkt)
// {
// 	return container_of((void *)pkt, struct sk_buff, cb);
// }

/*
 * IBA header types and methods
 *
 * Some of these are for reference and completeness only since
 * rxe does not currently support RD transport
 * most of this could be moved into IB core. ib_pack.h has
 * part of this but is incomplete
 *
 * Header specific routines to insert/extract values to/from headers
 * the routines that are named __hhh_(set_)fff() take a pointer to a
 * hhh header and get(set) the fff field. The routines named
 * hhh_(set_)fff take a packet info struct and find the
 * header and field based on the opcode in the packet.
 * Conversion to/from network byte order from cpu order is also done.
 */

#define VHOST_ICRC_SIZE		(4)
#define VHOST_MAX_HDR_LENGTH	(80)

/******************************************************************************
 * Base Transport Header
 ******************************************************************************/
struct vhost_bth {
	uint8_t			opcode;
	uint8_t			flags;
	rte_be16_t		pkey;
	rte_be32_t		qpn;
	rte_be32_t		apsn;
};

#define BTH_TVER		(0)
#define BTH_DEF_PKEY		(0xffff)

#define BTH_SE_MASK		(0x80)
#define BTH_MIG_MASK		(0x40)
#define BTH_PAD_MASK		(0x30)
#define BTH_TVER_MASK		(0x0f)
#define BTH_FECN_MASK		(0x80000000)
#define BTH_BECN_MASK		(0x40000000)
#define BTH_RESV6A_MASK		(0x3f000000)
#define BTH_QPN_MASK		(0x00ffffff)
#define BTH_ACK_MASK		(0x80000000)
#define BTH_RESV7_MASK		(0x7f000000)
#define BTH_PSN_MASK		(0x00ffffff)

static inline uint8_t __bth_opcode(void *arg)
{
	struct vhost_bth *bth = arg;

	return bth->opcode;
}

static inline void __bth_set_opcode(void *arg, uint8_t opcode)
{
	struct vhost_bth *bth = arg;

	bth->opcode = opcode;
}

static inline uint8_t __bth_se(void *arg)
{
	struct vhost_bth *bth = arg;

	return 0 != (BTH_SE_MASK & bth->flags);
}

static inline void __bth_set_se(void *arg, int se)
{
	struct vhost_bth *bth = arg;

	if (se)
		bth->flags |= BTH_SE_MASK;
	else
		bth->flags &= ~BTH_SE_MASK;
}

static inline uint8_t __bth_mig(void *arg)
{
	struct vhost_bth *bth = arg;

	return 0 != (BTH_MIG_MASK & bth->flags);
}

static inline void __bth_set_mig(void *arg, uint8_t mig)
{
	struct vhost_bth *bth = arg;

	if (mig)
		bth->flags |= BTH_MIG_MASK;
	else
		bth->flags &= ~BTH_MIG_MASK;
}

static inline uint8_t __bth_pad(void *arg)
{
	struct vhost_bth *bth = arg;

	return (BTH_PAD_MASK & bth->flags) >> 4;
}

static inline void __bth_set_pad(void *arg, uint8_t pad)
{
	struct vhost_bth *bth = arg;

	bth->flags = (BTH_PAD_MASK & (pad << 4)) |
			(~BTH_PAD_MASK & bth->flags);
}

static inline uint8_t __bth_tver(void *arg)
{
	struct vhost_bth *bth = arg;

	return BTH_TVER_MASK & bth->flags;
}

static inline void __bth_set_tver(void *arg, uint8_t tver)
{
	struct vhost_bth *bth = arg;

	bth->flags = (BTH_TVER_MASK & tver) |
			(~BTH_TVER_MASK & bth->flags);
}

static inline uint16_t __bth_pkey(void *arg)
{
	struct vhost_bth *bth = arg;

	return rte_be_to_cpu_16(bth->pkey);
}

static inline void __bth_set_pkey(void *arg, uint16_t pkey)
{
	struct vhost_bth *bth = arg;

	bth->pkey = rte_cpu_to_be_16(pkey);
}

static inline uint32_t __bth_qpn(void *arg)
{
	struct vhost_bth *bth = arg;

	return BTH_QPN_MASK & rte_be_to_cpu_32(bth->qpn);
}

static inline void __bth_set_qpn(void *arg, uint32_t qpn)
{
	struct vhost_bth *bth = arg;
	uint32_t resvqpn = rte_be_to_cpu_32(bth->qpn);

	bth->qpn = rte_cpu_to_be_32((BTH_QPN_MASK & qpn) |
			       (~BTH_QPN_MASK & resvqpn));
}

static inline int __bth_fecn(void *arg)
{
	struct vhost_bth *bth = arg;

	return 0 != (rte_cpu_to_be_32(BTH_FECN_MASK) & bth->qpn);
}

static inline void __bth_set_fecn(void *arg, int fecn)
{
	struct vhost_bth *bth = arg;

	if (fecn)
		bth->qpn |= rte_cpu_to_be_32(BTH_FECN_MASK);
	else
		bth->qpn &= ~rte_cpu_to_be_32(BTH_FECN_MASK);
}

static inline int __bth_becn(void *arg)
{
	struct vhost_bth *bth = arg;

	return 0 != (rte_cpu_to_be_32(BTH_BECN_MASK) & bth->qpn);
}

static inline void __bth_set_becn(void *arg, int becn)
{
	struct vhost_bth *bth = arg;

	if (becn)
		bth->qpn |= rte_cpu_to_be_32(BTH_BECN_MASK);
	else
		bth->qpn &= ~rte_cpu_to_be_32(BTH_BECN_MASK);
}

static inline uint8_t __bth_resv6a(void *arg)
{
	struct vhost_bth *bth = arg;

	return (BTH_RESV6A_MASK & rte_be_to_cpu_32(bth->qpn)) >> 24;
}

static inline void __bth_set_resv6a(void *arg)
{
	struct vhost_bth *bth = arg;

	bth->qpn = rte_cpu_to_be_32(~BTH_RESV6A_MASK);
}

static inline int __bth_ack(void *arg)
{
	struct vhost_bth *bth = arg;

	return 0 != (rte_cpu_to_be_32(BTH_ACK_MASK) & bth->apsn);
}

static inline void __bth_set_ack(void *arg, int ack)
{
	struct vhost_bth *bth = arg;

	if (ack)
		bth->apsn |= rte_cpu_to_be_32(BTH_ACK_MASK);
	else
		bth->apsn &= ~rte_cpu_to_be_32(BTH_ACK_MASK);
}

static inline void __bth_set_resv7(void *arg)
{
	struct vhost_bth *bth = arg;

	bth->apsn &= ~rte_cpu_to_be_32(BTH_RESV7_MASK);
}

static inline uint32_t __bth_psn(void *arg)
{
	struct vhost_bth *bth = arg;

	return BTH_PSN_MASK & rte_be_to_cpu_32(bth->apsn);
}

static inline void __bth_set_psn(void *arg, uint32_t psn)
{
	struct vhost_bth *bth = arg;
	uint32_t apsn = rte_be_to_cpu_32(bth->apsn);

	bth->apsn = rte_cpu_to_be_32((BTH_PSN_MASK & psn) |
			(~BTH_PSN_MASK & apsn));
}

static inline uint8_t bth_opcode(struct vhost_rdma_pkt_info *pkt)
{
	return __bth_opcode(pkt->hdr);
}

static inline void bth_set_opcode(struct vhost_rdma_pkt_info *pkt, uint8_t opcode)
{
	__bth_set_opcode(pkt->hdr, opcode);
}

static inline uint8_t bth_se(struct vhost_rdma_pkt_info *pkt)
{
	return __bth_se(pkt->hdr);
}

static inline void bth_set_se(struct vhost_rdma_pkt_info *pkt, int se)
{
	__bth_set_se(pkt->hdr, se);
}

static inline uint8_t bth_mig(struct vhost_rdma_pkt_info *pkt)
{
	return __bth_mig(pkt->hdr);
}

static inline void bth_set_mig(struct vhost_rdma_pkt_info *pkt, uint8_t mig)
{
	__bth_set_mig(pkt->hdr, mig);
}

static inline uint8_t bth_pad(struct vhost_rdma_pkt_info *pkt)
{
	return __bth_pad(pkt->hdr);
}

static inline void bth_set_pad(struct vhost_rdma_pkt_info *pkt, uint8_t pad)
{
	__bth_set_pad(pkt->hdr, pad);
}

static inline uint8_t bth_tver(struct vhost_rdma_pkt_info *pkt)
{
	return __bth_tver(pkt->hdr);
}

static inline void bth_set_tver(struct vhost_rdma_pkt_info *pkt, uint8_t tver)
{
	__bth_set_tver(pkt->hdr, tver);
}

static inline uint16_t bth_pkey(struct vhost_rdma_pkt_info *pkt)
{
	return __bth_pkey(pkt->hdr);
}

static inline void bth_set_pkey(struct vhost_rdma_pkt_info *pkt, uint16_t pkey)
{
	__bth_set_pkey(pkt->hdr, pkey);
}

static inline uint32_t bth_qpn(struct vhost_rdma_pkt_info *pkt)
{
	return __bth_qpn(pkt->hdr);
}

static inline void bth_set_qpn(struct vhost_rdma_pkt_info *pkt, uint32_t qpn)
{
	__bth_set_qpn(pkt->hdr, qpn);
}

static inline int bth_fecn(struct vhost_rdma_pkt_info *pkt)
{
	return __bth_fecn(pkt->hdr);
}

static inline void bth_set_fecn(struct vhost_rdma_pkt_info *pkt, int fecn)
{
	__bth_set_fecn(pkt->hdr, fecn);
}

static inline int bth_becn(struct vhost_rdma_pkt_info *pkt)
{
	return __bth_becn(pkt->hdr);
}

static inline void bth_set_becn(struct vhost_rdma_pkt_info *pkt, int becn)
{
	__bth_set_becn(pkt->hdr, becn);
}

static inline uint8_t bth_resv6a(struct vhost_rdma_pkt_info *pkt)
{
	return __bth_resv6a(pkt->hdr);
}

static inline void bth_set_resv6a(struct vhost_rdma_pkt_info *pkt)
{
	__bth_set_resv6a(pkt->hdr);
}

static inline int bth_ack(struct vhost_rdma_pkt_info *pkt)
{
	return __bth_ack(pkt->hdr);
}

static inline void bth_set_ack(struct vhost_rdma_pkt_info *pkt, int ack)
{
	__bth_set_ack(pkt->hdr, ack);
}

static inline void bth_set_resv7(struct vhost_rdma_pkt_info *pkt)
{
	__bth_set_resv7(pkt->hdr);
}

static inline uint32_t bth_psn(struct vhost_rdma_pkt_info *pkt)
{
	return __bth_psn(pkt->hdr);
}

static inline void bth_set_psn(struct vhost_rdma_pkt_info *pkt, uint32_t psn)
{
	__bth_set_psn(pkt->hdr, psn);
}

static inline void bth_init(struct vhost_rdma_pkt_info *pkt, uint8_t opcode, int se,
			    int mig, int pad, uint16_t pkey, uint32_t qpn, int ack_req,
			    uint32_t psn)
{
	struct vhost_bth *bth = (struct vhost_bth *)(pkt->hdr);

	bth->opcode = opcode;
	bth->flags = (pad << 4) & BTH_PAD_MASK;
	if (se)
		bth->flags |= BTH_SE_MASK;
	if (mig)
		bth->flags |= BTH_MIG_MASK;
	bth->pkey = rte_cpu_to_be_16(pkey);
	bth->qpn = rte_cpu_to_be_32(qpn & BTH_QPN_MASK);
	psn &= BTH_PSN_MASK;
	if (ack_req)
		psn |= BTH_ACK_MASK;
	bth->apsn = rte_cpu_to_be_32(psn);
}

/******************************************************************************
 * Reliable Datagram Extended Transport Header
 ******************************************************************************/
struct vhost_rdeth {
	rte_be32_t			een;
};

#define RDETH_EEN_MASK		(0x00ffffff)

static inline uint8_t __rdeth_een(void *arg)
{
	struct vhost_rdeth *rdeth = arg;

	return RDETH_EEN_MASK & rte_be_to_cpu_32(rdeth->een);
}

static inline void __rdeth_set_een(void *arg, uint32_t een)
{
	struct vhost_rdeth *rdeth = arg;

	rdeth->een = rte_cpu_to_be_32(RDETH_EEN_MASK & een);
}

static inline uint8_t rdeth_een(struct vhost_rdma_pkt_info *pkt)
{
	return __rdeth_een(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_RDETH]);
}

static inline void rdeth_set_een(struct vhost_rdma_pkt_info *pkt, uint32_t een)
{
	__rdeth_set_een(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_RDETH], een);
}

/******************************************************************************
 * Datagram Extended Transport Header
 ******************************************************************************/
struct vhost_deth {
	rte_be32_t			qkey;
	rte_be32_t			sqp;
};

#define GSI_QKEY		(0x80010000)
#define DETH_SQP_MASK		(0x00ffffff)

static inline uint32_t __deth_qkey(void *arg)
{
	struct vhost_deth *deth = arg;

	return rte_be_to_cpu_32(deth->qkey);
}

static inline void __deth_set_qkey(void *arg, uint32_t qkey)
{
	struct vhost_deth *deth = arg;

	deth->qkey = rte_cpu_to_be_32(qkey);
}

static inline uint32_t __deth_sqp(void *arg)
{
	struct vhost_deth *deth = arg;

	return DETH_SQP_MASK & rte_be_to_cpu_32(deth->sqp);
}

static inline void __deth_set_sqp(void *arg, uint32_t sqp)
{
	struct vhost_deth *deth = arg;

	deth->sqp = rte_cpu_to_be_32(DETH_SQP_MASK & sqp);
}

static inline uint32_t deth_qkey(struct vhost_rdma_pkt_info *pkt)
{
	return __deth_qkey(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_DETH]);
}

static inline void deth_set_qkey(struct vhost_rdma_pkt_info *pkt, uint32_t qkey)
{
	__deth_set_qkey(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_DETH], qkey);
}

static inline uint32_t deth_sqp(struct vhost_rdma_pkt_info *pkt)
{
	return __deth_sqp(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_DETH]);
}

static inline void deth_set_sqp(struct vhost_rdma_pkt_info *pkt, uint32_t sqp)
{
	__deth_set_sqp(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_DETH], sqp);
}

/******************************************************************************
 * RDMA Extended Transport Header
 ******************************************************************************/
struct vhost_reth {
	rte_be64_t			va;
	rte_be32_t			rkey;
	rte_be32_t			len;
};

static inline uint64_t __reth_va(void *arg)
{
	struct vhost_reth *reth = arg;

	return rte_be_to_cpu_64(reth->va);
}

static inline void __reth_set_va(void *arg, uint64_t va)
{
	struct vhost_reth *reth = arg;

	reth->va = rte_cpu_to_be_64(va);
}

static inline uint32_t __reth_rkey(void *arg)
{
	struct vhost_reth *reth = arg;

	return rte_be_to_cpu_32(reth->rkey);
}

static inline void __reth_set_rkey(void *arg, uint32_t rkey)
{
	struct vhost_reth *reth = arg;

	reth->rkey = rte_cpu_to_be_32(rkey);
}

static inline uint32_t __reth_len(void *arg)
{
	struct vhost_reth *reth = arg;

	return rte_be_to_cpu_32(reth->len);
}

static inline void __reth_set_len(void *arg, uint32_t len)
{
	struct vhost_reth *reth = arg;

	reth->len = rte_cpu_to_be_32(len);
}

static inline uint64_t reth_va(struct vhost_rdma_pkt_info *pkt)
{
	return __reth_va(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_RETH]);
}

static inline void reth_set_va(struct vhost_rdma_pkt_info *pkt, uint64_t va)
{
	__reth_set_va(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_RETH], va);
}

static inline uint32_t reth_rkey(struct vhost_rdma_pkt_info *pkt)
{
	return __reth_rkey(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_RETH]);
}

static inline void reth_set_rkey(struct vhost_rdma_pkt_info *pkt, uint32_t rkey)
{
	__reth_set_rkey(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_RETH], rkey);
}

static inline uint32_t reth_len(struct vhost_rdma_pkt_info *pkt)
{
	return __reth_len(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_RETH]);
}

static inline void reth_set_len(struct vhost_rdma_pkt_info *pkt, uint32_t len)
{
	__reth_set_len(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_RETH], len);
}

/******************************************************************************
 * Atomic Extended Transport Header
 ******************************************************************************/
struct vhost_atmeth {
	rte_be64_t			va;
	rte_be32_t			rkey;
	rte_be64_t			swap_add;
	rte_be64_t			comp;
} __rte_packed;

static inline uint64_t __atmeth_va(void *arg)
{
	struct vhost_atmeth *atmeth = arg;

	return rte_be_to_cpu_64(atmeth->va);
}

static inline void __atmeth_set_va(void *arg, uint64_t va)
{
	struct vhost_atmeth *atmeth = arg;

	atmeth->va = rte_cpu_to_be_64(va);
}

static inline uint32_t __atmeth_rkey(void *arg)
{
	struct vhost_atmeth *atmeth = arg;

	return rte_be_to_cpu_32(atmeth->rkey);
}

static inline void __atmeth_set_rkey(void *arg, uint32_t rkey)
{
	struct vhost_atmeth *atmeth = arg;

	atmeth->rkey = rte_cpu_to_be_32(rkey);
}

static inline uint64_t __atmeth_swap_add(void *arg)
{
	struct vhost_atmeth *atmeth = arg;

	return rte_be_to_cpu_64(atmeth->swap_add);
}

static inline void __atmeth_set_swap_add(void *arg, uint64_t swap_add)
{
	struct vhost_atmeth *atmeth = arg;

	atmeth->swap_add = rte_cpu_to_be_64(swap_add);
}

static inline uint64_t __atmeth_comp(void *arg)
{
	struct vhost_atmeth *atmeth = arg;

	return rte_be_to_cpu_64(atmeth->comp);
}

static inline void __atmeth_set_comp(void *arg, uint64_t comp)
{
	struct vhost_atmeth *atmeth = arg;

	atmeth->comp = rte_cpu_to_be_64(comp);
}

static inline uint64_t atmeth_va(struct vhost_rdma_pkt_info *pkt)
{
	return __atmeth_va(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_ATMETH]);
}

static inline void atmeth_set_va(struct vhost_rdma_pkt_info *pkt, uint64_t va)
{
	__atmeth_set_va(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_ATMETH], va);
}

static inline uint32_t atmeth_rkey(struct vhost_rdma_pkt_info *pkt)
{
	return __atmeth_rkey(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_ATMETH]);
}

static inline void atmeth_set_rkey(struct vhost_rdma_pkt_info *pkt, uint32_t rkey)
{
	__atmeth_set_rkey(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_ATMETH], rkey);
}

static inline uint64_t atmeth_swap_add(struct vhost_rdma_pkt_info *pkt)
{
	return __atmeth_swap_add(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_ATMETH]);
}

static inline void atmeth_set_swap_add(struct vhost_rdma_pkt_info *pkt, uint64_t swap_add)
{
	__atmeth_set_swap_add(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_ATMETH], swap_add);
}

static inline uint64_t atmeth_comp(struct vhost_rdma_pkt_info *pkt)
{
	return __atmeth_comp(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_ATMETH]);
}

static inline void atmeth_set_comp(struct vhost_rdma_pkt_info *pkt, uint64_t comp)
{
	__atmeth_set_comp(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_ATMETH], comp);
}

/******************************************************************************
 * Ack Extended Transport Header
 ******************************************************************************/
struct vhost_aeth {
	rte_be32_t			smsn;
};

#define AETH_SYN_MASK		(0xff000000)
#define AETH_MSN_MASK		(0x00ffffff)

enum aeth_syndrome {
	AETH_TYPE_MASK		= 0xe0,
	AETH_ACK		= 0x00,
	AETH_RNR_NAK		= 0x20,
	AETH_RSVD		= 0x40,
	AETH_NAK		= 0x60,
	AETH_ACK_UNLIMITED	= 0x1f,
	AETH_NAK_PSN_SEQ_ERROR	= 0x60,
	AETH_NAK_INVALID_REQ	= 0x61,
	AETH_NAK_REM_ACC_ERR	= 0x62,
	AETH_NAK_REM_OP_ERR	= 0x63,
	AETH_NAK_INV_RD_REQ	= 0x64,
};

static inline uint8_t __aeth_syn(void *arg)
{
	struct vhost_aeth *aeth = arg;

	return (AETH_SYN_MASK & rte_be_to_cpu_32(aeth->smsn)) >> 24;
}

static inline void __aeth_set_syn(void *arg, uint8_t syn)
{
	struct vhost_aeth *aeth = arg;
	uint32_t smsn = rte_be_to_cpu_32(aeth->smsn);

	aeth->smsn = rte_cpu_to_be_32((AETH_SYN_MASK & (syn << 24)) |
			 (~AETH_SYN_MASK & smsn));
}

static inline uint32_t __aeth_msn(void *arg)
{
	struct vhost_aeth *aeth = arg;

	return AETH_MSN_MASK & rte_be_to_cpu_32(aeth->smsn);
}

static inline void __aeth_set_msn(void *arg, uint32_t msn)
{
	struct vhost_aeth *aeth = arg;
	uint32_t smsn = rte_be_to_cpu_32(aeth->smsn);

	aeth->smsn = rte_cpu_to_be_32((AETH_MSN_MASK & msn) |
			 (~AETH_MSN_MASK & smsn));
}

static inline uint8_t aeth_syn(struct vhost_rdma_pkt_info *pkt)
{
	return __aeth_syn(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_AETH]);
}

static inline void aeth_set_syn(struct vhost_rdma_pkt_info *pkt, uint8_t syn)
{
	__aeth_set_syn(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_AETH], syn);
}

static inline uint32_t aeth_msn(struct vhost_rdma_pkt_info *pkt)
{
	return __aeth_msn(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_AETH]);
}

static inline void aeth_set_msn(struct vhost_rdma_pkt_info *pkt, uint32_t msn)
{
	__aeth_set_msn(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_AETH], msn);
}

/******************************************************************************
 * Atomic Ack Extended Transport Header
 ******************************************************************************/
struct vhost_atmack {
	rte_be64_t			orig;
};

static inline uint64_t __atmack_orig(void *arg)
{
	struct vhost_atmack *atmack = arg;

	return rte_be_to_cpu_64(atmack->orig);
}

static inline void __atmack_set_orig(void *arg, uint64_t orig)
{
	struct vhost_atmack *atmack = arg;

	atmack->orig = rte_cpu_to_be_64(orig);
}

static inline uint64_t atmack_orig(struct vhost_rdma_pkt_info *pkt)
{
	return __atmack_orig(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_ATMACK]);
}

static inline void atmack_set_orig(struct vhost_rdma_pkt_info *pkt, uint64_t orig)
{
	__atmack_set_orig(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_ATMACK], orig);
}

/******************************************************************************
 * Immediate Extended Transport Header
 ******************************************************************************/
struct vhost_immdt {
	rte_be32_t			imm;
};

static inline rte_be32_t __immdt_imm(void *arg)
{
	struct vhost_immdt *immdt = arg;

	return immdt->imm;
}

static inline void __immdt_set_imm(void *arg, rte_be32_t imm)
{
	struct vhost_immdt *immdt = arg;

	immdt->imm = imm;
}

static inline rte_be32_t immdt_imm(struct vhost_rdma_pkt_info *pkt)
{
	return __immdt_imm(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_IMMDT]);
}

static inline void immdt_set_imm(struct vhost_rdma_pkt_info *pkt, rte_be32_t imm)
{
	__immdt_set_imm(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_IMMDT], imm);
}

/******************************************************************************
 * Invalidate Extended Transport Header
 ******************************************************************************/
struct vhost_ieth {
	rte_be32_t			rkey;
};

static inline uint32_t __ieth_rkey(void *arg)
{
	struct vhost_ieth *ieth = arg;

	return rte_be_to_cpu_32(ieth->rkey);
}

static inline void __ieth_set_rkey(void *arg, uint32_t rkey)
{
	struct vhost_ieth *ieth = arg;

	ieth->rkey = rte_cpu_to_be_32(rkey);
}

static inline uint32_t ieth_rkey(struct vhost_rdma_pkt_info *pkt)
{
	return __ieth_rkey(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_IETH]);
}

static inline void ieth_set_rkey(struct vhost_rdma_pkt_info *pkt, uint32_t rkey)
{
	__ieth_set_rkey(pkt->hdr +
		vhost_rdma_opcode[pkt->opcode].offset[VHOST_IETH], rkey);
}

enum vhost_rdma_hdr_length {
	VHOST_BTH_BYTES	    	= sizeof(struct vhost_bth),
	VHOST_DETH_BYTES		= sizeof(struct vhost_deth),
	VHOST_IMMDT_BYTES		= sizeof(struct vhost_immdt),
	VHOST_RETH_BYTES		= sizeof(struct vhost_reth),
	VHOST_AETH_BYTES		= sizeof(struct vhost_aeth),
	VHOST_ATMACK_BYTES	    = sizeof(struct vhost_atmack),
	VHOST_ATMETH_BYTES  	= sizeof(struct vhost_atmeth),
	VHOST_IETH_BYTES		= sizeof(struct vhost_ieth),
	VHOST_RDETH_BYTES		= sizeof(struct vhost_rdeth),
};

static inline size_t header_size(struct vhost_rdma_pkt_info *pkt)
{
	return vhost_rdma_opcode[pkt->opcode].length;
}

static inline void *payload_addr(struct vhost_rdma_pkt_info *pkt)
{
	return pkt->hdr + vhost_rdma_opcode[pkt->opcode].offset[VHOST_PAYLOAD];
}

static inline size_t payload_size(struct vhost_rdma_pkt_info *pkt)
{
	return pkt->paylen - vhost_rdma_opcode[pkt->opcode].offset[VHOST_PAYLOAD]
		- bth_pad(pkt) - VHOST_ICRC_SIZE;
}

#endif
