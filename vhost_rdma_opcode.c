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

#include <linux/virtio_net.h>

#include "vhost_rdma_opcode.h"
#include "vhost_rdma_hdr.h"
#include "virtio_rdma_abi.h"

struct vhost_rdma_wr_opcode_info vhost_rdma_wr_opcode_info[] = {
	[VIRTIO_IB_WR_RDMA_WRITE]				= {
		.name	= "VIRTIO_IB_WR_RDMA_WRITE",
		.mask	= {
			[VIRTIO_IB_QPT_RC]	= WR_INLINE_MASK | WR_WRITE_MASK,
			[VIRTIO_IB_QPT_UC]	= WR_INLINE_MASK | WR_WRITE_MASK,
		},
	},
	[VIRTIO_IB_WR_RDMA_WRITE_WITH_IMM]			= {
		.name	= "VIRTIO_IB_WR_RDMA_WRITE_WITH_IMM",
		.mask	= {
			[VIRTIO_IB_QPT_RC]	= WR_INLINE_MASK | WR_WRITE_MASK,
			[VIRTIO_IB_QPT_UC]	= WR_INLINE_MASK | WR_WRITE_MASK,
		},
	},
	[VIRTIO_IB_WR_SEND]					= {
		.name	= "VIRTIO_IB_WR_SEND",
		.mask	= {
			[VIRTIO_IB_QPT_SMI]	= WR_INLINE_MASK | WR_SEND_MASK,
			[VIRTIO_IB_QPT_GSI]	= WR_INLINE_MASK | WR_SEND_MASK,
			[VIRTIO_IB_QPT_RC]	= WR_INLINE_MASK | WR_SEND_MASK,
			[VIRTIO_IB_QPT_UC]	= WR_INLINE_MASK | WR_SEND_MASK,
			[VIRTIO_IB_QPT_UD]	= WR_INLINE_MASK | WR_SEND_MASK,
		},
	},
	[VIRTIO_IB_WR_SEND_WITH_IMM]				= {
		.name	= "VIRTIO_IB_WR_SEND_WITH_IMM",
		.mask	= {
			[VIRTIO_IB_QPT_SMI]	= WR_INLINE_MASK | WR_SEND_MASK,
			[VIRTIO_IB_QPT_GSI]	= WR_INLINE_MASK | WR_SEND_MASK,
			[VIRTIO_IB_QPT_RC]	= WR_INLINE_MASK | WR_SEND_MASK,
			[VIRTIO_IB_QPT_UC]	= WR_INLINE_MASK | WR_SEND_MASK,
			[VIRTIO_IB_QPT_UD]	= WR_INLINE_MASK | WR_SEND_MASK,
		},
	},
	[VIRTIO_IB_WR_RDMA_READ]				= {
		.name	= "VIRTIO_IB_WR_RDMA_READ",
		.mask	= {
			[VIRTIO_IB_QPT_RC]	= WR_READ_MASK,
		},
	},
};

struct vhost_rdma_opcode_info vhost_rdma_opcode[VHOST_NUM_OPCODE] = {
	[IB_OPCODE_RC_SEND_FIRST]			= {
		.name	= "IB_OPCODE_RC_SEND_FIRST",
		.mask	= VHOST_PAYLOAD_MASK | VHOST_REQ_MASK | VHOST_RWR_MASK
				| VHOST_SEND_MASK | VHOST_START_MASK,
		.length = VHOST_BTH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_MIDDLE]		= {
		.name	= "IB_OPCODE_RC_SEND_MIDDLE",
		.mask	= VHOST_PAYLOAD_MASK | VHOST_REQ_MASK | VHOST_SEND_MASK
				| VHOST_MIDDLE_MASK,
		.length = VHOST_BTH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_LAST]			= {
		.name	= "IB_OPCODE_RC_SEND_LAST",
		.mask	= VHOST_PAYLOAD_MASK | VHOST_REQ_MASK | VHOST_COMP_MASK
				| VHOST_SEND_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RC_SEND_LAST_WITH_IMMEDIATE",
		.mask	= VHOST_IMMDT_MASK | VHOST_PAYLOAD_MASK | VHOST_REQ_MASK
				| VHOST_COMP_MASK | VHOST_SEND_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_IMMDT_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_IMMDT]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_ONLY]			= {
		.name	= "IB_OPCODE_RC_SEND_ONLY",
		.mask	= VHOST_PAYLOAD_MASK | VHOST_REQ_MASK | VHOST_COMP_MASK
				| VHOST_RWR_MASK | VHOST_SEND_MASK
				| VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RC_SEND_ONLY_WITH_IMMEDIATE",
		.mask	= VHOST_IMMDT_MASK | VHOST_PAYLOAD_MASK | VHOST_REQ_MASK
				| VHOST_COMP_MASK | VHOST_RWR_MASK | VHOST_SEND_MASK
				| VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_IMMDT_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_IMMDT]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_WRITE_FIRST]		= {
		.name	= "IB_OPCODE_RC_RDMA_WRITE_FIRST",
		.mask	= VHOST_RETH_MASK | VHOST_PAYLOAD_MASK | VHOST_REQ_MASK
				| VHOST_WRITE_MASK | VHOST_START_MASK,
		.length = VHOST_BTH_BYTES + VHOST_RETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RETH]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RETH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_WRITE_MIDDLE]		= {
		.name	= "IB_OPCODE_RC_RDMA_WRITE_MIDDLE",
		.mask	= VHOST_PAYLOAD_MASK | VHOST_REQ_MASK | VHOST_WRITE_MASK
				| VHOST_MIDDLE_MASK,
		.length = VHOST_BTH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_WRITE_LAST]			= {
		.name	= "IB_OPCODE_RC_RDMA_WRITE_LAST",
		.mask	= VHOST_PAYLOAD_MASK | VHOST_REQ_MASK | VHOST_WRITE_MASK
				| VHOST_END_MASK,
		.length = VHOST_BTH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RC_RDMA_WRITE_LAST_WITH_IMMEDIATE",
		.mask	= VHOST_IMMDT_MASK | VHOST_PAYLOAD_MASK | VHOST_REQ_MASK
				| VHOST_WRITE_MASK | VHOST_COMP_MASK | VHOST_RWR_MASK
				| VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_IMMDT_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_IMMDT]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_WRITE_ONLY]			= {
		.name	= "IB_OPCODE_RC_RDMA_WRITE_ONLY",
		.mask	= VHOST_RETH_MASK | VHOST_PAYLOAD_MASK | VHOST_REQ_MASK
				| VHOST_WRITE_MASK | VHOST_START_MASK
				| VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_RETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RETH]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RETH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RC_RDMA_WRITE_ONLY_WITH_IMMEDIATE",
		.mask	= VHOST_RETH_MASK | VHOST_IMMDT_MASK | VHOST_PAYLOAD_MASK
				| VHOST_REQ_MASK | VHOST_WRITE_MASK
				| VHOST_COMP_MASK | VHOST_RWR_MASK
				| VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_IMMDT_BYTES + VHOST_RETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RETH]	= VHOST_BTH_BYTES,
			[VHOST_IMMDT]	= VHOST_BTH_BYTES
						+ VHOST_RETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RETH_BYTES
						+ VHOST_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_READ_REQUEST]			= {
		.name	= "IB_OPCODE_RC_RDMA_READ_REQUEST",
		.mask	= VHOST_RETH_MASK | VHOST_REQ_MASK | VHOST_READ_MASK
				| VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_RETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RETH]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RETH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST]		= {
		.name	= "IB_OPCODE_RC_RDMA_READ_RESPONSE_FIRST",
		.mask	= VHOST_AETH_MASK | VHOST_PAYLOAD_MASK | VHOST_ACK_MASK
				| VHOST_START_MASK,
		.length = VHOST_BTH_BYTES + VHOST_AETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_AETH]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_AETH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE]		= {
		.name	= "IB_OPCODE_RC_RDMA_READ_RESPONSE_MIDDLE",
		.mask	= VHOST_PAYLOAD_MASK | VHOST_ACK_MASK | VHOST_MIDDLE_MASK,
		.length = VHOST_BTH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST]		= {
		.name	= "IB_OPCODE_RC_RDMA_READ_RESPONSE_LAST",
		.mask	= VHOST_AETH_MASK | VHOST_PAYLOAD_MASK | VHOST_ACK_MASK
				| VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_AETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_AETH]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_AETH_BYTES,
		}
	},
	[IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY]		= {
		.name	= "IB_OPCODE_RC_RDMA_READ_RESPONSE_ONLY",
		.mask	= VHOST_AETH_MASK | VHOST_PAYLOAD_MASK | VHOST_ACK_MASK
				| VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_AETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_AETH]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_AETH_BYTES,
		}
	},
	[IB_OPCODE_RC_ACKNOWLEDGE]			= {
		.name	= "IB_OPCODE_RC_ACKNOWLEDGE",
		.mask	= VHOST_AETH_MASK | VHOST_ACK_MASK | VHOST_START_MASK
				| VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_AETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_AETH]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_AETH_BYTES,
		}
	},
	[IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE]			= {
		.name	= "IB_OPCODE_RC_ATOMIC_ACKNOWLEDGE",
		.mask	= VHOST_AETH_MASK | VHOST_ATMACK_MASK | VHOST_ACK_MASK
				| VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_ATMACK_BYTES + VHOST_AETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_AETH]	= VHOST_BTH_BYTES,
			[VHOST_ATMACK]	= VHOST_BTH_BYTES
						+ VHOST_AETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
					+ VHOST_ATMACK_BYTES + VHOST_AETH_BYTES,
		}
	},
	[IB_OPCODE_RC_COMPARE_SWAP]			= {
		.name	= "IB_OPCODE_RC_COMPARE_SWAP",
		.mask	= VHOST_ATMETH_MASK | VHOST_REQ_MASK | VHOST_ATOMIC_MASK
				| VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_ATMETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_ATMETH]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_ATMETH_BYTES,
		}
	},
	[IB_OPCODE_RC_FETCH_ADD]			= {
		.name	= "IB_OPCODE_RC_FETCH_ADD",
		.mask	= VHOST_ATMETH_MASK | VHOST_REQ_MASK | VHOST_ATOMIC_MASK
				| VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_ATMETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_ATMETH]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_ATMETH_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE]		= {
		.name	= "IB_OPCODE_RC_SEND_LAST_WITH_INVALIDATE",
		.mask	= VHOST_IETH_MASK | VHOST_PAYLOAD_MASK | VHOST_REQ_MASK
				| VHOST_COMP_MASK | VHOST_SEND_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_IETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_IETH]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_IETH_BYTES,
		}
	},
	[IB_OPCODE_RC_SEND_ONLY_WITH_INVALIDATE]		= {
		.name	= "IB_OPCODE_RC_SEND_ONLY_INV",
		.mask	= VHOST_IETH_MASK | VHOST_PAYLOAD_MASK | VHOST_REQ_MASK
				| VHOST_COMP_MASK | VHOST_RWR_MASK | VHOST_SEND_MASK
				| VHOST_END_MASK  | VHOST_START_MASK,
		.length = VHOST_BTH_BYTES + VHOST_IETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_IETH]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_IETH_BYTES,
		}
	},

	/* UC */
	[IB_OPCODE_UC_SEND_FIRST]			= {
		.name	= "IB_OPCODE_UC_SEND_FIRST",
		.mask	= VHOST_PAYLOAD_MASK | VHOST_REQ_MASK | VHOST_RWR_MASK
				| VHOST_SEND_MASK | VHOST_START_MASK,
		.length = VHOST_BTH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES,
		}
	},
	[IB_OPCODE_UC_SEND_MIDDLE]		= {
		.name	= "IB_OPCODE_UC_SEND_MIDDLE",
		.mask	= VHOST_PAYLOAD_MASK | VHOST_REQ_MASK | VHOST_SEND_MASK
				| VHOST_MIDDLE_MASK,
		.length = VHOST_BTH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES,
		}
	},
	[IB_OPCODE_UC_SEND_LAST]			= {
		.name	= "IB_OPCODE_UC_SEND_LAST",
		.mask	= VHOST_PAYLOAD_MASK | VHOST_REQ_MASK | VHOST_COMP_MASK
				| VHOST_SEND_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES,
		}
	},
	[IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_UC_SEND_LAST_WITH_IMMEDIATE",
		.mask	= VHOST_IMMDT_MASK | VHOST_PAYLOAD_MASK | VHOST_REQ_MASK
				| VHOST_COMP_MASK | VHOST_SEND_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_IMMDT_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_IMMDT]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_UC_SEND_ONLY]			= {
		.name	= "IB_OPCODE_UC_SEND_ONLY",
		.mask	= VHOST_PAYLOAD_MASK | VHOST_REQ_MASK | VHOST_COMP_MASK
				| VHOST_RWR_MASK | VHOST_SEND_MASK
				| VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES,
		}
	},
	[IB_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_UC_SEND_ONLY_WITH_IMMEDIATE",
		.mask	= VHOST_IMMDT_MASK | VHOST_PAYLOAD_MASK | VHOST_REQ_MASK
				| VHOST_COMP_MASK | VHOST_RWR_MASK | VHOST_SEND_MASK
				| VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_IMMDT_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_IMMDT]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_UC_RDMA_WRITE_FIRST]		= {
		.name	= "IB_OPCODE_UC_RDMA_WRITE_FIRST",
		.mask	= VHOST_RETH_MASK | VHOST_PAYLOAD_MASK | VHOST_REQ_MASK
				| VHOST_WRITE_MASK | VHOST_START_MASK,
		.length = VHOST_BTH_BYTES + VHOST_RETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RETH]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RETH_BYTES,
		}
	},
	[IB_OPCODE_UC_RDMA_WRITE_MIDDLE]		= {
		.name	= "IB_OPCODE_UC_RDMA_WRITE_MIDDLE",
		.mask	= VHOST_PAYLOAD_MASK | VHOST_REQ_MASK | VHOST_WRITE_MASK
				| VHOST_MIDDLE_MASK,
		.length = VHOST_BTH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES,
		}
	},
	[IB_OPCODE_UC_RDMA_WRITE_LAST]			= {
		.name	= "IB_OPCODE_UC_RDMA_WRITE_LAST",
		.mask	= VHOST_PAYLOAD_MASK | VHOST_REQ_MASK | VHOST_WRITE_MASK
				| VHOST_END_MASK,
		.length = VHOST_BTH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES,
		}
	},
	[IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_UC_RDMA_WRITE_LAST_WITH_IMMEDIATE",
		.mask	= VHOST_IMMDT_MASK | VHOST_PAYLOAD_MASK | VHOST_REQ_MASK
				| VHOST_WRITE_MASK | VHOST_COMP_MASK | VHOST_RWR_MASK
				| VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_IMMDT_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_IMMDT]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_UC_RDMA_WRITE_ONLY]			= {
		.name	= "IB_OPCODE_UC_RDMA_WRITE_ONLY",
		.mask	= VHOST_RETH_MASK | VHOST_PAYLOAD_MASK | VHOST_REQ_MASK
				| VHOST_WRITE_MASK | VHOST_START_MASK
				| VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_RETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RETH]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RETH_BYTES,
		}
	},
	[IB_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_UC_RDMA_WRITE_ONLY_WITH_IMMEDIATE",
		.mask	= VHOST_RETH_MASK | VHOST_IMMDT_MASK | VHOST_PAYLOAD_MASK
				| VHOST_REQ_MASK | VHOST_WRITE_MASK
				| VHOST_COMP_MASK | VHOST_RWR_MASK
				| VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_IMMDT_BYTES + VHOST_RETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RETH]	= VHOST_BTH_BYTES,
			[VHOST_IMMDT]	= VHOST_BTH_BYTES
						+ VHOST_RETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RETH_BYTES
						+ VHOST_IMMDT_BYTES,
		}
	},

	/* RD */
	[IB_OPCODE_RD_SEND_FIRST]			= {
		.name	= "IB_OPCODE_RD_SEND_FIRST",
		.mask	= VHOST_RDETH_MASK | VHOST_DETH_MASK | VHOST_PAYLOAD_MASK
				| VHOST_REQ_MASK | VHOST_RWR_MASK | VHOST_SEND_MASK
				| VHOST_START_MASK,
		.length = VHOST_BTH_BYTES + VHOST_DETH_BYTES + VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_DETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES,
		}
	},
	[IB_OPCODE_RD_SEND_MIDDLE]		= {
		.name	= "IB_OPCODE_RD_SEND_MIDDLE",
		.mask	= VHOST_RDETH_MASK | VHOST_DETH_MASK | VHOST_PAYLOAD_MASK
				| VHOST_REQ_MASK | VHOST_SEND_MASK
				| VHOST_MIDDLE_MASK,
		.length = VHOST_BTH_BYTES + VHOST_DETH_BYTES + VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_DETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES,
		}
	},
	[IB_OPCODE_RD_SEND_LAST]			= {
		.name	= "IB_OPCODE_RD_SEND_LAST",
		.mask	= VHOST_RDETH_MASK | VHOST_DETH_MASK | VHOST_PAYLOAD_MASK
				| VHOST_REQ_MASK | VHOST_COMP_MASK | VHOST_SEND_MASK
				| VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_DETH_BYTES + VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_DETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES,
		}
	},
	[IB_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RD_SEND_LAST_WITH_IMMEDIATE",
		.mask	= VHOST_RDETH_MASK | VHOST_DETH_MASK | VHOST_IMMDT_MASK
				| VHOST_PAYLOAD_MASK | VHOST_REQ_MASK
				| VHOST_COMP_MASK | VHOST_SEND_MASK
				| VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_IMMDT_BYTES + VHOST_DETH_BYTES
				+ VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_DETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_IMMDT]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES
						+ VHOST_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RD_SEND_ONLY]			= {
		.name	= "IB_OPCODE_RD_SEND_ONLY",
		.mask	= VHOST_RDETH_MASK | VHOST_DETH_MASK | VHOST_PAYLOAD_MASK
				| VHOST_REQ_MASK | VHOST_COMP_MASK | VHOST_RWR_MASK
				| VHOST_SEND_MASK | VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_DETH_BYTES + VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_DETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES,
		}
	},
	[IB_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RD_SEND_ONLY_WITH_IMMEDIATE",
		.mask	= VHOST_RDETH_MASK | VHOST_DETH_MASK | VHOST_IMMDT_MASK
				| VHOST_PAYLOAD_MASK | VHOST_REQ_MASK
				| VHOST_COMP_MASK | VHOST_RWR_MASK | VHOST_SEND_MASK
				| VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_IMMDT_BYTES + VHOST_DETH_BYTES
				+ VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_DETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_IMMDT]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES
						+ VHOST_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_WRITE_FIRST]		= {
		.name	= "IB_OPCODE_RD_RDMA_WRITE_FIRST",
		.mask	= VHOST_RDETH_MASK | VHOST_DETH_MASK | VHOST_RETH_MASK
				| VHOST_PAYLOAD_MASK | VHOST_REQ_MASK
				| VHOST_WRITE_MASK | VHOST_START_MASK,
		.length = VHOST_BTH_BYTES + VHOST_RETH_BYTES + VHOST_DETH_BYTES
				+ VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_DETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_RETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES
						+ VHOST_RETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_WRITE_MIDDLE]		= {
		.name	= "IB_OPCODE_RD_RDMA_WRITE_MIDDLE",
		.mask	= VHOST_RDETH_MASK | VHOST_DETH_MASK | VHOST_PAYLOAD_MASK
				| VHOST_REQ_MASK | VHOST_WRITE_MASK
				| VHOST_MIDDLE_MASK,
		.length = VHOST_BTH_BYTES + VHOST_DETH_BYTES + VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_DETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_WRITE_LAST]			= {
		.name	= "IB_OPCODE_RD_RDMA_WRITE_LAST",
		.mask	= VHOST_RDETH_MASK | VHOST_DETH_MASK | VHOST_PAYLOAD_MASK
				| VHOST_REQ_MASK | VHOST_WRITE_MASK
				| VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_DETH_BYTES + VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_DETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RD_RDMA_WRITE_LAST_WITH_IMMEDIATE",
		.mask	= VHOST_RDETH_MASK | VHOST_DETH_MASK | VHOST_IMMDT_MASK
				| VHOST_PAYLOAD_MASK | VHOST_REQ_MASK
				| VHOST_WRITE_MASK | VHOST_COMP_MASK | VHOST_RWR_MASK
				| VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_IMMDT_BYTES + VHOST_DETH_BYTES
				+ VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_DETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_IMMDT]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES
						+ VHOST_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_WRITE_ONLY]			= {
		.name	= "IB_OPCODE_RD_RDMA_WRITE_ONLY",
		.mask	= VHOST_RDETH_MASK | VHOST_DETH_MASK | VHOST_RETH_MASK
				| VHOST_PAYLOAD_MASK | VHOST_REQ_MASK
				| VHOST_WRITE_MASK | VHOST_START_MASK
				| VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_RETH_BYTES + VHOST_DETH_BYTES
				+ VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_DETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_RETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES
						+ VHOST_RETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_RD_RDMA_WRITE_ONLY_WITH_IMMEDIATE",
		.mask	= VHOST_RDETH_MASK | VHOST_DETH_MASK | VHOST_RETH_MASK
				| VHOST_IMMDT_MASK | VHOST_PAYLOAD_MASK
				| VHOST_REQ_MASK | VHOST_WRITE_MASK
				| VHOST_COMP_MASK | VHOST_RWR_MASK
				| VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_IMMDT_BYTES + VHOST_RETH_BYTES
				+ VHOST_DETH_BYTES + VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_DETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_RETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES,
			[VHOST_IMMDT]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES
						+ VHOST_RETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES
						+ VHOST_RETH_BYTES
						+ VHOST_IMMDT_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_READ_REQUEST]			= {
		.name	= "IB_OPCODE_RD_RDMA_READ_REQUEST",
		.mask	= VHOST_RDETH_MASK | VHOST_DETH_MASK | VHOST_RETH_MASK
				| VHOST_REQ_MASK | VHOST_READ_MASK
				| VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_RETH_BYTES + VHOST_DETH_BYTES
				+ VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_DETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_RETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RETH_BYTES
						+ VHOST_DETH_BYTES
						+ VHOST_RDETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_READ_RESPONSE_FIRST]		= {
		.name	= "IB_OPCODE_RD_RDMA_READ_RESPONSE_FIRST",
		.mask	= VHOST_RDETH_MASK | VHOST_AETH_MASK
				| VHOST_PAYLOAD_MASK | VHOST_ACK_MASK
				| VHOST_START_MASK,
		.length = VHOST_BTH_BYTES + VHOST_AETH_BYTES + VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_AETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_AETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_READ_RESPONSE_MIDDLE]		= {
		.name	= "IB_OPCODE_RD_RDMA_READ_RESPONSE_MIDDLE",
		.mask	= VHOST_RDETH_MASK | VHOST_PAYLOAD_MASK | VHOST_ACK_MASK
				| VHOST_MIDDLE_MASK,
		.length = VHOST_BTH_BYTES + VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_READ_RESPONSE_LAST]		= {
		.name	= "IB_OPCODE_RD_RDMA_READ_RESPONSE_LAST",
		.mask	= VHOST_RDETH_MASK | VHOST_AETH_MASK | VHOST_PAYLOAD_MASK
				| VHOST_ACK_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_AETH_BYTES + VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_AETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_AETH_BYTES,
		}
	},
	[IB_OPCODE_RD_RDMA_READ_RESPONSE_ONLY]		= {
		.name	= "IB_OPCODE_RD_RDMA_READ_RESPONSE_ONLY",
		.mask	= VHOST_RDETH_MASK | VHOST_AETH_MASK | VHOST_PAYLOAD_MASK
				| VHOST_ACK_MASK | VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_AETH_BYTES + VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_AETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_AETH_BYTES,
		}
	},
	[IB_OPCODE_RD_ACKNOWLEDGE]			= {
		.name	= "IB_OPCODE_RD_ACKNOWLEDGE",
		.mask	= VHOST_RDETH_MASK | VHOST_AETH_MASK | VHOST_ACK_MASK
				| VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_AETH_BYTES + VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_AETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
		}
	},
	[IB_OPCODE_RD_ATOMIC_ACKNOWLEDGE]			= {
		.name	= "IB_OPCODE_RD_ATOMIC_ACKNOWLEDGE",
		.mask	= VHOST_RDETH_MASK | VHOST_AETH_MASK | VHOST_ATMACK_MASK
				| VHOST_ACK_MASK | VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_ATMACK_BYTES + VHOST_AETH_BYTES
				+ VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_AETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_ATMACK]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_AETH_BYTES,
		}
	},
	[IB_OPCODE_RD_COMPARE_SWAP]			= {
		.name	= "RD_COMPARE_SWAP",
		.mask	= VHOST_RDETH_MASK | VHOST_DETH_MASK | VHOST_ATMETH_MASK
				| VHOST_REQ_MASK | VHOST_ATOMIC_MASK
				| VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_ATMETH_BYTES + VHOST_DETH_BYTES
				+ VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_DETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_ATMETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES +
						+ VHOST_ATMETH_BYTES
						+ VHOST_DETH_BYTES +
						+ VHOST_RDETH_BYTES,
		}
	},
	[IB_OPCODE_RD_FETCH_ADD]			= {
		.name	= "IB_OPCODE_RD_FETCH_ADD",
		.mask	= VHOST_RDETH_MASK | VHOST_DETH_MASK | VHOST_ATMETH_MASK
				| VHOST_REQ_MASK | VHOST_ATOMIC_MASK
				| VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_ATMETH_BYTES + VHOST_DETH_BYTES
				+ VHOST_RDETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_RDETH]	= VHOST_BTH_BYTES,
			[VHOST_DETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES,
			[VHOST_ATMETH]	= VHOST_BTH_BYTES
						+ VHOST_RDETH_BYTES
						+ VHOST_DETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES +
						+ VHOST_ATMETH_BYTES
						+ VHOST_DETH_BYTES +
						+ VHOST_RDETH_BYTES,
		}
	},

	/* UD */
	[IB_OPCODE_UD_SEND_ONLY]			= {
		.name	= "IB_OPCODE_UD_SEND_ONLY",
		.mask	= VHOST_DETH_MASK | VHOST_PAYLOAD_MASK | VHOST_REQ_MASK
				| VHOST_COMP_MASK | VHOST_RWR_MASK | VHOST_SEND_MASK
				| VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_DETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_DETH]	= VHOST_BTH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_DETH_BYTES,
		}
	},
	[IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE]		= {
		.name	= "IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE",
		.mask	= VHOST_DETH_MASK | VHOST_IMMDT_MASK | VHOST_PAYLOAD_MASK
				| VHOST_REQ_MASK | VHOST_COMP_MASK | VHOST_RWR_MASK
				| VHOST_SEND_MASK | VHOST_START_MASK | VHOST_END_MASK,
		.length = VHOST_BTH_BYTES + VHOST_IMMDT_BYTES + VHOST_DETH_BYTES,
		.offset = {
			[VHOST_BTH]	= 0,
			[VHOST_DETH]	= VHOST_BTH_BYTES,
			[VHOST_IMMDT]	= VHOST_BTH_BYTES
						+ VHOST_DETH_BYTES,
			[VHOST_PAYLOAD]	= VHOST_BTH_BYTES
						+ VHOST_DETH_BYTES
						+ VHOST_IMMDT_BYTES,
		}
	},

};
