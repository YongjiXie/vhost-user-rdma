/*
 * Vhost-user RDMA device demo: ib verbs, copied from kernel
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

#include <stdbool.h>
#include "verbs.h"

static const struct {
	int			valid;
	enum virtio_ib_qp_attr_mask	req_param[VIRTIO_IB_QPT_UD + 1];
	enum virtio_ib_qp_attr_mask	opt_param[VIRTIO_IB_QPT_UD + 1];
} qp_state_table[VIRTIO_IB_QPS_ERR + 1][VIRTIO_IB_QPS_ERR + 1] = {
	[VIRTIO_IB_QPS_RESET] = {
		[VIRTIO_IB_QPS_RESET] = { .valid = 1 },
		[VIRTIO_IB_QPS_INIT]  = {
			.valid = 1,
			.req_param = {
				[VIRTIO_IB_QPT_UD] = VIRTIO_IB_QP_QKEY,
				[VIRTIO_IB_QPT_UC] = VIRTIO_IB_QP_ACCESS_FLAGS,
				[VIRTIO_IB_QPT_RC]  = VIRTIO_IB_QP_ACCESS_FLAGS,
				[VIRTIO_IB_QPT_SMI] = VIRTIO_IB_QP_QKEY,
				[VIRTIO_IB_QPT_GSI] = VIRTIO_IB_QP_QKEY,
			}
		},
	},
	[VIRTIO_IB_QPS_INIT]  = {
		[VIRTIO_IB_QPS_RESET] = { .valid = 1 },
		[VIRTIO_IB_QPS_ERR] =   { .valid = 1 },
		[VIRTIO_IB_QPS_INIT]  = {
			.valid = 1,
			.opt_param = {
				[VIRTIO_IB_QPT_UD] = VIRTIO_IB_QP_QKEY,
				[VIRTIO_IB_QPT_UC] = VIRTIO_IB_QP_ACCESS_FLAGS,
				[VIRTIO_IB_QPT_RC]  = VIRTIO_IB_QP_ACCESS_FLAGS,
				[VIRTIO_IB_QPT_SMI] = VIRTIO_IB_QP_QKEY,
				[VIRTIO_IB_QPT_GSI] = VIRTIO_IB_QP_QKEY,
			}
		},
		[VIRTIO_IB_QPS_RTR]   = {
			.valid = 1,
			.req_param = {
				[VIRTIO_IB_QPT_UC] = (VIRTIO_IB_QP_AV			|
						VIRTIO_IB_QP_PATH_MTU			|
						VIRTIO_IB_QP_DEST_QPN			|
						VIRTIO_IB_QP_RQ_PSN),
				[VIRTIO_IB_QPT_RC] = (VIRTIO_IB_QP_AV			|
						VIRTIO_IB_QP_PATH_MTU			|
						VIRTIO_IB_QP_DEST_QPN			|
						VIRTIO_IB_QP_RQ_PSN			|
						VIRTIO_IB_QP_MAX_DEST_RD_ATOMIC	|
						VIRTIO_IB_QP_MIN_RNR_TIMER),
			},
			.opt_param = {
				 [VIRTIO_IB_QPT_UD] = VIRTIO_IB_QP_QKEY,
				 [VIRTIO_IB_QPT_UC] = VIRTIO_IB_QP_ACCESS_FLAGS,
				 [VIRTIO_IB_QPT_RC] = VIRTIO_IB_QP_ACCESS_FLAGS,
				 [VIRTIO_IB_QPT_SMI] = VIRTIO_IB_QP_QKEY,
				 [VIRTIO_IB_QPT_GSI] = VIRTIO_IB_QP_QKEY,
			 },
		},
	},
	[VIRTIO_IB_QPS_RTR]   = {
		[VIRTIO_IB_QPS_RESET] = { .valid = 1 },
		[VIRTIO_IB_QPS_ERR] =   { .valid = 1 },
		[VIRTIO_IB_QPS_RTS]   = {
			.valid = 1,
			.req_param = {
				[VIRTIO_IB_QPT_UD]  = VIRTIO_IB_QP_SQ_PSN,
				[VIRTIO_IB_QPT_UC]  = VIRTIO_IB_QP_SQ_PSN,
				[VIRTIO_IB_QPT_RC]  = (VIRTIO_IB_QP_TIMEOUT			|
						VIRTIO_IB_QP_RETRY_CNT			|
						VIRTIO_IB_QP_RNR_RETRY			|
						VIRTIO_IB_QP_SQ_PSN			|
						VIRTIO_IB_QP_MAX_QP_RD_ATOMIC),
				[VIRTIO_IB_QPT_SMI] = VIRTIO_IB_QP_SQ_PSN,
				[VIRTIO_IB_QPT_GSI] = VIRTIO_IB_QP_SQ_PSN,
			},
			.opt_param = {
				 [VIRTIO_IB_QPT_UD]  = (VIRTIO_IB_QP_CUR_STATE		|
						 VIRTIO_IB_QP_QKEY),
				 [VIRTIO_IB_QPT_UC]  = (VIRTIO_IB_QP_CUR_STATE		|
						 VIRTIO_IB_QP_ACCESS_FLAGS),
				 [VIRTIO_IB_QPT_RC]  = (VIRTIO_IB_QP_CUR_STATE		|
						 VIRTIO_IB_QP_ACCESS_FLAGS		|
						 VIRTIO_IB_QP_MIN_RNR_TIMER),
				 [VIRTIO_IB_QPT_SMI] = (VIRTIO_IB_QP_CUR_STATE		|
						 VIRTIO_IB_QP_QKEY),
				 [VIRTIO_IB_QPT_GSI] = (VIRTIO_IB_QP_CUR_STATE		|
						 VIRTIO_IB_QP_QKEY),
			 }
		}
	},
	[VIRTIO_IB_QPS_RTS]   = {
		[VIRTIO_IB_QPS_RESET] = { .valid = 1 },
		[VIRTIO_IB_QPS_ERR] =   { .valid = 1 },
		[VIRTIO_IB_QPS_RTS]   = {
			.valid = 1,
			.opt_param = {
				[VIRTIO_IB_QPT_UD]  = (VIRTIO_IB_QP_CUR_STATE			|
						VIRTIO_IB_QP_QKEY),
				[VIRTIO_IB_QPT_UC]  = (VIRTIO_IB_QP_CUR_STATE			|
						VIRTIO_IB_QP_ACCESS_FLAGS),
				[VIRTIO_IB_QPT_RC]  = (VIRTIO_IB_QP_CUR_STATE			|
						VIRTIO_IB_QP_ACCESS_FLAGS		|
						VIRTIO_IB_QP_MIN_RNR_TIMER),
				[VIRTIO_IB_QPT_SMI] = (VIRTIO_IB_QP_CUR_STATE			|
						VIRTIO_IB_QP_QKEY),
				[VIRTIO_IB_QPT_GSI] = (VIRTIO_IB_QP_CUR_STATE			|
						VIRTIO_IB_QP_QKEY),
			}
		},
		[VIRTIO_IB_QPS_SQD]   = {
			.valid = 1,
		},
	},
	[VIRTIO_IB_QPS_SQD]   = {
		[VIRTIO_IB_QPS_RESET] = { .valid = 1 },
		[VIRTIO_IB_QPS_ERR] =   { .valid = 1 },
		[VIRTIO_IB_QPS_RTS]   = {
			.valid = 1,
			.opt_param = {
				[VIRTIO_IB_QPT_UD]  = (VIRTIO_IB_QP_CUR_STATE			|
						VIRTIO_IB_QP_QKEY),
				[VIRTIO_IB_QPT_UC]  = (VIRTIO_IB_QP_CUR_STATE			|
						VIRTIO_IB_QP_ACCESS_FLAGS),
				[VIRTIO_IB_QPT_RC]  = (VIRTIO_IB_QP_CUR_STATE			|
						VIRTIO_IB_QP_ACCESS_FLAGS		|
						VIRTIO_IB_QP_MIN_RNR_TIMER),
				[VIRTIO_IB_QPT_SMI] = (VIRTIO_IB_QP_CUR_STATE			|
						VIRTIO_IB_QP_QKEY),
				[VIRTIO_IB_QPT_GSI] = (VIRTIO_IB_QP_CUR_STATE			|
						VIRTIO_IB_QP_QKEY),
			}
		},
		[VIRTIO_IB_QPS_SQD]   = {
			.valid = 1,
			.opt_param = {
				[VIRTIO_IB_QPT_UD]  = VIRTIO_IB_QP_QKEY,
				[VIRTIO_IB_QPT_UC]  = (VIRTIO_IB_QP_AV			|
						VIRTIO_IB_QP_ACCESS_FLAGS),
				[VIRTIO_IB_QPT_RC]  = (VIRTIO_IB_QP_AV			|
						VIRTIO_IB_QP_TIMEOUT			|
						VIRTIO_IB_QP_RETRY_CNT			|
						VIRTIO_IB_QP_RNR_RETRY			|
						VIRTIO_IB_QP_MAX_QP_RD_ATOMIC		|
						VIRTIO_IB_QP_MAX_DEST_RD_ATOMIC	|
						VIRTIO_IB_QP_ACCESS_FLAGS		|
						VIRTIO_IB_QP_MIN_RNR_TIMER),
				[VIRTIO_IB_QPT_SMI] = VIRTIO_IB_QP_QKEY,
				[VIRTIO_IB_QPT_GSI] = VIRTIO_IB_QP_QKEY,
			}
		}
	},
	[VIRTIO_IB_QPS_SQE]   = {
		[VIRTIO_IB_QPS_RESET] = { .valid = 1 },
		[VIRTIO_IB_QPS_ERR] =   { .valid = 1 },
		[VIRTIO_IB_QPS_RTS]   = {
			.valid = 1,
			.opt_param = {
				[VIRTIO_IB_QPT_UD]  = (VIRTIO_IB_QP_CUR_STATE			|
						VIRTIO_IB_QP_QKEY),
				[VIRTIO_IB_QPT_UC]  = (VIRTIO_IB_QP_CUR_STATE			|
						VIRTIO_IB_QP_ACCESS_FLAGS),
				[VIRTIO_IB_QPT_SMI] = (VIRTIO_IB_QP_CUR_STATE			|
						VIRTIO_IB_QP_QKEY),
				[VIRTIO_IB_QPT_GSI] = (VIRTIO_IB_QP_CUR_STATE			|
						VIRTIO_IB_QP_QKEY),
			}
		}
	},
	[VIRTIO_IB_QPS_ERR] = {
		[VIRTIO_IB_QPS_RESET] = { .valid = 1 },
		[VIRTIO_IB_QPS_ERR] =   { .valid = 1 }
	}
};

bool ib_modify_qp_is_ok(enum virtio_ib_qp_state cur_state,
			enum virtio_ib_qp_state next_state,
			uint8_t type, enum virtio_ib_qp_attr_mask mask)
{
	enum virtio_ib_qp_attr_mask req_param, opt_param;

	if (mask & VIRTIO_IB_QP_CUR_STATE  &&
	    cur_state != VIRTIO_IB_QPS_RTR && cur_state != VIRTIO_IB_QPS_RTS &&
	    cur_state != VIRTIO_IB_QPS_SQD && cur_state != VIRTIO_IB_QPS_SQE)
		return false;

	if (!qp_state_table[cur_state][next_state].valid)
		return false;

	req_param = qp_state_table[cur_state][next_state].req_param[type];
	opt_param = qp_state_table[cur_state][next_state].opt_param[type];

	if ((mask & req_param) != req_param)
		return false;

	if (mask & ~(req_param | opt_param | VIRTIO_IB_QP_STATE))
		return false;

	return true;
}
