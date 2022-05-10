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
