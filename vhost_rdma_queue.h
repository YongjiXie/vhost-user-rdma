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

#ifndef __VHOST_RDMA_QUEUE_H__
#define __VHOST_RDMA_QUEUE_H__

#include <stdint.h>

#include <rte_interrupts.h>

#include "virtio_net.h"

int setup_iovs_from_descs(struct rte_vhost_memory *mem, struct vhost_queue *vq,
			  uint16_t req_idx, struct iovec *iovs, uint16_t num_iovs,
			  uint16_t *num_in, uint16_t* num_out);

static __rte_always_inline uint16_t
vq_get_desc_idx(struct vhost_queue *vq)
{
	uint16_t desc_idx;
	uint16_t last_avail_idx;

	last_avail_idx = vq->last_avail_idx & (vq->vring.size - 1);
	desc_idx = vq->vring.avail->ring[last_avail_idx];
	vq->last_avail_idx++;

	return desc_idx;
}

static __rte_always_inline void
vhost_queue_notify(int vid, struct vhost_queue* vq) {
	rte_vhost_vring_call(vid, vq->id);
}

static __rte_always_inline uint64_t
gpa_to_vva(struct rte_vhost_memory *mem, uint64_t gpa, uint64_t *len)
{
	assert(mem != NULL);
	return rte_vhost_va_from_guest_pa(mem, gpa, len);
}

static __rte_always_inline bool
descriptor_has_next_split(struct vring_desc *cur_desc)
{
	return !!(cur_desc->flags & VRING_DESC_F_NEXT);
}

static __rte_always_inline struct vring_desc *
vring_get_next_desc(struct vring_desc *table, struct vring_desc *desc)
{
	if (desc->flags & VRING_DESC_F_NEXT)
		return &table[desc->next];

	return NULL;
}

static __rte_always_inline bool
vhost_vq_is_avail(struct vhost_queue *vq)
{
	return vq->vring.avail->idx != vq->last_avail_idx;
}

static __rte_always_inline void
vhost_queue_push(struct vhost_queue *vq, uint16_t idx, uint32_t len)
{
	struct vring_used *used = vq->vring.used;

	used->ring[used->idx & (vq->vring.size - 1)].id = idx;
	used->ring[used->idx & (vq->vring.size - 1)].len = len;
	rte_smp_mb();
	used->idx++;
	rte_smp_mb();
}

#endif
