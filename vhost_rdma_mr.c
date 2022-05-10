/*
 * Vhost-user RDMA device demo: memory region
 *
 * Copyright (C) 2022 Bytedance Inc. and/or its affiliates. All rights reserved.
 *
 * Author: Xie Yongji <xieyongji@bytedance.com>
 *         Wei Junji <weijunji@bytedance.com>
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

#include <rte_random.h>
#include <rte_malloc.h>

#include "vhost_rdma.h"
#include "vhost_rdma_ib.h"
#include "vhost_rdma_loc.h"

#define BUF_PER_PAGE (512)

uint8_t
vhost_rdma_get_next_key(uint32_t last_key)
{
	uint8_t key;

	do {
		key = rte_rand();
	} while (key == last_key);

	return key;
}

#define IB_ACCESS_REMOTE	(VIRTIO_IB_ACCESS_REMOTE_READ		\
				| VIRTIO_IB_ACCESS_REMOTE_WRITE)

void
vhost_rdma_mr_init_key(struct vhost_rdma_mr *mr, uint32_t mrn)
{
	uint32_t lkey = mrn << 8 | vhost_rdma_get_next_key(-1);
	uint32_t rkey = (mr->access & IB_ACCESS_REMOTE) ? lkey : 0;

	mr->lkey = lkey;
	mr->rkey = rkey;
}

void
vhost_rdma_map_pages(struct rte_vhost_memory *mem, uint64_t *pages,
			uint64_t *dma_pages, uint32_t npages)
{
	uint32_t i;
	uint64_t len = TARGET_PAGE_SIZE;

	for (i = 0; i < npages; i++) {
		pages[i] = gpa_to_vva(mem, dma_pages[i], &len);
		assert(len == TARGET_PAGE_SIZE);
	}
}

void
vhost_rdma_mr_cleanup(void* arg)
{
	struct vhost_rdma_mr *mr = arg;

	mr->type = VHOST_MR_TYPE_NONE;
}
