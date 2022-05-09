/*
 * Vhost-user RDMA device demo: obj pool
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

#include <rte_bitmap.h>
#include <rte_malloc.h>

#include "vhost_rdma_pool.h"
#include "logging.h"

void*
vhost_rdma_pool_alloc(struct vhost_rdma_pool* pool, uint32_t *idx)
{
	int found;
	uint32_t pos = 0;
	uint64_t slab = 0;
	void* obj;

	__rte_bitmap_scan_init(pool->bitmap);
	found = rte_bitmap_scan(pool->bitmap, &pos, &slab);
	if (found) {
		*idx = pos + __builtin_ctzll(slab);

		obj = (char*)pool->objs + pool->size * *idx;
		memset(obj, 0, pool->size);

		rte_bitmap_clear(pool->bitmap, *idx);

		return obj;
	}
	return NULL;
}

void
vhost_rdma_pool_free(struct vhost_rdma_pool* pool, uint32_t idx)
{
	// FIXME: lock?
	rte_bitmap_set(pool->bitmap, idx);
}

void*
vhost_rdma_pool_get(struct vhost_rdma_pool* pool, uint32_t idx)
{
	uint64_t set;

	set = rte_bitmap_get(pool->bitmap, idx);
	if (set) {
		return NULL;
	} else {
		return (char*)pool->objs + pool->size * idx;
	}
}

int
vhost_rdma_pool_init(struct vhost_rdma_pool* pool, char* name, uint32_t num,
		     uint32_t size, bool start_zero, void (*cleanup)(void*))
{
	void *mem;
	uint32_t bmp_size;
	struct rte_bitmap *bmp;

	if (!start_zero) {
		num += 1;
	}

	pool->objs = rte_zmalloc(name, num * size, RTE_CACHE_LINE_SIZE);
	if (pool->objs == NULL) {
		RDMA_LOG_ERR("Failed to allocate memory for objs");
		return -1;
	}

	bmp_size = rte_bitmap_get_memory_footprint(num);

	mem = rte_zmalloc(name, bmp_size, RTE_CACHE_LINE_SIZE);
	if (mem == NULL) {
		rte_free(pool->objs);
		RDMA_LOG_ERR("Failed to allocate memory for bitmap");
		return -1;
	}

	bmp = rte_bitmap_init(num, mem, bmp_size);
	if (bmp == NULL) {
		rte_free(mem);
		rte_free(pool->objs);
		RDMA_LOG_ERR("Failed to init bitmap");
		return -1;
	}

	/* set all available */
	for(uint64_t i = 0; i < num; i++) {
		rte_bitmap_set(bmp, i);
	}
	if (!start_zero) {
		rte_bitmap_clear(bmp, 0);
	}

	pool->bitmap = bmp;
	pool->bitmap_mem = mem;
	pool->num = num;
	pool->size = size;
	pool->cleanup = cleanup;

	return 0;
}

void
vhost_rdma_pool_destroy(struct vhost_rdma_pool* pool)
{
	rte_free(pool->objs);
	rte_bitmap_free(pool->bitmap);
	rte_free(pool->bitmap_mem);
}
