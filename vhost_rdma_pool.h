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

#ifndef __VHOST_RDMA_POOL_H__
#define __VHOST_RDMA_POOL_H__

#include <stdint.h>

#include <rte_bitmap.h>

struct vhost_rdma_pool {
	void *objs;
	uint32_t num;
	uint32_t size;

	struct rte_bitmap *bitmap;
	void *bitmap_mem;

	void (*cleanup)(void *arg);
};

int vhost_rdma_pool_init(struct vhost_rdma_pool* pool, char* name, uint32_t num,
			 uint32_t size, bool start_zero, void(*cleanup)(void *arg));
void vhost_rdma_pool_destroy(struct vhost_rdma_pool* pool);
void* vhost_rdma_pool_alloc(struct vhost_rdma_pool* pool, uint32_t *idx);
void vhost_rdma_pool_free(struct vhost_rdma_pool* pool, uint32_t idx);
void* vhost_rdma_pool_get(struct vhost_rdma_pool* pool, uint32_t idx);

#define vhost_rdma_ref_init(obj) \
	do{\
		rte_atomic32_init(&(obj)->refcnt); \
		rte_atomic32_inc(&(obj)->refcnt); \
	}while(0)

#define vhost_rdma_add_ref(obj) rte_atomic32_inc(&(obj)->refcnt)

#define vhost_rdma_drop_ref(obj, dev, type) \
	do { \
		if (rte_atomic32_dec_and_test(&(obj)->refcnt)) { \
			struct vhost_rdma_pool* pool = &(dev)->type##_pool; \
			if (pool->cleanup) { \
				pool->cleanup(obj); \
			} \
			vhost_rdma_pool_free(pool, (obj)->type##n); \
		} \
	}while(0)

#endif
