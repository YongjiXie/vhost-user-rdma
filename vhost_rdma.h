/*
 * Vhost-user RDMA device demo: rdma device
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

#ifndef __VHOST_RDMA_H__
#define __VHOST_RDMA_H__

#include <rte_vhost.h>
#include <rte_interrupts.h>

#include <linux/virtio_net.h>
#include "virtio_net.h"

#define NUM_VHOST_QUEUES 2

/* VIRTIO_F_EVENT_IDX is NOT supported now */
#define VHOST_RDMA_FEATURE ((1ULL << VIRTIO_F_VERSION_1) |\
	(1ULL << VIRTIO_RING_F_INDIRECT_DESC) | \
	(1ULL << VHOST_USER_F_PROTOCOL_FEATURES) | \
	(1ULL << VHOST_USER_PROTOCOL_F_STATUS))

extern struct vhost_rdma_dev g_vhost_rdma_dev;

struct vhost_rdma_dev {
	int vid;
	int started;
#define VHOST_STATE_READY	0
#define VHOST_STATE_STARTED	1
#define VHOST_STATE_STOPPED	2
#define VHOST_STATE_REMOVED	3
	volatile int state;

	struct rte_vhost_memory *mem;

	struct rte_mempool *mbuf_pool;
	struct vhost_queue vqs[NUM_VHOST_QUEUES];

	struct virtio_net_config config;
};

int vhost_rdma_construct(const char *path);
void vhost_rdma_destroy(const char* path);

#endif
