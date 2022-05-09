/*
 * Vhost-user RDMA device demo: vhost user net
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

#ifndef __VHOST_NET_H__
#define __VHOST_NET_H__

#include <rte_vhost.h>

#define MAX_PKTS_BURST 32

#define VHOST_NET_RXQ 0
#define VHOST_NET_TXQ 1

struct vhost_queue {
	struct rte_vhost_vring vring;
	uint16_t last_avail_idx;
	uint16_t last_used_idx;
	uint16_t id;
	bool enabled;
};

void vs_vhost_net_construct(struct vhost_queue *queues);
void vs_vhost_net_setup(int vid);
void vs_vhost_net_remove();

uint16_t vs_dequeue_pkts(uint16_t queue_id, struct rte_mempool *mbuf_pool,
                struct rte_mbuf **pkts, uint16_t count);
uint16_t vs_enqueue_pkts(uint16_t queue_id, struct rte_mbuf **pkts,
                uint32_t count);

#endif
