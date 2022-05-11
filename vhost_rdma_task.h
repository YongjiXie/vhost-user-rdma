/*
 * Vhost-user RDMA device demo: task scheduler
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

#ifndef __VHOST_RDMA_TASK_H__
#define __VHOST_RDMA_TASK_H__

enum {
	TASK_STATE_START = 0,
	TASK_STATE_BUSY = 1,
	TASK_STATE_ARMED = 2,
};

struct vhost_rdma_task {
	char name[8];
	int state;
	bool destroyed;
	rte_atomic16_t sched;
	rte_spinlock_t state_lock; /* spinlock for task state */
	struct rte_ring *task_ring;

	int (*func)(void *arg);
	void *arg;
	int ret;
};

static __rte_always_inline int
__vhost_rdma_do_task(struct vhost_rdma_task *task)

{
	int ret;
	while ((ret = task->func(task->arg)) == 0);
	task->ret = ret;
	return ret;
}

void vhost_rdma_do_task(struct vhost_rdma_task *task);
int vhost_rdma_init_task(struct vhost_rdma_task *task, struct rte_ring* work_r,
						void *arg, int (*func)(void *), char *name);
void vhost_rdma_cleanup_task(struct vhost_rdma_task *task);
void vhost_rdma_run_task(struct vhost_rdma_task *task, int sched);

int vhost_rdma_scheduler(void* arg);

#endif
