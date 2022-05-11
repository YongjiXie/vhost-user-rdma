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

#include <rte_mbuf.h>

#include "vhost_rdma_loc.h"
#include "vhost_rdma_task.h"

void
vhost_rdma_do_task(struct vhost_rdma_task *task)
{
	int cont;
	int ret;

	rte_spinlock_lock(&task->state_lock);
	switch (task->state) {
	case TASK_STATE_START:
		task->state = TASK_STATE_BUSY;
		rte_spinlock_unlock(&task->state_lock);
		break;

	case TASK_STATE_BUSY:
		task->state = TASK_STATE_ARMED;
		// fallthrough
	case TASK_STATE_ARMED:
		rte_spinlock_unlock(&task->state_lock);
		return;

	default:
		rte_spinlock_unlock(&task->state_lock);
		RDMA_LOG_INFO("%s failed with bad state %d\n", __func__, task->state);
		return;
	}

	do {
		cont = 0;
		ret = task->func(task->arg);

		rte_spinlock_lock(&task->state_lock);
		switch (task->state) {
		case TASK_STATE_BUSY:
			if (ret)
				task->state = TASK_STATE_START;
			else
				cont = 1;
			break;

		/* soneone tried to run the task since the last time we called
		 * func, so we will call one more time regardless of the
		 * return value
		 */
		case TASK_STATE_ARMED:
			task->state = TASK_STATE_BUSY;
			cont = 1;
			break;

		default:
			RDMA_LOG_INFO("%s failed with bad state %d\n", __func__,
				task->state);
		}
		rte_spinlock_unlock(&task->state_lock);
	} while (cont);

	task->ret = ret;
}

int
vhost_rdma_init_task(struct vhost_rdma_task *task, struct rte_ring *task_ring,
		     void *arg, int (*func)(void *), char *name)
{
	task->arg	= arg;
	task->func	= func;
	rte_strscpy(task->name, name, 8);
	task->destroyed	= false;
	task->task_ring	= task_ring;

	task->state = TASK_STATE_START;
	rte_atomic16_clear(&task->sched);
	rte_spinlock_init(&task->state_lock);

	return 0;
}

void
vhost_rdma_cleanup_task(struct vhost_rdma_task *task)
{
	bool idle;

	task->destroyed = true;
	rte_atomic16_clear(&task->sched);

	do {
		rte_spinlock_lock(&task->state_lock);
		idle = (task->state == TASK_STATE_START);
		rte_spinlock_unlock(&task->state_lock);
	} while (!idle);
}

void
vhost_rdma_run_task(struct vhost_rdma_task *task, int sched)
{
	if (task->destroyed)
		return;
	RDMA_LOG_DEBUG_DP("run task %s sched %d", task->name, sched);
	if (sched) {
		if (rte_atomic16_test_and_set(&task->sched)) {
			rte_ring_enqueue(task->task_ring, task);
		}
	} else {
		vhost_rdma_do_task(task);
	}
}

extern volatile bool force_quit;

int
vhost_rdma_scheduler(void *arg)
{
	struct vhost_rdma_dev *dev = (struct vhost_rdma_dev *) arg;
	struct vhost_rdma_task *task;
	struct rte_mbuf *pkt;

	RDMA_LOG_INFO("scheduler %u start", rte_lcore_id());
	g_vhost_rdma_dev.inuse++;
	if (rte_lcore_index(rte_lcore_id()) == 1) {
		// we cannot use multiple threads to recv pkts, which will cause pkts
		// disorder, and finally cause pkt retransmit?
		while (!force_quit && !g_vhost_rdma_dev.stopped) {
			// recv_pkts
			if (rte_ring_dequeue(dev->rx_ring, (void**)&pkt) == 0) {
				vhost_rdma_net_recv(dev, pkt);
			}
		}
	} else {
		rte_timer_subsystem_init();
		while (!force_quit && !g_vhost_rdma_dev.stopped) {
			// task
			if (rte_ring_dequeue(dev->task_ring, (void**)&task) == 0) {
				RDMA_LOG_DEBUG_DP("task (%s) start", task->name);
				rte_atomic16_clear(&task->sched);
				vhost_rdma_do_task(task);
				RDMA_LOG_DEBUG_DP("task (%s) finish", task->name);
			}

			// timer
			rte_timer_manage();
		}
		rte_timer_subsystem_finalize();
	}
	g_vhost_rdma_dev.inuse--;
	RDMA_LOG_INFO("scheduler %u quit", rte_lcore_id());
	return 0;
}
