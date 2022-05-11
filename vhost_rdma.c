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

#include <unistd.h>

#include <rte_ring.h>
#include <rte_vhost.h>

#include "virtio_net.h"
#include "vhost_rdma.h"
#include "vhost_user.h"
#include "vhost_rdma_ib.h"
#include "vhost_rdma_loc.h"

struct vhost_rdma_dev g_vhost_rdma_dev;

// FIXME: new_device never called because not all vq have been used.
static int
new_device(int vid)
{
	struct vhost_rdma_dev *dev = &g_vhost_rdma_dev;

	RDMA_LOG_INFO("new device");

	if (dev->started)
		return 0;

	vs_vhost_net_setup(vid);
	/* device has been started */
	dev->started = 1;
	dev->stopped = false;

	return 0;
}

static void
destroy_device(__rte_unused int vid)
{
	struct vhost_rdma_dev *dev;
	struct vhost_queue *vq;

	dev = &g_vhost_rdma_dev;

	if (!dev->started)
		return;

	dev->started = 0;
	dev->stopped = true;

	while (dev->inuse == 0) {
		rte_pause();
	}

	vs_vhost_net_remove();
	vhost_rdma_destroy_ib(dev);

	for (int i = 0; i < NUM_VHOST_QUEUES; i++) {
		vq = &dev->vqs[i];

		rte_vhost_set_vring_base(dev->vid, i,
					 vq->last_avail_idx,
					 vq->last_used_idx);

		vq->enabled = false;
	}

	free(dev->mem);
}

static enum rte_vhost_msg_result
extern_vhost_pre_msg_handler(__rte_unused int vid, void *_msg)
{
	struct vhost_rdma_dev *dev;
	struct vhost_user_msg *msg = _msg;

	dev = &g_vhost_rdma_dev;

	switch ((int)msg->request) {
	case VHOST_USER_GET_VRING_BASE:
	case VHOST_USER_SET_VRING_BASE:
	case VHOST_USER_SET_VRING_ADDR:
	case VHOST_USER_SET_VRING_NUM:
	case VHOST_USER_SET_VRING_KICK:
	case VHOST_USER_SET_VRING_CALL:
	case VHOST_USER_SET_MEM_TABLE:
		break;
	case VHOST_USER_GET_CONFIG: {
		rte_memcpy(msg->payload.cfg.region, &dev->config, sizeof(dev->config));
		return RTE_VHOST_MSG_RESULT_REPLY;
	}
	case VHOST_USER_SET_CONFIG:
	default:
		break;
	}

	return RTE_VHOST_MSG_RESULT_NOT_HANDLED;
}

struct rte_vhost_user_extern_ops g_extern_vhost_ops = {
	.pre_msg_handle = extern_vhost_pre_msg_handler,
};

static int
new_connection(int vid)
{
	int ret = 0;

	ret = rte_vhost_extern_callback_register(vid, &g_extern_vhost_ops, NULL);
	if (ret != 0)
		RDMA_LOG_ERR(
			"rte_vhost_extern_callback_register failed for vid = %d\n",
			vid);

	g_vhost_rdma_dev.vid = vid;
	return ret;
}

static int
vring_state_changed(int vid, uint16_t queue_id, int enable) {
	struct vhost_rdma_dev *dev = &g_vhost_rdma_dev;
	struct vhost_queue *vq;

	assert(dev->vid == vid);

	if (enable) {
		vq = &dev->vqs[queue_id];

		if (vq->enabled)
			return 0;

		vq->id = queue_id;

		assert(rte_vhost_get_vhost_vring(dev->vid, queue_id,
						 &vq->vring) == 0);
		assert(rte_vhost_get_vring_base(dev->vid, queue_id,
						&vq->last_avail_idx,
						&vq->last_used_idx) == 0);
		vq->enabled = true;
		/*
		 * ctrl_handler MUST start when the virtqueue is enabled,
		 * NOT start in new_device(). because driver will query some
		 * informations through ctrl vq in ib_register_device() when
		 * the device is not enabled.
		 */
		if (queue_id == VHOST_NET_ROCE_CTRL_QUEUE && !dev->ctrl_intr_registed) {
			assert(rte_vhost_get_mem_table(vid, &dev->mem) == 0);
			assert(dev->mem != NULL);

			dev->ctrl_intr_handle.fd = dev->vqs[VHOST_NET_ROCE_CTRL_QUEUE].vring.kickfd;
			dev->ctrl_intr_handle.type = RTE_INTR_HANDLE_EXT;
			rte_intr_callback_register(&dev->ctrl_intr_handle,
						   vhost_rdma_handle_ctrl, dev);
			dev->ctrl_intr_registed = 1;
		}
	}
	return 0;
}

struct vhost_device_ops vhost_rdma_device_ops = {
	.new_device =  new_device,
	.destroy_device = destroy_device,
	.new_connection = new_connection,
	.vring_state_changed = vring_state_changed,
};

static void
vhost_rdma_install_rte_compat_hooks(const char *path)
{
	uint64_t protocol_features = 0;

	rte_vhost_driver_get_protocol_features(path, &protocol_features);
	protocol_features |= (1ULL << VHOST_USER_PROTOCOL_F_CONFIG);
	protocol_features |= (1ULL << VHOST_USER_PROTOCOL_F_MQ);
	rte_vhost_driver_set_protocol_features(path, protocol_features);
}

void
vhost_rdma_destroy(const char* path)
{
	struct vhost_rdma_dev *dev;

	dev = &g_vhost_rdma_dev;
	if (dev->task_ring)
		rte_ring_free(dev->task_ring);
	dev->task_ring = NULL;

	RDMA_LOG_INFO("vhost rdma destroy");

	rte_intr_callback_unregister(&dev->ctrl_intr_handle,
					vhost_rdma_handle_ctrl, dev);
	rte_vhost_driver_unregister(path);
}

int
vhost_rdma_construct(const char *path, struct rte_mempool *mbuf_pool,
		     struct rte_ring* tx_ring, struct rte_ring* rx_ring) {
	struct vhost_rdma_dev *dev = &g_vhost_rdma_dev;
	int ret;

	RDMA_LOG_INFO("rdma path: %s", path);
	unlink(path);

	ret = rte_vhost_driver_register(path, 0);
	if (ret != 0) {
		RDMA_LOG_ERR("Socket %s already exists\n", path);
		return ret;
	}

	ret = rte_vhost_driver_set_features(path, VHOST_RDMA_FEATURE);
	if (ret != 0) {
		RDMA_LOG_ERR("Set vhost driver features failed\n");
		rte_vhost_driver_unregister(path);
		return ret;
	}

	dev->stopped = false;
	dev->inuse = 0;

	/* set vhost user protocol features */
	vhost_rdma_install_rte_compat_hooks(path);

	dev->rdma_vqs = &dev->vqs[VHOST_NET_ROCE_CTRL_QUEUE];

	vs_vhost_net_construct(dev->vqs);

	vhost_rdma_init_ib(dev);
	rte_spinlock_init(&dev->port_lock);

	rte_vhost_driver_callback_register(path,
					   &vhost_rdma_device_ops);

	dev->mbuf_pool = mbuf_pool;
	dev->tx_ring = tx_ring;
	dev->rx_ring = rx_ring;

	dev->task_ring = rte_ring_create("rdma_task_ring",
			roundup_pow_of_two(dev->config.max_rdma_qps * 3),
			rte_socket_id(), RING_F_MP_HTS_ENQ | RING_F_MC_HTS_DEQ);

	for (int i = 0; i < VHOST_NUM_OF_COUNTERS; i++) {
		rte_atomic64_init(&dev->stats_counters[i]);
	}

	rte_eal_mp_remote_launch(vhost_rdma_scheduler, dev, SKIP_MAIN);

	return 0;
}
