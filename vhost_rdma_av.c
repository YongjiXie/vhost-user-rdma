/*
 * Vhost-user RDMA device demo: address handle
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

#include "vhost_rdma.h"
#include "vhost_rdma_ib.h"
#include "vhost_rdma_loc.h"

void vhost_rdma_av_to_attr(struct vhost_rdma_av *av,
			   struct virtio_rdma_ah_attr *attr)
{
	struct virtio_rdma_global_route *grh = &attr->grh;

	rte_memcpy(grh->dgid, av->grh.dgid, sizeof(av->grh.dgid));
	grh->flow_label = av->grh.flow_label;
	grh->sgid_index = av->grh.sgid_index;
	grh->hop_limit = av->grh.hop_limit;
	grh->traffic_class = av->grh.traffic_class;
	rte_memcpy(attr->dmac, av->dmac, ETH_ALEN);
}

void
vhost_rdma_av_from_attr(struct vhost_rdma_av *av,
		     struct virtio_rdma_ah_attr *attr)
{
	const struct virtio_rdma_global_route *grh = &attr->grh;

	memset(av, 0, sizeof(*av));
	rte_memcpy(av->grh.dgid, grh->dgid, sizeof(grh->dgid));
	av->grh.flow_label = grh->flow_label;
	av->grh.sgid_index = grh->sgid_index;
	av->grh.hop_limit = grh->hop_limit;
	av->grh.traffic_class = grh->traffic_class;
	rte_memcpy(av->dmac, attr->dmac, ETH_ALEN);
}

static void
vhost_rdma_av_fill_ip_info(struct vhost_rdma_dev *dev,
			struct vhost_rdma_av *av, struct virtio_rdma_ah_attr *attr)
{
	const struct vhost_rdma_gid *sgid_attr;
	int ibtype;
	int type;

	sgid_attr = &dev->gid_tbl[attr->grh.sgid_index];

	rdma_gid2ip((struct sockaddr *)&av->sgid_addr, sgid_attr->gid);
	rdma_gid2ip((struct sockaddr *)&av->dgid_addr, attr->grh.dgid);

	ibtype = rdma_gid_attr_network_type(sgid_attr);

	switch (ibtype) {
	case RDMA_NETWORK_IPV4:
		type = VHOST_NETWORK_TYPE_IPV4;
		break;
	case RDMA_NETWORK_IPV6:
		type = VHOST_NETWORK_TYPE_IPV6;
		break;
	default:
		/* not reached - checked in av_chk_attr */
		type = 0;
		break;
	}

	av->network_type = type;
}

void
vhost_rdma_init_av(struct vhost_rdma_dev *dev, struct virtio_rdma_ah_attr *attr,
				struct vhost_rdma_av *av)
{
	vhost_rdma_av_from_attr(av, attr);
	vhost_rdma_av_fill_ip_info(dev, av, attr);
	rte_memcpy(av->dmac, attr->dmac, ETH_ALEN);
}

int
vhost_rdma_av_chk_attr(struct vhost_rdma_dev *dev,
						struct virtio_rdma_ah_attr *attr)
{
	struct virtio_rdma_global_route *grh = &attr->grh;
	int type;

	// uint8 sgid_index is always smaller than VHOST_MAX_GID_TBL_LEN
	type = rdma_gid_attr_network_type(&dev->gid_tbl[grh->sgid_index]);
	if (type < RDMA_NETWORK_IPV4 ||
		type > RDMA_NETWORK_IPV6) {
		RDMA_LOG_ERR("invalid network type = %d", type);
		return -EINVAL;
	}

	return 0;
}

void
init_av_from_virtio(struct vhost_rdma_dev *dev, struct vhost_rdma_av *dst,
		    uint32_t ah)
{
	struct vhost_rdma_av *av;

        av = vhost_rdma_pool_get(&dev->ah_pool, ah);

	assert(av);

	rte_memcpy(dst, av, sizeof(*dst));
}

struct vhost_rdma_av*
vhost_rdma_get_av(struct vhost_rdma_pkt_info *pkt)
{
	if (!pkt || !pkt->qp)
		return NULL;

	if (pkt->qp->type == VIRTIO_IB_QPT_RC ||
	    pkt->qp->type == VIRTIO_IB_QPT_UC)
		return &pkt->qp->av;

	return (pkt->wqe) ? &pkt->wqe->av : NULL;
}
