/*
 * Vhost-user RDMA device demo: loc header
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

#ifndef __VHOST_RDMA_LOC_H__
#define __VHOST_RDMA_LOC_H__

#include <stdint.h>
#include <netinet/in.h>
#include <linux/virtio_net.h>

#include <rte_mbuf.h>

#include "logging.h"
#include "vhost_rdma_ib.h"

__rte_always_inline uint32_t
roundup_pow_of_two(uint32_t n)
{
	return n < 2 ? n : (1u << (32 - __builtin_clz (n - 1)));
}

static inline bool ipv6_addr_v4mapped(const struct in6_addr *a)
{
	return IN6_IS_ADDR_V4MAPPED(a);
}

static inline void rdma_gid2ip(struct sockaddr *out, const uint8_t *gid)
{
	if (ipv6_addr_v4mapped((struct in6_addr *)gid)) {
		struct sockaddr_in *out_in = (struct sockaddr_in *)out;
		memset(out_in, 0, sizeof(*out_in));
		out_in->sin_family = AF_INET;
		rte_memcpy(&out_in->sin_addr.s_addr, gid + 12, 4);
	} else {
		struct sockaddr_in6 *out_in = (struct sockaddr_in6 *)out;
		memset(out_in, 0, sizeof(*out_in));
		out_in->sin6_family = AF_INET6;
		rte_memcpy(&out_in->sin6_addr.s6_addr, gid, 16);
	}
}

static inline enum rdma_network_type
rdma_gid_attr_network_type(const struct vhost_rdma_gid *attr)
{
	if (attr->type == IB_GID_TYPE_IB)
		return RDMA_NETWORK_IB;

	if (attr->type == IB_GID_TYPE_ROCE)
		return RDMA_NETWORK_ROCE_V1;

	if (ipv6_addr_v4mapped((struct in6_addr *)&attr->gid))
		return RDMA_NETWORK_IPV4;
	else
		return RDMA_NETWORK_IPV6;
}

/* vhost_rdma_av.c */
void vhost_rdma_av_to_attr(struct vhost_rdma_av *av,
				struct virtio_rdma_ah_attr *attr);
void vhost_rdma_av_from_attr(struct vhost_rdma_av *av,
		     struct virtio_rdma_ah_attr *attr);
int vhost_rdma_av_chk_attr(struct vhost_rdma_dev *dev,
				struct virtio_rdma_ah_attr *attr);
void vhost_rdma_init_av(struct vhost_rdma_dev *dev,
			struct virtio_rdma_ah_attr *attr, struct vhost_rdma_av *av);
void init_av_from_virtio(struct vhost_rdma_dev *dev, struct vhost_rdma_av *dst,
			 uint32_t ah);

/* vhost_rdma_mr.c */

uint8_t vhost_rdma_get_next_key(uint32_t last_key);
void vhost_rdma_mr_init_key(struct vhost_rdma_mr *mr, uint32_t mrn);
uint64_t** vhost_rdma_alloc_page_tbl(uint32_t npages);
void vhost_rdma_map_pages(struct rte_vhost_memory *mem, uint64_t *pages,
				uint64_t *dma_pages, uint32_t npages);
void vhost_rdma_mr_cleanup(void* arg);

/* vhost_rdma_qp.c */
int vhost_rdma_qp_init(struct vhost_rdma_dev *dev, struct vhost_rdma_qp *qp,
			struct virtio_rdma_cmd_create_qp *cmd);
void vhost_rdma_qp_destroy(struct vhost_rdma_qp *qp);
int vhost_rdma_qp_query(struct vhost_rdma_qp *qp,
			struct virtio_rdma_ack_query_qp *rsp);
int vhost_rdma_qp_validate(struct vhost_rdma_dev *dev, struct vhost_rdma_qp *qp,
			   struct virtio_rdma_cmd_modify_qp *cmd);
int vhost_rdma_qp_modify(struct vhost_rdma_dev *dev, struct vhost_rdma_qp *qp,
			 struct virtio_rdma_cmd_modify_qp *cmd);
void vhost_rdma_qp_error(struct vhost_rdma_qp *qp);
void vhost_rdma_qp_cleanup(void* arg);

#endif
