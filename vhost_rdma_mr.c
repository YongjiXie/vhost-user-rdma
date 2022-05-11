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

struct vhost_rdma_mr*
lookup_mr(struct vhost_rdma_pd *pd, int access,
		uint32_t key, enum vhost_rdma_mr_lookup_type type)
{
	struct vhost_rdma_mr *mr;
	int index = key >> 8;

	mr = vhost_rdma_pool_get(&pd->dev->mr_pool, index);
	if (!mr)
		return NULL;
	vhost_rdma_add_ref(mr);

	if (unlikely((type == VHOST_LOOKUP_LOCAL && mr->lkey != key) ||
		     (type == VHOST_LOOKUP_REMOTE && mr->rkey != key) ||
		     mr->pd != pd || (access && !(access & mr->access)) ||
		     mr->state != VHOST_MR_STATE_VALID)) {
		vhost_rdma_drop_ref(mr, pd->dev, mr);
		mr = NULL;
	}

	return mr;
}

int
mr_check_range(struct vhost_rdma_mr *mr, uint64_t iova, size_t length)
{
	switch (mr->type) {
	case VHOST_MR_TYPE_DMA:
		return 0;

	case VHOST_MR_TYPE_MR:
		if (iova < mr->iova || length > mr->length ||
		    iova > mr->iova + mr->length - length)
			return -EFAULT;
		return 0;

	default:
		return -EFAULT;
	}
}

static __rte_always_inline uint64_t
lookup_iova(struct vhost_rdma_mr *mr, uint64_t iova)
{
	size_t offset, index;

	index = (iova - mr->iova) / TARGET_PAGE_SIZE;
	offset = (iova - mr->iova) & ~PAGE_MASK;

	return mr->pages[index] + offset;
}

int
vhost_rdma_mr_copy(struct rte_vhost_memory *mem, struct vhost_rdma_mr *mr,
		uint64_t iova, void *addr, uint64_t length,enum vhost_rdma_mr_copy_dir dir,
		uint32_t *crcp)
{
	int err;
	uint64_t bytes;
	uint8_t *va;
	uint32_t crc = crcp ? (*crcp) : 0;

	if (length == 0)
		return 0;

	if (mr->type == VHOST_MR_TYPE_DMA) {
		uint8_t *src, *dest;
		// for dma addr, need to translate
		iova = gpa_to_vva(mem, iova, &length);

		src = (dir == VHOST_TO_MR_OBJ) ? addr : ((void *)(uintptr_t)iova);

		dest = (dir == VHOST_TO_MR_OBJ) ? ((void *)(uintptr_t)iova) : addr;

		rte_memcpy(dest, src, length);

		if (crcp)
			*crcp = crc32(*crcp, dest, length);

		return 0;
	}

	err = mr_check_range(mr, iova, length);
	if (err) {
		err = -EFAULT;
		goto err1;
	}

	while (length > 0) {
		uint8_t *src, *dest;

		va = (uint8_t *)lookup_iova(mr, iova);
		src = (dir == VHOST_TO_MR_OBJ) ? addr : va;
		dest = (dir == VHOST_TO_MR_OBJ) ? va : addr;

		bytes = TARGET_PAGE_SIZE - ((uint64_t)va & ~PAGE_MASK);

		if (bytes > length)
			bytes = length;

		RDMA_LOG_DEBUG_DP("copy %p <- %p %lu", dest, src, bytes);
		rte_memcpy(dest, src, bytes);

		if (crcp)
			crc = crc32(crc, dest, bytes);

		length -= bytes;
		addr += bytes;
		iova += bytes;
	}

	if (crcp)
		*crcp = crc;

	return 0;

err1:
	return err;
}

int
copy_data(struct vhost_rdma_pd *pd, int access,
	  struct vhost_rdma_dma_info *dma, void *addr,
	  int length, enum vhost_rdma_mr_copy_dir dir, uint32_t *crcp)
{
	uint32_t bytes;
	struct virtio_rdma_sge *sge = &dma->sge[dma->cur_sge];
	uint32_t offset = dma->sge_offset;
	int resid = dma->resid;
	struct vhost_rdma_mr *mr = NULL;
	uint64_t iova;
	int err;

	if (length == 0)
		return 0;

	if (length > resid) {
		err = -EINVAL;
		goto err2;
	}

	RDMA_LOG_DEBUG_DP("sge %llx %u offset %u %d", sge->addr, sge->length, offset, length);
	if (sge->length && (offset < sge->length)) {
		mr = lookup_mr(pd, access, sge->lkey, VHOST_LOOKUP_LOCAL);
		if (!mr) {
			err = -EINVAL;
			goto err1;
		}
	}

	while (length > 0) {
		bytes = length;

		if (offset >= sge->length) {
			if (mr) {
				vhost_rdma_drop_ref(mr, pd->dev, mr);
				mr = NULL;
			}
			sge++;
			dma->cur_sge++;
			offset = 0;

			if (dma->cur_sge >= dma->num_sge) {
				err = -ENOSPC;
				goto err2;
			}

			if (sge->length) {
				mr = lookup_mr(pd, access, sge->lkey, VHOST_LOOKUP_LOCAL);
				if (!mr) {
					err = -EINVAL;
					goto err1;
				}
			} else {
				continue;
			}
		}

		if (bytes > sge->length - offset)
			bytes = sge->length - offset;

		if (bytes > 0) {
			iova = sge->addr + offset;

			err = vhost_rdma_mr_copy(pd->dev->mem, mr, iova, addr, bytes, dir, crcp);
			if (err)
				goto err2;

			offset	+= bytes;
			resid	-= bytes;
			length	-= bytes;
			addr	+= bytes;
		}
	}

	dma->sge_offset = offset;
	dma->resid	= resid;

	if (mr)
		vhost_rdma_drop_ref(mr, pd->dev, mr);

	return 0;

err2:
	if (mr)
		vhost_rdma_drop_ref(mr, pd->dev, mr);
err1:
	return err;
}

void*
iova_to_vaddr(struct vhost_rdma_mr *mr, uint64_t iova, int length)
{
	size_t offset;
	uint64_t addr;

	if (mr->state != VHOST_MR_STATE_VALID) {
		RDMA_LOG_ERR_DP("mr not in valid state");
		return NULL;
	}

	if (!mr->pages) {
		return (void *)(uintptr_t)iova;
	}

	if (mr_check_range(mr, iova, length)) {
		RDMA_LOG_ERR_DP("range violation");
		return NULL;
	}

	addr = lookup_iova(mr, iova);
	offset = addr & ~PAGE_MASK;

	if (offset + length > TARGET_PAGE_SIZE) {
		RDMA_LOG_ERR_DP("crosses page boundary");
		return NULL;
	}

	return (void *)(uintptr_t)addr;
}

int
vhost_rdma_invalidate_mr(struct vhost_rdma_qp *qp, uint32_t rkey)
{
	struct vhost_rdma_dev *dev = qp->dev;
	struct vhost_rdma_mr *mr;
	int ret;

	mr = vhost_rdma_pool_get(&dev->mr_pool, rkey >> 8);
	if (!mr) {
		RDMA_LOG_ERR_DP("%s: No MR for rkey %#x\n", __func__, rkey);
		ret = -EINVAL;
		goto err;
	}
	vhost_rdma_add_ref(mr);

	if (rkey != mr->rkey) {
		RDMA_LOG_ERR_DP("%s: rkey (%#x) doesn't match mr->rkey (%#x)\n",
			__func__, rkey, mr->rkey);
		ret = -EINVAL;
		goto err_drop_ref;
	}

	mr->state = VHOST_MR_STATE_FREE;
	ret = 0;

err_drop_ref:
	vhost_rdma_drop_ref(mr, qp->dev, mr);
err:
	return ret;
}

int
advance_dma_data(struct vhost_rdma_dma_info *dma, unsigned int length)
{
	struct virtio_rdma_sge *sge = &dma->sge[dma->cur_sge];
	uint32_t offset = dma->sge_offset;
	int resid = dma->resid;

	while (length) {
		unsigned int bytes;

		if (offset >= sge->length) {
			sge++;
			dma->cur_sge++;
			offset = 0;
			if (dma->cur_sge >= dma->num_sge)
				return -ENOSPC;
		}

		bytes = length;

		if (bytes > sge->length - offset)
			bytes = sge->length - offset;

		offset	+= bytes;
		resid	-= bytes;
		length	-= bytes;
	}

	dma->sge_offset = offset;
	dma->resid	= resid;

	return 0;
}

void
vhost_rdma_mr_cleanup(void* arg)
{
	struct vhost_rdma_mr *mr = arg;

	mr->type = VHOST_MR_TYPE_NONE;
}
