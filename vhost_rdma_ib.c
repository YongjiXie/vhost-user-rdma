/*
 * Vhost-user RDMA device demo: ib ops
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
#include <sys/uio.h>

#include <rte_ethdev.h>
#include <rte_spinlock.h>

#include "vhost_user.h"
#include "vhost_rdma.h"
#include "vhost_rdma_ib.h"
#include "vhost_rdma_pool.h"
#include "vhost_rdma_loc.h"
#include "virtio_rdma_abi.h"

#define CHK_IOVEC(tp, iov) \
	do { \
		if(iov->iov_len < sizeof(*tp)) { \
			RDMA_LOG_ERR("%s: " #iov " iovec is too small", __func__); \
			return -1; \
		} \
		tp = iov->iov_base; \
	} while(0); \

#define DEFINE_VIRTIO_RDMA_CMD(cmd, handler) [cmd] = {handler, #cmd}

#define CTRL_NO_CMD __rte_unused struct iovec *__in
#define CTRL_NO_RSP __rte_unused struct iovec *__out

static int
vhost_rdma_query_device(struct vhost_rdma_dev *dev, CTRL_NO_CMD,
			struct iovec *out)
{
	struct virtio_rdma_ack_query_device *rsp;

	CHK_IOVEC(rsp, out);

	rsp->max_mr_size = dev->attr.max_mr_size;
	rsp->page_size_cap = dev->attr.page_size_cap;
	rsp->max_qp_wr = dev->attr.max_qp_wr;
	rsp->device_cap_flags = dev->attr.device_cap_flags;
	rsp->max_send_sge = dev->attr.max_send_sge;
	rsp->max_recv_sge = dev->attr.max_recv_sge;
	rsp->max_sge_rd = dev->attr.max_sge_rd;
	rsp->max_cqe = dev->attr.max_cqe;
	rsp->max_mr = dev->attr.max_mr;
	rsp->max_pd = dev->attr.max_pd;
	rsp->max_qp_rd_atom = dev->attr.max_qp_rd_atom;
	rsp->max_qp_init_rd_atom = dev->attr.max_qp_init_rd_atom;
	rsp->max_ah = dev->attr.max_ah;
	rsp->local_ca_ack_delay = dev->attr.local_ca_ack_delay;

	return 0;
}

static int
vhost_rdma_query_port(__rte_unused struct vhost_rdma_dev *dev,
		      CTRL_NO_CMD, struct iovec *out)
{
	struct virtio_rdma_ack_query_port *rsp;

	CHK_IOVEC(rsp, out);

	rsp->gid_tbl_len = VHOST_MAX_GID_TBL_LEN;
	rsp->max_msg_sz = 0x800000;

	return 0;
}

static __rte_always_inline void
print_gid(struct vhost_rdma_gid *gid) {
        uint8_t *raw = &gid->gid[0];
        RDMA_LOG_DEBUG(
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        raw[0], raw[1], raw[2], raw[4], raw[5], raw[6], raw[7], raw[8],
        raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15], raw[16]);
}

static int
vhost_rdma_add_gid(struct vhost_rdma_dev *dev, struct iovec *in, CTRL_NO_RSP)
{
	struct virtio_rdma_cmd_add_gid *cmd;
	struct vhost_rdma_gid *gid;

	CHK_IOVEC(cmd, in);
	if (cmd->index >= VHOST_MAX_GID_TBL_LEN) {
		RDMA_LOG_ERR("gid index is too big");
		return -EINVAL;
	}

	RDMA_LOG_INFO("add gid %d", cmd->index);

	gid = &dev->gid_tbl[cmd->index];
	gid->type = IB_GID_TYPE_ROCE_UDP_ENCAP;

	rte_memcpy(gid->gid, cmd->gid, 16);

	print_gid(&dev->gid_tbl[cmd->index]);

	return 0;
}

static int
vhost_rdma_del_gid(struct vhost_rdma_dev *dev, struct iovec *in, CTRL_NO_RSP)
{
	struct virtio_rdma_cmd_del_gid *cmd;

	CHK_IOVEC(cmd, in);
	if (cmd->index >= VHOST_MAX_GID_TBL_LEN) {
		RDMA_LOG_ERR("gid index is too big");
		return -EINVAL;
	}

	RDMA_LOG_INFO("del gid %d", cmd->index);

	dev->gid_tbl[cmd->index].type = VHOST_RDMA_GID_TYPE_ILLIGAL;

	return 0;
}

static int
vhost_rdma_create_pd(struct vhost_rdma_dev *dev, CTRL_NO_CMD, struct iovec *out)
{
	struct virtio_rdma_ack_create_pd *rsp;
	struct vhost_rdma_pd *pd;
	uint32_t idx;

	CHK_IOVEC(rsp, out);

	pd = vhost_rdma_pool_alloc(&dev->pd_pool, &idx);
	if(pd == NULL) {
		return -ENOMEM;
	}
	vhost_rdma_ref_init(pd);

	RDMA_LOG_INFO("create pd %u", idx);
	pd->dev = dev;
	pd->pdn = idx;
	rsp->pdn = idx;

	return 0;
}

static int
vhost_rdma_destroy_pd(struct vhost_rdma_dev *dev, struct iovec *in, CTRL_NO_RSP)
{
	struct virtio_rdma_cmd_destroy_pd *cmd;
	struct vhost_rdma_pd *pd;

	CHK_IOVEC(cmd, in);

	pd = vhost_rdma_pool_get(&dev->pd_pool, cmd->pdn);
	vhost_rdma_drop_ref(pd, dev, pd);

	RDMA_LOG_INFO("destroy pd %u", cmd->pdn);

	return 0;
}

static int
vhost_rdma_get_dma_mr(struct vhost_rdma_dev *dev, struct iovec *in,
					struct iovec *out)
{
	struct virtio_rdma_cmd_get_dma_mr *cmd;
	struct virtio_rdma_ack_get_dma_mr *rsp;
	struct vhost_rdma_pd *pd;
	struct vhost_rdma_mr *mr;
	uint32_t mrn;

	CHK_IOVEC(cmd, in);
	CHK_IOVEC(rsp, out);

	pd = vhost_rdma_pool_get(&dev->pd_pool, cmd->pdn);
	if (unlikely(pd == NULL)) {
		RDMA_LOG_ERR("pd is not found");
		return -EINVAL;
	}

	mr = vhost_rdma_pool_alloc(&dev->mr_pool, &mrn);
	if (mr == NULL) {
		RDMA_LOG_ERR("mr alloc failed");
		return -ENOMEM;
	}

	vhost_rdma_ref_init(mr);
	vhost_rdma_add_ref(pd);

	mr->type = VHOST_MR_TYPE_DMA;
	mr->state = VHOST_MR_STATE_VALID;
	mr->access = cmd->access_flags;
	mr->pd = pd;
	vhost_rdma_mr_init_key(mr, mrn);
	mr->mrn = mrn;

	rsp->lkey = mr->lkey;
	rsp->rkey = mr->rkey;
	rsp->mrn = mrn;

	return 0;
}

static int
vhost_rdma_reg_user_mr(struct vhost_rdma_dev *dev, struct iovec *in,
					struct iovec *out)
{
	struct virtio_rdma_cmd_reg_user_mr *cmd;
	struct virtio_rdma_ack_reg_user_mr *rsp;
	struct vhost_rdma_mr *mr;
	struct vhost_rdma_pd *pd;
	uint32_t mrn;

	CHK_IOVEC(cmd, in);
	CHK_IOVEC(rsp, out);

	pd = vhost_rdma_pool_get(&dev->pd_pool, cmd->pdn);
	if (unlikely(pd == NULL)) {
		RDMA_LOG_ERR("pd is not found");
		return -EINVAL;
	}

	mr = vhost_rdma_pool_alloc(&dev->mr_pool, &mrn);
	if (mr == NULL) {
		return -ENOMEM;
	}

	mr->pages = malloc(sizeof(uint64_t) * cmd->npages);
	if (mr->pages == NULL) {
		return -ENOMEM;
	}

	vhost_rdma_ref_init(mr);
	vhost_rdma_add_ref(pd);

	vhost_rdma_map_pages(dev->mem, mr->pages, (uint64_t *)cmd->pages, cmd->npages);

	mr->pd = pd;
	mr->access = cmd->access_flags;
	mr->length = cmd->length;
	mr->iova = cmd->virt_addr & PAGE_MASK;
	mr->npages = cmd->npages;
	mr->type = VHOST_MR_TYPE_MR;
	mr->state = VHOST_MR_STATE_VALID;
	vhost_rdma_mr_init_key(mr, mrn);
	mr->mrn = mrn;

	rsp->lkey = mr->lkey;
	rsp->rkey = mr->rkey;
	rsp->mrn = mrn;

	return 0;
}

static int
vhost_rdma_dereg_mr(struct vhost_rdma_dev *dev, struct iovec *in, CTRL_NO_RSP)
{
	struct virtio_rdma_cmd_dereg_mr *cmd;
	struct vhost_rdma_mr *mr;

	CHK_IOVEC(cmd, in);

	mr = vhost_rdma_pool_get(&dev->mr_pool, cmd->mrn);
	if (unlikely(mr == NULL)) {
		RDMA_LOG_ERR("mr not found");
	}

	mr->state = VHOST_MR_STATE_ZOMBIE;

	vhost_rdma_drop_ref(mr->pd, dev, pd);
	vhost_rdma_drop_ref(mr, dev, mr);

	RDMA_LOG_DEBUG("destroy mr %u", cmd->mrn);

	return 0;
}

static int
vhost_rdma_create_cq(struct vhost_rdma_dev *dev, struct iovec *in,
					struct iovec *out)
{
	struct virtio_rdma_cmd_create_cq *cmd;
	struct virtio_rdma_ack_create_cq *rsp;
	struct vhost_rdma_cq *cq;
	uint32_t cqn;

	CHK_IOVEC(cmd, in);
	if (cmd->cqe > dev->attr.max_cqe) {
		return -EINVAL;
	}

	CHK_IOVEC(rsp, out);

	cq = vhost_rdma_pool_alloc(&dev->cq_pool, &cqn);
	if (cq == NULL) {
		RDMA_LOG_ERR("cq alloc failed");
	}
	vhost_rdma_ref_init(cq);

	rte_spinlock_init(&cq->cq_lock);
	cq->is_dying = false;
	cq->notify = 0;
	cq->vq = &dev->cq_vqs[cqn];
	cq->cqn = cqn;

	rsp->cqn = cqn;
	RDMA_LOG_INFO("create cq %u", cqn);

	return 0;
}

static int
vhost_rdma_destroy_cq(struct vhost_rdma_dev *dev, struct iovec *in, CTRL_NO_RSP)
{
	struct virtio_rdma_cmd_destroy_cq *cmd;
	struct vhost_rdma_cq *cq;

	CHK_IOVEC(cmd, in);

	cq = vhost_rdma_pool_get(&dev->cq_pool, cmd->cqn);

	rte_spinlock_lock(&cq->cq_lock);
	cq->is_dying = true;
	cq->vq->last_avail_idx = 0;
	cq->vq->last_used_idx = 0;
	rte_spinlock_unlock(&cq->cq_lock);

	vhost_rdma_drop_ref(cq, dev, cq);

	RDMA_LOG_DEBUG("destroy cq %u", cmd->cqn);

	return 0;
}

static int
vhost_rdma_req_notify(struct vhost_rdma_dev *dev, struct iovec *in, CTRL_NO_RSP)
{
	struct virtio_rdma_cmd_req_notify *cmd;
	struct vhost_rdma_cq *cq;

	CHK_IOVEC(cmd, in);

	cq = vhost_rdma_pool_get(&dev->cq_pool, cmd->cqn);
	if (unlikely(cq == NULL)) {
		RDMA_LOG_ERR("cq not found");
		return -EINVAL;
	}

	cq->notify = cmd->flags;

	return 0;
}

static int
vhost_rdma_create_qp(struct vhost_rdma_dev *dev, struct iovec *in,
					struct iovec *out)
{
	struct virtio_rdma_cmd_create_qp *cmd;
	struct virtio_rdma_ack_create_qp *rsp;
	struct vhost_rdma_qp *qp;
	uint32_t qpn;

	CHK_IOVEC(cmd, in);
	CHK_IOVEC(rsp, out);

	switch (cmd->qp_type) {
	case VIRTIO_IB_QPT_GSI:
		if (dev->qp_gsi->valid)
			return -EINVAL;
		qp = dev->qp_gsi;
		qpn = 1;
		break;
	case VIRTIO_IB_QPT_RC:
	case VIRTIO_IB_QPT_UD:
	case VIRTIO_IB_QPT_UC:
		qp = vhost_rdma_pool_alloc(&dev->qp_pool, &qpn);
		break;
	default:
		return -EINVAL;
	}

	if (qp == NULL) {
		return -ENOMEM;
	}
	vhost_rdma_ref_init(qp);

	qp->qpn = qpn;

	if (vhost_rdma_qp_init(dev, qp, cmd)) {
		RDMA_LOG_ERR("init qp failed");
		vhost_rdma_drop_ref(qp, dev, qp);
		return -EINVAL;
	}

	rsp->qpn = qpn;

	RDMA_LOG_INFO("create qp %u type: %d", qp->qpn, cmd->qp_type);

	return 0;
}

static int
vhost_rdma_destroy_qp(struct vhost_rdma_dev *dev, struct iovec *in, CTRL_NO_RSP)
{
	struct virtio_rdma_cmd_destroy_qp *cmd;
	struct vhost_rdma_qp* qp;

	CHK_IOVEC(cmd, in);

	qp = vhost_rdma_pool_get(&dev->qp_pool, cmd->qpn);

	vhost_rdma_qp_destroy(qp);

	if (qp->type != VIRTIO_IB_QPT_GSI)
		vhost_rdma_drop_ref(qp, dev, qp);

	RDMA_LOG_DEBUG("destroy qp %u", cmd->qpn);

	return 0;
}

static int
vhost_rdma_query_qp(struct vhost_rdma_dev *dev, struct iovec *in,
		    struct iovec *out)
{
	struct virtio_rdma_cmd_query_qp *cmd;
	struct virtio_rdma_ack_query_qp *rsp;
	struct vhost_rdma_qp *qp;

	CHK_IOVEC(cmd, in);
	CHK_IOVEC(rsp, out);

	qp = vhost_rdma_pool_get(&dev->qp_pool, cmd->qpn);
	vhost_rdma_qp_query(qp, rsp);

	return 0;
}

static int
vhost_rdma_modify_qp(struct vhost_rdma_dev *dev, struct iovec *in, CTRL_NO_RSP)
{
	struct virtio_rdma_cmd_modify_qp *cmd;
	struct vhost_rdma_qp *qp;
	int err;

	CHK_IOVEC(cmd, in);

	qp = vhost_rdma_pool_get(&dev->qp_pool, cmd->qpn);
	if (unlikely(qp == NULL)) {
		RDMA_LOG_ERR("qp not found");
	}

	RDMA_LOG_INFO("modify qp %u", qp->qpn);

	// FIXME: check in driver?
	err = vhost_rdma_qp_validate(dev, qp, cmd);
	if (err)
		goto err;

	err = vhost_rdma_qp_modify(dev, qp, cmd);
	if (err)
		goto err;

	return 0;

err:
	return err;
}

static int
vhost_rdma_create_ah(struct vhost_rdma_dev *dev, struct iovec *in,
		     struct iovec *out)
{
	struct virtio_rdma_cmd_create_ah *cmd;
	struct virtio_rdma_ack_create_ah *rsp;
	struct vhost_rdma_av *av;
	uint32_t ah_num;

	CHK_IOVEC(cmd, in);
	CHK_IOVEC(rsp, out);

	if (!vhost_rdma_pool_get(&dev->pd_pool, cmd->pdn))
		return -EINVAL;

	av = vhost_rdma_pool_alloc(&dev->ah_pool, &ah_num);
	if (av == NULL) {
		return -ENOMEM;
	}

	vhost_rdma_init_av(dev, &cmd->ah_attr, av);
	rsp->ah = ah_num;

	RDMA_LOG_INFO("create ah %u", ah_num);

	return 0;
}

static int
vhost_rdma_destroy_ah(struct vhost_rdma_dev *dev, struct iovec *in, CTRL_NO_RSP)
{
	struct virtio_rdma_cmd_destroy_ah *cmd;
	struct vhost_rdma_av *av;

	CHK_IOVEC(cmd, in);

	av = vhost_rdma_pool_get(&dev->ah_pool, cmd->ah);
	if (av == NULL) {
		return -EINVAL;
	}
	vhost_rdma_pool_free(&dev->ah_pool, cmd->ah);

	RDMA_LOG_INFO("destroy ah %u", cmd->ah);

	return 0;
}

struct {
    int (*handler)(struct vhost_rdma_dev *dev, struct iovec *in,
					struct iovec *out);
    const char* name;
} cmd_tbl[] = {
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_NET_CTRL_ROCE_QUERY_DEVICE, vhost_rdma_query_device),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_NET_CTRL_ROCE_QUERY_PORT, vhost_rdma_query_port),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_NET_CTRL_ROCE_CREATE_CQ, vhost_rdma_create_cq),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_NET_CTRL_ROCE_DESTROY_CQ, vhost_rdma_destroy_cq),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_NET_CTRL_ROCE_CREATE_PD, vhost_rdma_create_pd),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_NET_CTRL_ROCE_DESTROY_PD, vhost_rdma_destroy_pd),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_NET_CTRL_ROCE_GET_DMA_MR, vhost_rdma_get_dma_mr),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_NET_CTRL_ROCE_REG_USER_MR, vhost_rdma_reg_user_mr),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_NET_CTRL_ROCE_DEREG_MR, vhost_rdma_dereg_mr),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_NET_CTRL_ROCE_CREATE_QP, vhost_rdma_create_qp),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_NET_CTRL_ROCE_MODIFY_QP, vhost_rdma_modify_qp),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_NET_CTRL_ROCE_QUERY_QP, vhost_rdma_query_qp),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_NET_CTRL_ROCE_DESTROY_QP, vhost_rdma_destroy_qp),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_NET_CTRL_ROCE_CREATE_AH, vhost_rdma_create_ah),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_NET_CTRL_ROCE_DESTROY_AH, vhost_rdma_destroy_ah),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_NET_CTRL_ROCE_ADD_GID, vhost_rdma_add_gid),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_NET_CTRL_ROCE_DEL_GID, vhost_rdma_del_gid),
    DEFINE_VIRTIO_RDMA_CMD(VIRTIO_NET_CTRL_ROCE_REQ_NOTIFY_CQ, vhost_rdma_req_notify),
};

void
vhost_rdma_handle_ctrl(void* arg) {
	struct vhost_rdma_dev* dev = arg;
	struct virtio_net_ctrl_hdr *hdr;
	virtio_net_ctrl_ack *status;
	struct vhost_queue *ctrl_vq = &dev->rdma_vqs[0];
	int kick_fd, nbytes, i, in_len;
	eventfd_t kick_data;
	struct iovec iovs[4];
	uint16_t desc_idx, num_in, num_out;
	struct iovec *in_iovs, *out_iovs;

	/* consume eventfd data */
	kick_fd = ctrl_vq->vring.kickfd;
	do {
		nbytes = eventfd_read(kick_fd, &kick_data);
		if (nbytes < 0) {
			if (errno == EINTR ||
				errno == EWOULDBLOCK ||
				errno == EAGAIN) {
				continue;
			}
			RDMA_LOG_ERR("Failed to read kickfd of ctrl virtq: %s",
				strerror(errno));
		}
		break;
	} while (1);

	while(vhost_vq_is_avail(ctrl_vq)) {
		desc_idx = vq_get_desc_idx(ctrl_vq);

		if (setup_iovs_from_descs(dev->mem, ctrl_vq, desc_idx, iovs, 4,
			&num_in, &num_out) < 0) {
			RDMA_LOG_ERR("read from desc failed");
			break;
		}

		out_iovs = iovs;
		in_iovs = &iovs[num_out];

		in_len = 0;
		for (i = 0; i < num_in; i++) {
			in_len += in_iovs[i].iov_len;
		}

		hdr = out_iovs[0].iov_base;
		status = in_iovs[0].iov_base;

		if (out_iovs[0].iov_len != sizeof(*hdr)) {
			RDMA_LOG_ERR("invalid header");
			*status = VIRTIO_NET_ERR;
			goto pushq;
		}

		if (hdr->cmd >= (sizeof(cmd_tbl) / sizeof(cmd_tbl[0]))) {
			RDMA_LOG_ERR("unknown cmd %d", hdr->cmd);
			*status = VIRTIO_NET_ERR;
			goto pushq;
		}

		if (!cmd_tbl[hdr->cmd].handler) {
			RDMA_LOG_ERR("no handler for cmd %d\n", hdr->cmd);
			*status = VIRTIO_NET_ERR;
			goto pushq;
		}

		*status = (cmd_tbl[hdr->cmd].handler(dev,
				num_out > 1 ? &out_iovs[1] : NULL,
				num_in > 1 ? &in_iovs[1] : NULL) == 0) ?
				VIRTIO_NET_OK : VIRTIO_NET_ERR;

pushq:
		RDMA_LOG_INFO("cmd=%d %s status: %d", hdr->cmd,
				cmd_tbl[hdr->cmd].name, *status);
		vhost_queue_push(ctrl_vq, desc_idx, in_len);
		vhost_queue_notify(dev->vid, ctrl_vq);
	}
}

void
vhost_rdma_init_ib(struct vhost_rdma_dev *dev) {
	uint32_t qpn;

	dev->config.max_rdma_qps = 64;
	dev->config.max_rdma_cqs = 64;

	dev->attr.max_mr_size = -1ull;
	dev->attr.page_size_cap = 0xfffff000;
	dev->attr.max_qp_wr = 1024;
	dev->attr.device_cap_flags = VIRTIO_IB_DEVICE_RC_RNR_NAK_GEN;
	dev->attr.max_send_sge = 32;
	dev->attr.max_recv_sge = 32;
	dev->attr.max_sge_rd = 32;
	dev->attr.max_cqe = 1024;
	dev->attr.max_mr = 0x00001000;
	dev->attr.max_mw = 0;
	dev->attr.max_pd = 0x7ffc;
	dev->attr.max_qp_rd_atom = 128;
	dev->attr.max_qp_init_rd_atom = 128;
	dev->attr.max_ah = 100;
	dev->attr.max_fast_reg_page_list_len = 512;
	dev->attr.local_ca_ack_delay = 15;

	dev->max_inline_data = dev->attr.max_send_sge *
					sizeof(struct virtio_rdma_sge);

	dev->mtu_cap = ib_mtu_enum_to_int(DEFAULT_IB_MTU);

	dev->port_attr.bad_pkey_cntr = 0;
	dev->port_attr.qkey_viol_cntr = 0;

	for (int i = 0; i < VHOST_MAX_GID_TBL_LEN; i++) {
		dev->gid_tbl[i].type = VHOST_RDMA_GID_TYPE_ILLIGAL;
	}

	dev->cq_vqs = &dev->rdma_vqs[1];
	dev->qp_vqs = &dev->rdma_vqs[1 + dev->config.max_rdma_cqs];

	vhost_rdma_pool_init(&dev->pd_pool, "pd_pool", dev->attr.max_pd,
				sizeof(struct vhost_rdma_pd), false, NULL);
	vhost_rdma_pool_init(&dev->mr_pool, "mr_pool", dev->attr.max_mr,
				sizeof(struct vhost_rdma_mr), false, vhost_rdma_mr_cleanup);
	vhost_rdma_pool_init(&dev->cq_pool, "cq_pool", dev->config.max_rdma_cqs,
				sizeof(struct vhost_rdma_cq), true, NULL);
	vhost_rdma_pool_init(&dev->qp_pool, "qp_pool", dev->config.max_rdma_qps,
				sizeof(struct vhost_rdma_qp), false, vhost_rdma_qp_cleanup);
	vhost_rdma_pool_init(&dev->ah_pool, "ah_pool", dev->attr.max_ah,
				sizeof(struct vhost_rdma_av), false, NULL);
	dev->qp_gsi = vhost_rdma_pool_alloc(&dev->qp_pool, &qpn);
	vhost_rdma_add_ref(dev->qp_gsi);
	assert(qpn == 1);
}

void
vhost_rdma_destroy_ib(struct vhost_rdma_dev *dev) {
	struct vhost_rdma_mr *mr;
	struct vhost_rdma_pd *pd;
	struct vhost_rdma_cq *cq;
	struct vhost_rdma_qp *qp;
	struct vhost_rdma_av *av;
	uint32_t i = 0;

	for (i = 0; i < dev->attr.max_mr; i++) {
		mr = vhost_rdma_pool_get(&dev->mr_pool, i);
		if (mr)
			vhost_rdma_pool_free(&dev->mr_pool, i);
	}

	for (i = 0; i < dev->attr.max_pd; i++) {
		pd = vhost_rdma_pool_get(&dev->pd_pool, i);
		if (pd)
			vhost_rdma_pool_free(&dev->pd_pool, i);
	}

	for (i = 0; i < dev->config.max_rdma_cqs; i++) {
		cq = vhost_rdma_pool_get(&dev->cq_pool, i);
		if (cq)
			vhost_rdma_pool_free(&dev->cq_pool, i);
	}

	for (i = 0; i < dev->config.max_rdma_qps; i++) {
		qp = vhost_rdma_pool_get(&dev->qp_pool, i);
		if (qp) {
			vhost_rdma_pool_free(&dev->qp_pool, i);
		}
	}

	for (i = 0; i < dev->attr.max_ah; i++) {
		av = vhost_rdma_pool_get(&dev->ah_pool, i);
		if (av)
			vhost_rdma_pool_free(&dev->ah_pool, i);
	}

	vhost_rdma_pool_destroy(&dev->mr_pool);
	vhost_rdma_pool_destroy(&dev->pd_pool);
	vhost_rdma_pool_destroy(&dev->cq_pool);
	vhost_rdma_pool_destroy(&dev->qp_pool);
	vhost_rdma_pool_destroy(&dev->ah_pool);
}
