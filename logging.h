/*
 * Vhost-user RDMA device demo: logging
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

#ifndef __LOGGING_H__
#define __LOGGING_H__

#include <rte_log.h>

#define RTE_LOGTYPE_ETHER RTE_LOGTYPE_USER1

#define LOG_DEBUG_DP(f, ...) RTE_LOG_DP(DEBUG, ETHER, f "\n", ##__VA_ARGS__)
#define LOG_INFO_DP(f, ...) RTE_LOG_DP(INFO, ETHER, f "\n", ##__VA_ARGS__)
#define LOG_WARN_DP(f, ...) RTE_LOG_DP(WARNING, ETHER, f "\n", ##__VA_ARGS__)
#define LOG_ERR_DP(f, ...) RTE_LOG_DP(ERR, ETHER, f "\n", ##__VA_ARGS__)

#define LOG_DEBUG(f, ...) RTE_LOG(DEBUG, ETHER, f "\n", ##__VA_ARGS__)
#define LOG_INFO(f, ...) RTE_LOG(INFO, ETHER, f "\n", ##__VA_ARGS__)
#define LOG_WARN(f, ...) RTE_LOG(WARNING, ETHER, f "\n", ##__VA_ARGS__)
#define LOG_ERR(f, ...) RTE_LOG(ERR, ETHER, f "\n", ##__VA_ARGS__)

#define RTE_LOGTYPE_RDMA RTE_LOGTYPE_USER2

#define RDMA_LOG_DEBUG(f, ...) RTE_LOG(DEBUG, RDMA, f "\n", ##__VA_ARGS__)
#define RDMA_LOG_INFO(f, ...) RTE_LOG(INFO, RDMA, f "\n", ##__VA_ARGS__)
#define RDMA_LOG_ERR(f, ...) RTE_LOG(ERR, RDMA, f "\n", ##__VA_ARGS__)

#ifdef DEBUG_RDMA_DP
#define RDMA_LOG_DEBUG_DP(f, ...) RTE_LOG(DEBUG, RDMA, "[%u] " f "\n", \
					  rte_lcore_id(), ##__VA_ARGS__)
#define RDMA_LOG_INFO_DP(f, ...) RTE_LOG(INFO, RDMA, "[%u] " f "\n", \
					 rte_lcore_id(), ##__VA_ARGS__)
#define RDMA_LOG_ERR_DP(f, ...) RTE_LOG(ERR, RDMA, "[%u] " f "\n", \
					rte_lcore_id(), ##__VA_ARGS__)
#else
#define RDMA_LOG_DEBUG_DP(f, ...) RTE_LOG_DP(DEBUG, RDMA, "[%u] " f "\n", \
					     rte_lcore_id(), ##__VA_ARGS__)
#define RDMA_LOG_INFO_DP(f, ...) RTE_LOG_DP(INFO, RDMA, "[%u] " f "\n", \
					    rte_lcore_id(), ##__VA_ARGS__)
#define RDMA_LOG_ERR_DP(f, ...) RTE_LOG_DP(ERR, RDMA, "[%u] " f "\n", \
					   rte_lcore_id(), ##__VA_ARGS__)
#endif

#define RTE_LOGTYPE_VNET RTE_LOGTYPE_USER3

#define VNET_LOG_DEBUG(f, ...) RTE_LOG(DEBUG, VNET, f "\n", ##__VA_ARGS__)
#define VNET_LOG_INFO(f, ...) RTE_LOG(INFO, VNET, f "\n", ##__VA_ARGS__)
#define VNET_LOG_ERR(f, ...) RTE_LOG(ERR, VNET, f "\n", ##__VA_ARGS__)

#endif
