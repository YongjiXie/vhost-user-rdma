/*
 * Vhost-user RDMA device demo: init and packets forwarding
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

#include <signal.h>
#include <getopt.h>

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_log.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include "virtio_net.h"
#include "vhost_rdma.h"
#include "logging.h"

static struct rte_eth_conf port_conf_default;
static struct rte_eth_conf port_conf_offload = {
	.txmode = {
		.offloads = DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM,
	},
};

static struct rte_mempool *mbuf_pool;

static char dev_pathname[PATH_MAX] = "/tmp/vhost-rdma0";

uint16_t pair_port_id;

volatile bool force_quit;

struct udpv4_hdr {
	struct rte_ether_hdr ether;
	struct rte_ipv4_hdr ipv4;
	struct rte_udp_hdr udp;
} __rte_aligned(2);

struct udpv6_hdr {
	struct rte_ether_hdr ether;
	struct rte_ipv6_hdr ipv6;
	struct rte_udp_hdr udp;
} __rte_aligned(2);

/*
 * there is no need to change mac address of pkts,
 * because the pair dev is transparent
 */

/* vhost --> pair_dev */
static __rte_always_inline void
eth_rx() {
	struct rte_mbuf *pkts[MAX_PKTS_BURST];
	uint16_t nb_rx_pkts, nb_tx_pkts;

	/* send ethernet pkts */
	nb_rx_pkts = vs_dequeue_pkts(VHOST_NET_TXQ, mbuf_pool, pkts, MAX_PKTS_BURST);
	if (nb_rx_pkts != 0) {
#ifdef DEBUG_ETHERNET
		LOG_DEBUG("rx got %d packets", nb_rx_pkts);
		for (int i = 0; i < nb_rx_pkts; i++) {
			struct rte_ether_hdr *eth;
			char sbuf[RTE_ETHER_ADDR_FMT_SIZE];
			char dbuf[RTE_ETHER_ADDR_FMT_SIZE];
			eth = rte_pktmbuf_mtod(pkts[i], struct rte_ether_hdr *);
			rte_ether_format_addr(sbuf, RTE_ETHER_ADDR_FMT_SIZE, &eth->s_addr);
			rte_ether_format_addr(dbuf, RTE_ETHER_ADDR_FMT_SIZE, &eth->d_addr);
			LOG_DEBUG(" -> : 0x%x %s %s", rte_be_to_cpu_16(eth->ether_type), sbuf, dbuf);
		}
#endif

		nb_tx_pkts = rte_eth_tx_burst(pair_port_id, 0, pkts, nb_rx_pkts);
		if (unlikely(nb_tx_pkts < nb_rx_pkts)) {
			uint16_t buf;

			for (buf = nb_tx_pkts; buf < nb_rx_pkts; buf++)
				rte_pktmbuf_free(pkts[buf]);
			LOG_DEBUG_DP("rx drop %d pkts", nb_rx_pkts - nb_tx_pkts);
		}
	}
}

/*
 * pair_dev --> vhost
 * WARNING: ip reassemble is NOT supported now
 */
static __rte_always_inline void
eth_tx() {
	struct rte_mbuf *pkts[MAX_PKTS_BURST];
	uint16_t nb_rx_pkts;

	nb_rx_pkts = rte_eth_rx_burst(pair_port_id, 0, pkts, MAX_PKTS_BURST);
	if (nb_rx_pkts == 0) {
		return;
	}

#ifdef DEBUG_ETHERNET
	LOG_DEBUG("tx got %d packets", nb_rx_pkts);
	for (int i = 0; i < nb_rx_pkts; i++) {
		struct rte_ether_hdr *eth;
		char sbuf[RTE_ETHER_ADDR_FMT_SIZE];
		char dbuf[RTE_ETHER_ADDR_FMT_SIZE];
		eth = rte_pktmbuf_mtod(pkts[i], struct rte_ether_hdr *);
		rte_ether_format_addr(sbuf, RTE_ETHER_ADDR_FMT_SIZE, &eth->s_addr);
		rte_ether_format_addr(dbuf, RTE_ETHER_ADDR_FMT_SIZE, &eth->d_addr);
		LOG_DEBUG(" <- : 0x%x %s %s", rte_be_to_cpu_16(eth->ether_type), sbuf, dbuf);
	}
#endif

	for (int i = 0; i < nb_rx_pkts; i++) {
		/* forward pkt to vhost_net */
		if (unlikely(vs_enqueue_pkts(VHOST_NET_RXQ, &pkts[i], 1) != 1)) {
			rte_pktmbuf_free(pkts[i]);
			LOG_DEBUG_DP("tx drop one pkt");
		}
	}
}

static int
eth_main_loop(__rte_unused void* arg) {
	LOG_INFO("ethernet main loop started");
	while (!force_quit && g_vhost_rdma_dev.state < VHOST_STATE_STOPPED) {
		eth_rx();

		eth_tx();
	}
	g_vhost_rdma_dev.state = VHOST_STATE_REMOVED;
	LOG_INFO("ethernet main loop quit");
	return 0;
}

static void
signal_handler(__rte_unused int signum)
{
	force_quit = true;
}

static int
init_port(uint16_t port_id, bool offload) {
	int ret;
	uint16_t nb_rxd = 1024;
	uint16_t nb_txd = 1024;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;
	struct rte_ether_addr addr;
	struct rte_eth_conf port_conf = offload ? port_conf_offload: port_conf_default;
	char buf[RTE_ETHER_ADDR_FMT_SIZE];

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret < 0)
		goto out;

	ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
	if (ret < 0)
		goto out;

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
	if (ret < 0)
		goto out;

	ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
				rte_eth_dev_socket_id(port_id), NULL,
				mbuf_pool);
	if (ret < 0)
		goto out;

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd,
				rte_eth_dev_socket_id(port_id), &txconf);
	if (ret < 0)
		goto out;

	ret = rte_eth_dev_start(port_id);
	if (ret < 0)
		goto out;

	ret = rte_eth_promiscuous_enable(port_id);
	if (ret < 0)
		goto out;

	ret = rte_eth_macaddr_get(port_id, &addr);
	if (ret < 0)
		goto out;

	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, &addr);
	LOG_INFO("port %d MAC %s", port_id, buf);

out:
	return ret;
}

static int
parse_args(int argc, char **argv)
{
	int opt;
	int option_index;
	static struct option lgopts[] = {
		{"sock-path", required_argument, 0, 256},
		{NULL, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "s:",
				lgopts, &option_index)) != EOF) {
		switch (opt) {
		/* socket path */
		case 's':
		case 256:
			rte_strscpy(dev_pathname, optarg, PATH_MAX);
			break;

		default:
			LOG_ERR("unknown option");
			return -1;
		}
	}

	return 0;
}

int
main(int argc, char **argv)
{
	int ret;
	uint16_t port_id;
	struct rte_eth_dev_info dev_info;
	bool pair_found = false;

	signal(SIGINT, signal_handler);

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	rte_log_set_global_level(RTE_LOG_NOTICE);
#ifdef DEBUG_ETHERNET
	rte_log_set_global_level(RTE_LOG_DEBUG);
	rte_log_set_level_pattern("lib.vhost.*", RTE_LOG_NOTICE);
	rte_log_set_level(RTE_LOGTYPE_ETHER, RTE_LOG_DEBUG);
#endif

#ifdef DEBUG_RDMA
	rte_log_set_global_level(RTE_LOG_DEBUG);
	rte_log_set_level_pattern("lib.vhost.*", RTE_LOG_NOTICE);
	rte_log_set_level(RTE_LOGTYPE_RDMA, RTE_LOG_DEBUG);
#endif

	argc -= ret;
	argv += ret;

	if (parse_args(argc, argv) != 0) {
		rte_exit(EXIT_FAILURE, "failed to parse args\n");
	}

	if (rte_lcore_count() < 2) {
		rte_exit(EXIT_FAILURE,
		"Not enough cores, expecting at least 2\n"
		"\tcore 0:   ethernet packages forwarding\n"
		"\tcore 1-n: rdma ctrl thread\n"
		);
	}

	/* init mempool */
	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", 65535,
			250, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));

	/* init eth_dev */
	RTE_ETH_FOREACH_DEV(port_id) {
		rte_eth_dev_info_get(port_id, &dev_info);

		if (!pair_found && strcmp(dev_info.driver_name, "net_tap") == 0) {
			pair_port_id = port_id;
			pair_found = true;
			if (init_port(port_id, true) != 0) {
				rte_exit(EXIT_FAILURE, "%s\n", rte_strerror(rte_errno));
			}
			LOG_INFO("use %s(%d) as pair dev", dev_info.device->name, port_id);
		}
	}

	if (!pair_found)
		rte_exit(EXIT_FAILURE, "tap dev not found");

	/* init vhost rdma */
	vhost_rdma_construct(dev_pathname);

	rte_vhost_driver_start(dev_pathname);

	/* launch ether main loop to forward pkts */
	eth_main_loop(NULL);

	rte_eal_mp_wait_lcore();

	vhost_rdma_destroy(dev_pathname);

	rte_eal_cleanup();

	return 0;
}
