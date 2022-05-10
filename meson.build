project('vhost-user-rdma', 'c',
  version : '0.1',
  default_options : [
    'warning_level=2',
    'werror=True',
  ]
)

dpdk = dependency('libdpdk')

executable('vhost-user-rdma',
  [
    'main.c',
    'virtio_net.c',
    'vhost_rdma.c',
    'verbs.c',
    'vhost_rdma_pool.c',
    'vhost_rdma_queue.c',
    'vhost_rdma_mr.c',
    'vhost_rdma_qp.c',
    'vhost_rdma_av.c',
    'vhost_rdma_ib.c',
  ],
  dependencies: dpdk,
  c_args: [
    '-DALLOW_EXPERIMENTAL_API',
    '-DDEBUG_RDMA',
    '-DDEBUG_RDMA_DP',
  ],
  install : false
)
