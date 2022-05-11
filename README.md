# VHOST-USER-RDMA

A vhost-user-rdma demo

## Build

* Download and install dpdk (we only tested with dpdk-stable-20.11.3).

* Build vhost-user-rdma
```bash
mkdir build
meson build
cd build
ninja
```

## Run

* Start vhost-user-rdma
```bash
sudo ./vhost-user-rdma --vdev 'net_tap0' --lcore '1-3' -- -s '/tmp/vhost-rdma0'
```

* Run QEMU [1] with command
```bash
qemu-system-x86_64 -chardev socket,path=/tmp/vhost-rdma0,id=vrdma \
    -device vhost-user-rdma-pci,page-per-vq,chardev=vrdma ...
```
[1] https://github.com/bytedance/qemu/tree/vhost-user-rdma

## DEBUG

Add following to `meson.build` to debug.

```
c_args: [
    '-DDEBUG_RDMA',
    '-DDEBUG_RDMA_DP',
    '-DDEBUG_ETHERNET',
]
```

* `DEBUG_RDMA`: RDMA control panel
* `DEBUG_RDMA_DP`: RDMA data panel
* `DEBUG_ETHERNET`: Ethernet
