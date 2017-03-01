#!/bin/bash -e

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SGX_DRV_DIR=$ROOT/../linux-sgx-driver

sudo apt install build-essential gawk autoconf python-protobuf python-crypto

pushd Pal/src

make SGX=1

pushd host/Linux-SGX/sgx-driver
echo $SGX_DRV_DIR | sudo ./load.sh
popd

popd

pushd LibOS
make
popd 

sudo sysctl vm.mmap_min_addr=0
