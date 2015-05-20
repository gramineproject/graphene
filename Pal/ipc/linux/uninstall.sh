#!/bin/bash

DIR=`readlink -f "${BASH_SOURCE[0]}"`
MOD=graphene-ipc
VER=0.0.1

/sbin/lsmod | grep -q graphene_ipc
if [ $? -eq 0 ]; then
	modprobe -r graphene-ipc
fi

/usr/sbin/dkms status | grep -q $MOD
if [ $? -eq 0 ]; then
	dkms remove $MOD/$VER --all
fi

rm -rf /usr/src/$MOD-$VER
