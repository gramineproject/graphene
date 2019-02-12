#!/usr/bin/env bash

SCRIPT=`readlink -f "${BASH_SOURCE[0]}"`
DIR=`dirname $SCRIPT`
MOD=graphene-ipc
MODNAME=graphene_ipc
VER=0.0.1

/sbin/lsmod | grep -q $MODNAME
if [ $? -eq 0 ]; then
	echo "$MOD already running"
	exit 0
fi

/usr/sbin/dkms status | grep -q $MOD
if [ $? -eq 0 ]; then
	modprobe $MOD || exit $?
	echo "$MOD loaded"
	exit 0
fi

dkms add $DIR || exit $?

dkms build -m $MOD -v $VER
if [ $? -ne 0 ]; then
	err=$?
	rm -rf /usr/src/$MOD-$VER
	exit $err
fi

dkms install -m $MOD -v $VER
if [ $? -ne 0 ]; then
	err=$?
	dkms remove $MOD/$VER --all
	rm -rf /usr/src/$MOD-$VER
	exit $err
fi

modprobe $MOD || exit $?
echo "$MOD loaded"
