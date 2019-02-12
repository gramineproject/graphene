#!/usr/bin/env bash

MOD=graphene-ipc
MODNAME=graphene_ipc

(/sbin/lsmod | grep -q $MODNAME) && \
((echo "unloading $MODNAME..."; /sbin/rmmod $MODNAME) || exit 1) || continue

# invoke insmod with all arguments we got
# and use a pathname, as newer modutils don't look in . by default
echo "loading $MODNAME..."
/sbin/insmod ./$MOD.ko $* || exit 1
