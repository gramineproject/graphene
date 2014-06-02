#!/bin/sh

module="graphene-ipc"

(/sbin/lsmod | grep -q "graphene_ipc") && \
((echo "unloading graphene_ipc..."; /sbin/rmmod graphene_ipc) || exit 1) || continue

# invoke insmod with all arguments we got
# and use a pathname, as newer modutils don't look in . by default
echo "loading graphene_ipc..."
/sbin/insmod ./$module.ko $* || exit 1
