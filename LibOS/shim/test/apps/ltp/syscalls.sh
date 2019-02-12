#!/usr/bin/env bash

cd `dirname $0`
export LTPROOT=$PWD"/opt/ltp"
awk -v SGX=$SGX_RUN -f edit_sys_tests.awk $LTPROOT/runtest/syscalls > syscalls.graphene 
cd $LTPROOT/../..
python fetch.py
