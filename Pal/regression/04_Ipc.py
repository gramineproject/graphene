#!/usr/bin/env python2

import os, sys, mmap
from regression import Regression

loader = os.environ['PAL_LOADER']
try:
    sgx = os.environ['SGX_RUN']
except KeyError:
    sgx = 0
    
if sgx:
    print "Bulk IPC not supported on SGX"
    exit(0)

## XXX Should really be running these tests as part of CI 
if not os.path.exists('/dev/gipc'):
    print "GIPC not loaded; skipping these tests\n"
    exit(0)
    
def prepare_files(args):
    with open("ipc_mapping.tmp", "w") as f:
        f.write("Hello World")
        os.ftruncate(f.fileno(), mmap.PAGESIZE)

regression = Regression(loader, "Ipc", prepare_files)

def check_times(target, lines, times):
    count = 0
    for line in lines:
        if target == line:
            count += 1
    return count == times

regression.add_check(name="Create and Join Physical Memory Bulk Copy Store",
    check=lambda res: check_times("Create Physical Memory Store OK", res[0].log, 5) and
                      check_times("Join Physical Memory Store OK",   res[0].log, 5))

regression.add_check(name="Map and Commit Anonymous Physical Memory",
    check=lambda res: "[Test 1] Physical Memory Commit OK" in res[0].log and
                      "[Test 1] Physical Memory Map   : Hello World" in res[0].log)

regression.add_check(name="Transfer Anonymous Physical Memory as Copy-on-Write",
    check=lambda res: "[Test 1] Sender   After  Commit: Hello World, Alice" in res[0].log and
                      "[Test 1] Sender   Before Map   : Alice, Hello World" in res[0].log and
                      "[Test 1] Receiver After  Map   : Hello World, Bob"   in res[0].log and
                      "[Test 1] Sender   After  Map   : Alice, Hello World" in res[0].log)

regression.add_check(name="Map and Commit Untouched Physical Memory",
    check=lambda res: "[Test 2] Physical Memory Commit OK" in res[0].log and
                      "[Test 2] Physical Memory Map   : "                   in res[0].log and
                      "[Test 2] Sender   After  Commit: Hello World, Alice" in res[0].log and
                      "[Test 2] Sender   Before Map   : Alice, Hello World" in res[0].log and
                      "[Test 2] Receiver After  Map   : Hello World, Bob"   in res[0].log and
                      "[Test 2] Sender   After  Map   : Alice, Hello World" in res[0].log)

regression.add_check(name="Map and Commit File-Backed Physical Memory",
    check=lambda res: "[Test 3] Physical Memory Commit OK" in res[0].log and
                      "[Test 3] Physical Memory Map   : Hello World"        in res[0].log and
                      "[Test 3] Sender   After  Commit: Hello World"        in res[0].log and
                      "[Test 3] Receiver After  Map   : Hello World, Bob"   in res[0].log and
                      "[Test 3] Sender   After  Map   : Hello World"        in res[0].log)

regression.add_check(name="Map and Commit File-Backed Physical Memory Beyond File Size",
    check=lambda res: "[Test 4] Physical Memory Commit OK" in res[0].log and
                      "[Test 4] Physical Memory Map   : Memory Fault" in res[0].log)

regression.add_check(name="Map and Commit Huge Physical Memory",
    check=lambda res: "[Test 5] Physical Memory Commit OK" in res[0].log and
                      "[Test 5] Physical Memory Map   : Hello World" in res[0].log)

rv = regression.run_checks()
if rv: sys.exit(rv)
