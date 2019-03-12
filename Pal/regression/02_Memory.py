#!/usr/bin/env python2

import os, sys, mmap
from regression import Regression

loader = os.environ['PAL_LOADER']
try:
    sgx = os.environ['SGX_RUN']
except KeyError:
    sgx = 0

regression = Regression(loader, "Memory")

regression.add_check(name="Memory Allocation",
    check=lambda res: "Memory Allocation OK" in res[0].log)

regression.add_check(name="Memory Allocation with Address",
    check=lambda res: "Memory Allocation with Address OK" in res[0].log)

# Memory protection and deallocation can't be tested on SGX since we can't
# unmap a page or change its protection (SGX2 makes this possible).
if not sgx:
    regression.add_check(name="Memory Protection",
        check=lambda res: "Memory Allocation Protection (RW) OK" in res[0].log and
                          "Memory Protection (R) OK" in res[0].log)

    regression.add_check(name="Memory Deallocation",
        check=lambda res: "Memory Deallocation OK" in res[0].log)

def check_quota(res):
    for line in res[0].log:
        if line.startswith("Total Memory:"):
            return line != "Total Memory: 0"
    return False

regression.add_check(name="Get Memory Total Quota", check=check_quota)

regression.add_check(name="Get Memory Available Quota",
    check=lambda res: "Get Memory Available Quota OK" in res[0].log)

rv = regression.run_checks()
if rv: sys.exit(rv)
