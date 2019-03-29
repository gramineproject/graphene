#!/usr/bin/env python2

import os, sys, mmap
from regression import Regression

loader = sys.argv[1]
try:
    sgx = os.environ['SGX_RUN']
except KeyError:
    sgx = False

# Running Bootstrap
regression = Regression(loader, "getdents", None, 10000)

# This doesn't catch extraneous entries, but should be fine
# until the LTP test can be run (need symlink support)
regression.add_check(name="Directory listing (32-bit)",
    check=lambda res: "getdents: setup ok" in res[0].out and \
                      "getdents32: . [0x4]" in res[0].out and \
                      "getdents32: .. [0x4]" in res[0].out and \
                      "getdents32: file1 [0x8]" in res[0].out and \
                      "getdents32: file2 [0x8]" in res[0].out and \
                      "getdents32: dir3 [0x4]" in res[0].out)

regression.add_check(name="Directory listing (64-bit)",
    check=lambda res: "getdents: setup ok" in res[0].out and \
                      "getdents64: . [0x4]" in res[0].out and \
                      "getdents64: .. [0x4]" in res[0].out and \
                      "getdents64: file1 [0x8]" in res[0].out and \
                      "getdents64: file2 [0x8]" in res[0].out and \
                      "getdents64: dir3 [0x4]" in res[0].out)

regression.run_checks()
