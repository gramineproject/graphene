#!/usr/bin/env python2

import os, sys, mmap
from regression import Regression

loader = sys.argv[1]
sgx = os.environ.get('SGX_RUN') == '1'

# Running Bootstrap
regression = Regression(loader, "mmap-file", None, 60000)

regression.add_check(name="Private mmap beyond file range",
    check=lambda res: "mmap test 6 passed" in res[0].out and \
                      "mmap test 7 passed" in res[0].out)

regression.add_check(name="Private mmap beyond file range (after fork)",
    check=lambda res: "mmap test 1 passed" in res[0].out and \
                      "mmap test 2 passed" in res[0].out and \
                      "mmap test 3 passed" in res[0].out and \
                      "mmap test 4 passed" in res[0].out)

# On SGX, SIGBUS isn't always implemented correctly, for lack
# of memory protection.  For now, some of these cases won't work.
if not sgx:
    regression.add_check(name="SIGBUS test",
                         check=lambda res: "mmap test 5 passed" in res[0].out and \
                         "mmap test 8 passed" in res[0].out)


rv = regression.run_checks()
if rv: sys.exit(rv)
