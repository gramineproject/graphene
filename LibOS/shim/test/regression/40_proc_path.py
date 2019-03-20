#!/usr/bin/env python2

import os, sys, mmap
from regression import Regression

loader = sys.argv[1]
try:
    sgx = os.environ['SGX_RUN']
except KeyError:
    sgx = False

# Running Bootstrap
regression = Regression(loader, "proc-path")

regression.add_check(name="Base /proc path present",
    check=lambda res: "proc path test success" in res[0].out)


rv = regression.run_checks()
if rv: sys.exit(rv)
