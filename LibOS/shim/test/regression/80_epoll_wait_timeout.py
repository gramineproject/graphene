#!/usr/bin/env python2

import os, sys, mmap
from regression import Regression

loader = sys.argv[1]

regression = Regression(loader, "epoll_wait_timeout", None, 50000)

regression.add_check(name="epoll_wait timeout",
    args = ['8000'],
    check=lambda res: "epoll_wait test passed" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)
