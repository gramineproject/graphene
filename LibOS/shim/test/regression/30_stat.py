#!/usr/bin/env python2

import os, sys, mmap
from regression import Regression

loader = sys.argv[1]

# Running stat
regression = Regression(loader, "stat_invalid_args")

regression.add_check(name="Stat with invalid arguments",
    check=lambda res: "stat(invalid-path-ptr) correctly returns error" in res[0].out and \
                      "stat(invalid-buf-ptr) correctly returns error" in res[0].out and \
                      "lstat(invalid-path-ptr) correctly returns error" in res[0].out and \
                      "lstat(invalid-buf-ptr) correctly returns error" in res[0].out)

regression.run_checks()
