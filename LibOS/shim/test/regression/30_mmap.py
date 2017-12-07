#!/usr/bin/python

import os, sys, mmap
from regression import Regression

loader = sys.argv[1]

# Running Bootstrap
regression = Regression(loader, "mmap-file", None, 60000)

regression.add_check(name="Private mmap beyond file range",
    check=lambda res: "mmap test 6 passed" in res[0].out and \
                      "mmap test 7 passed" in res[0].out and \
                      "mmap test 8 passed" in res[0].out)

regression.add_check(name="Private mmap beyond file range (after fork)",
    check=lambda res: "mmap test 1 passed" in res[0].out and \
                      "mmap test 2 passed" in res[0].out and \
                      "mmap test 3 passed" in res[0].out and \
                      "mmap test 4 passed" in res[0].out and \
                      "mmap test 5 passed" in res[0].out)

regression.run_checks()
