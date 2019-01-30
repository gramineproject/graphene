#!/usr/bin/env python2

import os, sys, mmap
from regression import Regression

loader = sys.argv[1]

# Running Bootstrap
regression = Regression(loader, "large-mmap", None, 240000)

regression.add_check(name="Ftruncate",
    check=lambda res: "large-mmap: ftruncate OK" in res[0].out)

regression.add_check(name="Large mmap",
    check=lambda res: "large-mmap: mmap 1 completed OK" in res[0].out and \
                     "large-mmap: mmap 2 completed OK" in res[0].out)

regression.run_checks()
