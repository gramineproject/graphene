#!/usr/bin/python

import os, sys, mmap
from regression import Regression

loader = './pal'

# Running Bootstrap
regression = Regression(loader, "large-mmap")

regression.add_check(name="Ftruncate",
    check=lambda res: "large-mmap: ftruncate OK" in res[0].out)

regression.add_check(name="Large mmap",
    check=lambda res: "large-mmap: test completed OK" in res[0].out)

regression.run_checks()
