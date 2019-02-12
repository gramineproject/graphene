#!/usr/bin/env python2

import os, sys, mmap
from regression import Regression

loader = sys.argv[1]

# Running futex
regression = Regression(loader, "futex")

regression.add_check(name="Futex Wake Test",
    check=lambda res: "Woke all kiddos" in res[0].out)

regression.run_checks()
