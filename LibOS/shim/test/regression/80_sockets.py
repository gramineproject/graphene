#!/usr/bin/env python2

import os, sys, mmap
from regression import Regression

loader = sys.argv[1]

# Running getsockopt
regression = Regression(loader, "getsockopt", None)

regression.add_check(name="getsockopt",
    check=lambda res: "getsockopt: Got socket type OK" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)
