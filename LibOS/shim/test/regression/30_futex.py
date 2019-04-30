import os, sys, mmap
from regression import Regression

loader = sys.argv[1]

# Running futex
regression = Regression(loader, "futex")

regression.add_check(name="Futex Wake Test",
    check=lambda res: "Woke all kiddos" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)

# Running futex-timeout
regression = Regression(loader, "futex-timeout")

regression.add_check(name="Futex Timeout Test",
    check=lambda res: "hello" in res[0].out and \
            "world" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)
