import os, sys, mmap
from regression import Regression

loader = sys.argv[1]

# Running Bootstrap
regression = Regression(loader, "openmp")

regression.add_check(name="OpenMP simple for loop",
    check=lambda res: "first: 0, last: 9" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)
