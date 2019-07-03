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

rv = regression.run_checks()
if rv: sys.exit(rv)

# Running fstat
regression = Regression(loader, "fstat_cwd")

regression.add_check(name="Fstat on a directory",
    check=lambda res: "fstat returns the fd type as S_IFDIR" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)
