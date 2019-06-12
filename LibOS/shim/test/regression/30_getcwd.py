import os, sys, mmap
from regression import Regression

loader = sys.argv[1]

# Running stat
regression = Regression(loader, "getcwd")

regression.add_check(name="Getcwd syscall",
    check=lambda res: "[bss_cwd_buf] getcwd succeeded: /" in res[0].out and \
                      "[mmapped_cwd_buf] getcwd succeeded: /" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)
