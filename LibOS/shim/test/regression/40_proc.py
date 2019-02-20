import os, sys, mmap
from regression import Regression

loader = sys.argv[1]

# Running Bootstrap
regression = Regression(loader, "proc")

regression.add_check(name="Base /proc files present",
    check=lambda res: "/proc/1/.." in res[0].out and \
                      "/proc/1/cwd" in res[0].out and \
                      "/proc/1/exe" in res[0].out and \
                      "/proc/1/root" in res[0].out and \
                      "/proc/1/fd" in res[0].out and \
                      "/proc/1/maps" in res[0].out and \
                      "/proc/." in res[0].out and \
                      "/proc/1" in res[0].out and \
                      "/proc/self" in res[0].out and \
                      "/proc/meminfo" in res[0].out and \
                      "/proc/cpuinfo" in res[0].out)


rv = regression.run_checks()
if rv: sys.exit(rv)
