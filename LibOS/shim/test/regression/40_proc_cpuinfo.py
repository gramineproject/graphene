import sys
from regression import Regression

loader = sys.argv[1]

regression = Regression(loader, "proc_cpuinfo", None, 50000)

regression.add_check(name="proc/cpuinfo Linux-based formatting",
    check=lambda res: "cpuinfo test passed" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)
