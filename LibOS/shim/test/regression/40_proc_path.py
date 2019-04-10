import os, sys
from regression import Regression

loader = sys.argv[1]

# Running Bootstrap
regression = Regression(loader, "proc-path")

regression.add_check(name="Base /proc path present",
    check=lambda res: "proc path test success" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)
