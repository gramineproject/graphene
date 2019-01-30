#!/usr/bin/env python2

import os, sys, mmap
from regression import Regression

loader = os.environ['PAL_LOADER']

regression = Regression(loader, "Misc", timeout=5000)

regression.add_check(name="Query System Time",
    check=lambda res: "Query System Time OK" in res[0].log)

regression.add_check(name="Delay Execution for 10000 Microseconds",
    check=lambda res: "Delay Execution for 10000 Microseconds OK" in res[0].log)

regression.add_check(name="Delay Execution for 3 Seconds",
    check=lambda res: "Delay Execution for 3 Seconds OK" in res[0].log)

regression.add_check(name="Generate Random Bits",
    check=lambda res: "Generate Random Bits OK" in res[0].log)

rv = regression.run_checks()
if rv: sys.exit(rv)

regression = Regression(loader, "Hex")

regression.add_check(name="Hex 2 String Helper Function",
                     check=lambda res: "Hex test 1 is deadbeef" in res[0].log and \
                     "Hex test 2 is cdcdcdcdcdcdcdcd" in res[0].log)

rv = regression.run_checks()
if rv: sys.exit(rv)

regression = Regression(loader, "Exit")

regression.add_check(name="Exit Code Propagation",
    check=lambda res: 112 == res[0].code)

rv = regression.run_checks()
if rv: sys.exit(rv)
