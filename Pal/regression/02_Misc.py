#!/usr/bin/python

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

regression.run_checks()
