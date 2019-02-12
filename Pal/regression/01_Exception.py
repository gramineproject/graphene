#!/usr/bin/env python2

import os, sys, mmap
from regression import Regression

loader = os.environ['PAL_LOADER']

regression = Regression(loader, "Exception")

regression.add_check(name="Exception Handling (Div-by-Zero)",
    check=lambda res: any([line.startswith("Div-by-Zero Exception Handler") for line in res[0].log]))

regression.add_check(name="Exception Handling (Memory Fault)",
    check=lambda res: any([line.startswith("Memory Fault Exception Handler") for line in res[0].log]))

regression.add_check(name="Exception Handler Swap",
    check=lambda res: any([line.startswith("Div-by-Zero Exception Handler 1") for line in res[0].log]) and
                      any([line.startswith("Div-by-Zero Exception Handler 2") for line in res[0].log]))

regression.add_check(name="Exception Handling (Set Context)",
    check=lambda res: any([line.startswith("Div-by-Zero Exception Handler 1") for line in res[0].log]))

rv = regression.run_checks()
if rv: sys.exit(rv)
