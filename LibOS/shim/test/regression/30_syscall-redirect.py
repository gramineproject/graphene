#!/usr/bin/python

import os, sys, mmap
from regression import Regression

loader = sys.argv[1]

# Running Syscall Instruction Example
regression = Regression(loader, "syscall")

regression.add_check(name="Syscall Instruction Redirection",
    check=lambda res: "Hello world" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)
