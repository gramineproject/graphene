#!/usr/bin/env python2

import os, sys, mmap
from regression import Regression

loader = os.environ['PAL_LOADER']

regression = Regression(loader, "Pipe")

regression.add_check(name="Pipe Creation",
    check=lambda res: "Pipe Creation 1 OK" in res[0].log)

regression.add_check(name="Pipe Attributes",
    check=lambda res: "Pipe Attribute Query 1 on pipesrv returned OK" in res[0].log)

regression.add_check(name="Pipe Connection",
    check=lambda res: "Pipe Connection 1 OK" in res[0].log)

regression.add_check(name="Pipe Transmission",
    check=lambda res: "Pipe Write 1 OK" in res[0].log and
                      "Pipe Read 1: Hello World 1" in res[0].log and
                      "Pipe Write 2 OK" in res[0].log and
                      "Pipe Read 2: Hello World 2" in res[0].log)

rv = regression.run_checks()
if rv: sys.exit(rv)
