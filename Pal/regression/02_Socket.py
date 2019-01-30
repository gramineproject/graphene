#!/usr/bin/env python2

import os, sys, mmap
from regression import Regression

loader = os.environ['PAL_LOADER']

regression = Regression(loader, "Socket")

regression.add_check(name="TCP Socket Creation",
    check=lambda res: "TCP Creation 1 OK" in res[0].log)

regression.add_check(name="TCP Socket Connection",
    check=lambda res: "TCP Connection 1 OK" in res[0].log)

regression.add_check(name="TCP Socket Transmission",
    check=lambda res: "TCP Write 1 OK" in res[0].log and
                      "TCP Read 1: Hello World 1" in res[0].log and
                      "TCP Write 2 OK" in res[0].log and
                      "TCP Read 2: Hello World 2" in res[0].log)

regression.add_check(name="UDP Socket Creation",
    check=lambda res: "UDP Creation 1 OK" in res[0].log)

regression.add_check(name="UDP Socket Connection",
    check=lambda res: "UDP Connection 1 OK" in res[0].log)

regression.add_check(name="UDP Socket Transmission",
    check=lambda res: "UDP Write 1 OK" in res[0].log and
                      "UDP Read 1: Hello World 1" in res[0].log and
                      "UDP Write 2 OK" in res[0].log and
                      "UDP Read 2: Hello World 2" in res[0].log)

regression.add_check(name="Bound UDP Socket Transmission",
    check=lambda res: "UDP Write 3 OK" in res[0].log and
                      "UDP Read 3: Hello World 1" in res[0].log and
                      "UDP Write 4 OK" in res[0].log and
                      "UDP Read 4: Hello World 2" in res[0].log)

rv = regression.run_checks()
if rv: sys.exit(rv)
