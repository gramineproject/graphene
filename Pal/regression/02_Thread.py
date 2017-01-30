#!/usr/bin/python

import os, sys, mmap
from regression import Regression

loader = os.environ['PAL_LOADER']

regression = Regression(loader, "Thread")

regression.add_check(name="Thread Creation",
    check=lambda res: "Child Thread Created" in res[0].log and
                      "Run in Child Thread: Hello World" in res[0].log)

regression.add_check(name="Multiple Threads Run in Parallel",
    check=lambda res: "Threads Run in Parallel OK" in res[0].log)

regression.add_check(name="Set Thread Private Segment Register",
    check=lambda res: "Private Message (FS Segment) 1: Hello World 1" in res[0].log and
                      "Private Message (FS Segment) 2: Hello World 2" in res[0].log)

regression.add_check(name="Thread Exit",
    check=lambda res: "Child Thread Exited" in res[0].log)

regression.run_checks()
