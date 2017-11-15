#!/usr/bin/python

import os, sys, mmap, random, string
from regression import Regression

loader = os.environ['PAL_LOADER']

# Running Semaphore
regression = Regression(loader, "Semaphore")

regression.add_check(name="Semaphore: Timeout on Locked Semaphores",
    check=lambda res: "Locked binary semaphore timed out (1000)." in res[0].log and
                      "Locked non-binary semaphore timed out (1000)." in res[0].log and
                      "Two locked semaphores timed out (1000)." in res[0].log and
                      "Locked binary semaphore timed out (0)." in res[0].log and
                      "Locked non-binary semaphore timed out (0)." in res[0].log and
                      "Two locked semaphores timed out (0)." in res[0].log)

regression.add_check(name="Semaphore: Acquire Unlocked Semaphores",
    check=lambda res: "Locked binary semaphore successfully (-1)." in res[0].log and
                      "Locked non-binary semaphore successfully (-1)." in res[0].log and
                      "Locked binary semaphore successfully (0)." in res[0].log and
                      "Locked non-binary semaphore successfully (0)." in res[0].log)

rv = regression.run_checks()
if rv: sys.exit(rv)
