#!/usr/bin/env python2

import os, sys, mmap
from regression import Regression

loader = os.environ['PAL_LOADER']

sgx = ('SGX_RUN' in os.environ and os.environ['SGX_RUN'] == '1')

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

rv = regression.run_checks()
if rv: sys.exit(rv)

regression = Regression(loader, "Thread2")

regression.add_check(name="Thread Cleanup: Exit by return.",
    check=lambda res: "Thread 2 ok." in res[0].log)

# The 2 following tests are currently broken on SGX because TCS slots are not
# resued yet (needed because of thread limit), see issue #517.

regression.add_check(name="Thread Cleanup: Exit by DkThreadExit.",
    check=lambda res: "Thread 3 ok." in res[0].log and
                      "Exiting thread 3 failed." not in res[0].log,
    ignore_failure=sgx)

regression.add_check(name="Thread Cleanup: Can still start threads.",
    check=lambda res: "Thread 4 ok." in res[0].log,
    ignore_failure=sgx)

rv = regression.run_checks()
if rv: sys.exit(rv)
