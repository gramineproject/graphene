#!/usr/bin/env python2

import os, sys, mmap
from regression import Regression

loader = os.environ['PAL_LOADER']

regression = Regression(loader, "SendHandle")

def check_times(target, lines, times):
    count = 0
    for line in lines:
        if target == line:
            count += 1
    return count == times

regression.add_check(name="Send and Receive Handles across Processes",
    check=lambda res: check_times("Send Handle OK", res[0].log, 3) and
                      check_times("Receive Handle OK", res[0].log, 3))

regression.add_check(name="Send Pipe Handle",
        check=lambda res: check_times("Receive Pipe Handle: Hello World", res[0].log, 1))

regression.add_check(name="Send Socket Handle",
        check=lambda res: check_times("Receive Socket Handle: Hello World", res[0].log, 1))

regression.add_check(name="Send File Handle",
        check=lambda res: check_times("Receive File Handle: Hello World", res[0].log, 1))

rv = regression.run_checks()
if rv: sys.exit(rv)
