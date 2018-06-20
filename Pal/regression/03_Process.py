#!/usr/bin/python

import os, sys, mmap
from regression import Regression

loader = os.environ['PAL_LOADER']

regression = Regression(loader, "Process")

def check_times(target, lines, times):
    count = 0
    for line in lines:
        if target == line:
            count += 1
    return count == times

regression.add_check(name="Process Creation",
    check=lambda res: check_times("Child Process Created", res[0].log, 3))

regression.add_check(name="Process Creation Arguments",
    check=lambda res: check_times("argv[0] = Process", res[0].log, 3) and
                      check_times("argv[1] = Child",   res[0].log, 3))

regression.add_check(name="Process Channel Transmission",
    check=lambda res: check_times("Process Write 1 OK",            res[0].log, 3) and
                      check_times("Process Read 1: Hello World 1", res[0].log, 3) and
                      check_times("Process Write 2 OK",            res[0].log, 3) and
                      check_times("Process Read 2: Hello World 2", res[0].log, 3))

regression.add_check(name="Multi-Process Broadcast Channel Transmission",
    check=lambda res: check_times("Broadcast Write OK",            res[0].log, 1) and
                      check_times("Broadcast Read: Hello World 1", res[0].log, 3))

rv = regression.run_checks()
if rv: sys.exit(rv)

regression = Regression(loader, "Process2")

regression.add_check(name="Process Creation with a Different Binary",
    check=lambda res: check_times("User Program Started", res[0].log, 1))

rv = regression.run_checks()
if rv: sys.exit(rv)

regression = Regression(loader, "Process3")

regression.add_check(name="Process Creation without Executable",
    check=lambda res: check_times("Binary 1 Preloaded", res[0].log, 2) and
                      check_times("Binary 2 Preloaded", res[0].log, 2))

rv = regression.run_checks()
if rv: sys.exit(rv)

