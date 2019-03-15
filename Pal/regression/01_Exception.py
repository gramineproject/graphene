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

if os.environ['PAL_HOST'] == 'Linux':
    def check_altstack(res):
        stacks = []
        for line in res[0].log:
            if line.startswith('stack in '):
                try:
                    stack = int(line.split(' ')[3][2:], 16)
                except:
                    return False
                stacks.append(stack)
        # The first stack will be the main stack
        for stack in stacks[1:]:
            # Handler stack cannot be on the same page with the main stack
            if int(stack / 4096) == int(stacks[0] / 4096):
                return False
        return True

    regression.add_check(name="Use host alternate stack (Linux only)", check=check_altstack)

rv = regression.run_checks()
if rv: sys.exit(rv)
