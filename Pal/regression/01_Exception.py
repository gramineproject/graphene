#!/usr/bin/python

import os, sys, mmap
from regression import Regression

loader = '../src/pal'

regression = Regression(loader, "Exception")

def check_exception1(res):
    for line in res[0].log:
        if not line:
            continue
        if line.startswith('Div-by-Zero Exception Handler'):
            return True
    return False

regression.add_check(name="Exception Handling (Div-by-Zero)", check=check_exception1)

def check_exception2(res):
    for line in res[0].log:
        if not line:
            continue
        if line.startswith('Memory Fault Exception Handler'):
            return True
    return False

regression.add_check(name="Exception Handling (Memory Fault)", check=check_exception2)

def check_exception3(res):
    found1 = False
    found2 = False
    for line in res[0].log:
        if not line:
            continue
        if line.startswith('Div-by-Zero Exception Handler 1'):
            found1 = True
        if line.startswith('Div-by-Zero Exception Handler 2'):
            found2 = True
    return found1 and found2

regression.add_check(name="Exception Handler Swap", check=check_exception3)

def check_exception4(res):
    found = 0
    for line in res[0].log:
        if not line:
            continue
        if line.startswith('Div-by-Zero Exception Handler 1'):
            found += 1
    return found == 1

regression.add_check(name="Exception Handling (Set Context)", check=check_exception4)

regression.run_checks()
