#!/usr/bin/env python

import os, sys, gdb

if len(gdb.inferiors()) == 1:
    print "Are you loading the script [Y]/n ? ",
    ans = sys.stdin.readline()

    if ans[0] == 'n' or ans[0] == 'N':
        gdb.execute("set detach-on-fork on")
        gdb.execute("set follow-fork-mode child")

    else:
        gdbfile = os.path.dirname(__file__) + "/pal.gdb"
        gdb.execute("set env IN_GDB = 1")
        gdb.execute("source " + gdbfile)
        print "script",  gdbfile, "loaded"
