#!/usr/bin/env python3

import os, sys, gdb

if len(gdb.inferiors()) == 1:
    gdb.execute("set env IN_GDB = 1")
    gdb.execute("set auto-load off")

    sys.stdout.write("Are you loading the script [Y]/n ? ")
    sys.stdout.flush()
    ans = sys.stdin.readline()

    if ans[0] != 'n' and ans[0] != 'N':
        gdbfile = os.path.dirname(__file__) + "/pal.gdb"
        gdb.execute("source " + gdbfile)
        sys.stdout.write("script %s loaded\n" % gdbfile)
