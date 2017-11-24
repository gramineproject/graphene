#!/usr/bin/python

import os, sys, mmap, random, string
from regression import Regression

loader = os.environ['PAL_LOADER']

def prepare_files(args):
    global file_exist
    file_exist = ''.join([random.choice(string.ascii_letters) for i in range(2 * mmap.PAGESIZE)])

    with open("file_exist.tmp", "w") as f:
        f.write(file_exist)

    if os.path.exists("file_nonexist.tmp"):
        os.remove("file_nonexist.tmp")

    with open("file_delete.tmp", "w") as f:
        f.write(file_exist)

# Running File
regression = Regression(loader, "File", prepare_files)

regression.add_check(name="Basic File Opening",
    check=lambda res: "File Open Test 1 OK" in res[0].log and
                      "File Open Test 2 OK" in res[0].log and
                      "File Open Test 3 OK" in res[0].log)

regression.add_check(name="Basic File Creation",
    check=lambda res: "File Creation Test 1 OK" in res[0].log and
                      "File Creation Test 2 OK" in res[0].log and
                      "File Creation Test 3 OK" in res[0].log)

regression.add_check(name="File Reading",
    check=lambda res: ("Read Test 1 (0th - 40th): " + file_exist[0:40]) in res[0].log and
                      ("Read Test 2 (0th - 40th): " + file_exist[0:40]) in res[0].log and
                      ("Read Test 3 (200th - 240th): " + file_exist[200:240]) in res[0].log)

def check_write(res):
    global file_exist
    with open("file_nonexist.tmp", "r") as f:
        file_nonexist = f.read()
    return file_exist[0:40] == file_nonexist[200:240] and \
           file_exist[200:240] == file_nonexist[0:40]

regression.add_check(name="File Writing", check=check_write)

regression.add_check(name="File Attribute Query",
    check=lambda res: ("Query: type = 1, size = %d" % (mmap.PAGESIZE * 2)) in res[0].log)

regression.add_check(name="File Attribute Query by Handle",
    check=lambda res: ("Query by Handle: type = 1, size = %d" % (mmap.PAGESIZE * 2)) in res[0].log)

regression.add_check(name="File Mapping",
    check=lambda res: ("Map Test 1 (0th - 40th): " + file_exist[0:40]) in res[0].log and
                      ("Map Test 2 (200th - 240th): " + file_exist[200:240]) in res[0].log and
                      ("Map Test 3 (0th - 40th): " + file_exist[4096:4136]) in res[0].log and
                      ("Map Test 4 (200th - 240th): " + file_exist[4296:4336]) in res[0].log)

regression.add_check(name="Set File Length",
    check=lambda res: os.stat("file_nonexist.tmp").st_size == mmap.ALLOCATIONGRANULARITY)

regression.add_check(name="File Deletion",
    check=lambda res: not os.path.exists("file_delete.tmp"))

rv = regression.run_checks()
if rv: sys.exit(rv)
