#!/usr/bin/env python2

import os, sys, mmap, random, string, shutil
from regression import Regression

loader = os.environ['PAL_LOADER']

def prepare_dirs(args):
    if os.path.exists("dir_exist.tmp"):
        shutil.rmtree("dir_exist.tmp")
    if os.path.exists("dir_nonexist.tmp"):
        shutil.rmtree("dir_nonexist.tmp")
    if os.path.exists("dir_delete.tmp"):
        shutil.rmtree("dir_delete.tmp")

    global dir_files
    os.mkdir("dir_exist.tmp")
    dir_files = []
    for i in range(5):
        file = ''.join([random.choice(string.ascii_letters) for i in range(8)])
        f = open("dir_exist.tmp/" + file, "w")
        f.close()
        dir_files.append(file)

    os.mkdir("dir_delete.tmp")


regression = Regression(loader, "Directory", prepare_dirs)

regression.add_check(name="Basic Directory Opening",
    check=lambda res: "Directory Open Test 1 OK" in res[0].log and
                      "Directory Open Test 2 OK" in res[0].log and
                      "Directory Open Test 3 OK" in res[0].log)

regression.add_check(name="Basic Directory Creation",
    check=lambda res: "Directory Creation Test 1 OK" in res[0].log and
                      "Directory Creation Test 2 OK" in res[0].log and
                      "Directory Creation Test 3 OK" in res[0].log)

def check_read(res):
    global dir_files
    for file in dir_files:
        if ("Read Directory: " + file) not in res[0].log:
            return False
    return True

regression.add_check(name="Directory Reading", check=check_read)

regression.add_check(name="Directory Attribute Query",
    check=lambda res: "Query: type = 7" in res[0].log)

regression.add_check(name="Directory Attribute Query by Handle",
    check=lambda res: "Query by Handle: type = 7" in res[0].log)

regression.add_check(name="Directory Deletion",
    check=lambda res: not os.path.exists("dir_delete.tmp"))

rv = regression.run_checks()
if rv: sys.exit(rv)
