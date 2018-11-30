#!/usr/bin/python

import os, sys, mmap, subprocess
from regression import Regression

regression = Regression("./gcc.manifest")

def helloworld_check(res):
    subprocess.call(['chmod', '755', 'test_files/helloworld'])
    subprocess.call(['test_files/helloworld'])
    subprocess.call(['rm', '-f', 'test_files/helloworld'])
    return True

regression.add_check(name="helloworld.c",
                     args=['helloworld.c', '-o', 'helloworld'],
                     check=helloworld_check)

def bzip2_check(res):
    subprocess.call(['chmod', '755', 'test_files/bzip2'])
    subprocess.call(['cp', '-f', 'test_files/bzip2', 'test_files/bzip2.copy'])
    subprocess.call(['test_files/bzip2', '-z', 'test_files/bzip2.copy'])
    subprocess.call(['test_files/bzip2', '-d', 'test_files/bzip2.copy'])
    subprocess.call(['diff', '-q', 'test_files/bzip2', 'test_files/bzip2.copy'])
    subprocess.call(['rm', '-f', 'test_files/bzip2', 'test_files/bzip2.copy'])
    return True

regression.add_check(name="bzip2.c",
                     args=['bzip2.c', '-o', 'bzip2'],
                     check=bzip2_check)

def gzip_check(res):
    subprocess.call(['chmod', '755', 'test_files/gzip'])
    subprocess.call(['cp', '-f', 'test_files/gzip', 'test_files/gzip.copy'])
    subprocess.call(['test_files/gzip', 'test_files/gzip.copy'])
    subprocess.call(['test_files/gzip', '-d', 'test_files/gzip.copy'])
    subprocess.call(['diff', '-q', 'test_files/gzip', 'test_files/gzip.copy'])
    subprocess.call(['rm', '-f', 'test_files/gzip', 'test_files/gzip.copy'])
    return True

regression.add_check(name="gzip.c",
                     args=['gzip.c', '-o', 'gzip'],
                     check=gzip_check)

regression.run_checks()
