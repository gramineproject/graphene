#!/usr/bin/python

import os, sys, mmap, subprocess
from regression import Regression

def helloworld_check(res):
    try:
        subprocess.check_call(['chmod', '755', 'test_files/helloworld'])
        output = subprocess.check_output(['test_files/helloworld'])
        subprocess.call(['rm', '-f', 'test_files/helloworld'])
    except subprocess.CalledProcessError:
        return False
    return "Hello world" in output

def bzip2_check(res):
    try:
        subprocess.check_call(['chmod', '755', 'test_files/bzip2'])
        subprocess.call(['rm', '-f', 'test_files/bzip2.copy*'])
        subprocess.call(['cp', '-f', 'test_files/bzip2', 'test_files/bzip2.copy'])
        subprocess.check_call(['test_files/bzip2', '-z', 'test_files/bzip2.copy'])
        subprocess.check_call(['test_files/bzip2', '-d', 'test_files/bzip2.copy.bz2'])
        subprocess.check_call(['diff', '-q', 'test_files/bzip2', 'test_files/bzip2.copy'])
        subprocess.call(['rm', '-f', 'test_files/bzip2', 'test_files/bzip2.copy*'])
    except subprocess.CalledProcessError:
        return False
    return True

def gzip_check(res):
    try:
        subprocess.check_call(['chmod', '755', 'test_files/gzip'])
        subprocess.call(['rm', '-f', 'test_files/gzip.copy*'])
        subprocess.call(['cp', '-f', 'test_files/gzip', 'test_files/gzip.copy'])
        subprocess.check_call(['test_files/gzip', 'test_files/gzip.copy'])
        subprocess.check_call(['test_files/gzip', '-d', 'test_files/gzip.copy.gz'])
        subprocess.check_call(['diff', '-q', 'test_files/gzip', 'test_files/gzip.copy'])
        subprocess.call(['rm', '-f', 'test_files/gzip', 'test_files/gzip.copy*'])
    except subprocess.CalledProcessError:
        return False
    return True

for source, check in [("helloworld.c",  helloworld_check),
                      ("bzip2.c",       bzip2_check),
                      ("gzip.c",        gzip_check)]:

    regression = Regression(executable="./gcc.manifest")
    regression.add_check(name=source,
                         args=['test_files/' + source, '-o', 'test_files/' + source.replace('.c', '')],
                         check=check)
    regression.run_checks()
