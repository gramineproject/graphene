#!/usr/bin/python

import os, sys, mmap, subprocess
from regression import Regression

def gcc_check(res):
    try:
        subprocess.check_call(['chmod', '755', 'test_files/gcc'])
        output = subprocess.check_output(['test_files/gcc', 'test_files/helloworld.c'])
    except subprocess.CalledProcessError:
        return False
    return True

for source, check in [("gcc.c",  	gcc_check)]:

    regression = Regression(executable="./gcc.manifest")
    regression.add_check(name=source,
                         args=['test_files/' + source, '-o', 'test_files/' + source.replace('.c', '')],
                         check=check)
    regression.run_checks()
