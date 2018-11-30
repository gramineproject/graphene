#!/usr/bin/python

import subprocess
from regression import Regression

def gcc_check(res):
    try:
        subprocess.check_call(['chmod', '755', 'test_files/gcc'])
    except subprocess.CalledProcessError:
        return False
    return True

for source, check in [("gcc.c",  	gcc_check)]:

    regression = Regression(executable="./gcc.manifest", timeout=30000)
    regression.add_check(name=source,
                         args=['test_files/' + source, '-o', 'test_files/' + source.replace('.c', '')],
                         check=check)
    regression.run_checks()
