#!/usr/bin/env python2

import os, sys, mmap
from regression import Regression

loader = os.environ['PAL_LOADER']
sgx = os.environ.get('SGX_RUN') == '1'

def manifest_file(file):
    if sgx:
        return file + '.manifest.sgx'
    else:
        return file + '.manifest'

# Running AtomicMath
regression = Regression(loader, "AtomicMath")

regression.add_check(name="Atomic Math",
    check=lambda res: "Subtract INT_MIN: Both values match 2147483648" in res[0].log and \
                     "Subtract INT_MAX: Both values match -2147483647" in res[0].log and \
                     "Subtract LLONG_MIN: Both values match -9223372036854775808" in res[0].log and \
                     "Subtract LLONG_MAX: Both values match -9223372036854775807" in res[0].log)

rv = regression.run_checks()
if rv: sys.exit(rv)
