#!/usr/bin/python

import os, sys, mmap
from regression import Regression

loader = os.environ['PAL_LOADER']
try:
    sgx = os.environ['SGX_RUN']
except KeyError:
    sgx = False

def manifest_file(file):
    if 'SGX_RUN' in os.environ and os.environ['SGX_RUN'] == '1':
        return file + '.manifest.sgx'
    else:
        return file + '.manifest'

# Running AvxDisable 
regression = Regression(loader, "AvxDisable")

regression.add_check(name="Disable AVX bit in XFRM",
    check=lambda res: "Illegal Instruction Unsupported inside Enclave" in res[0].log)

rv = regression.run_checks()
if rv: sys.exit(rv)
