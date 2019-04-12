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

if not sgx:
  sys.exit(0)
# Running AvxDisable
regression = Regression(loader, "AvxDisable")

regression.add_check(name="Disable AVX bit in XFRM",
    check=lambda res: "Illegal instruction executed in enclave" in res[0].log)

rv = regression.run_checks()
if rv: sys.exit(rv)
