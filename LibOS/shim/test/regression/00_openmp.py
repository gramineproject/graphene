import os, sys, mmap
from regression import Regression

loader = sys.argv[1]
sgx = os.environ.get('SGX_RUN') == '1'

# This test is only meaningful on SGX PAL because only SGX catches raw syscalls
# and redirects to Graphene's LibOS. If we will add seccomp to Linux PAL, then
# we should allow this test on Linux PAL as well.
if not sgx:
    sys.exit(0)

# Running OpenMP
regression = Regression(loader, "openmp")

regression.add_check(name="OpenMP simple for loop",
    check=lambda res: "first: 0, last: 9" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)
