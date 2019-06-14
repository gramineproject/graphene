import os, sys, mmap
from regression import Regression

loader = sys.argv[1]
sgx = os.environ.get('SGX_RUN') == '1'

# This test is only meaningful on SGX PAL because only SGX catches raw syscalls
# and redirects to Graphene's LibOS. If we will add seccomp to Linux PAL, then
# we should allow this test on Linux PAL as well.
if not sgx:
    sys.exit(0)

# Running Syscall Instruction Example
regression = Regression(loader, "syscall")

regression.add_check(name="Syscall Instruction Redirection",
    check=lambda res: "Hello world" in res[0].out)

rv = regression.run_checks()
if rv: sys.exit(rv)
