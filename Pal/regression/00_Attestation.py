import os, sys, mmap
from regression import Regression

loader = os.environ['PAL_LOADER']
sgx = os.environ.get('SGX_RUN') == '1'

if sgx:
    regression = Regression(loader, "Attestation1.manifest.sgx")

    regression.add_check(name="Remote Attestation (SGX Only)",
        check=lambda res: "User Program Started" in res[0].log)

    rv = regression.run_checks()
    if rv: sys.exit(rv)
