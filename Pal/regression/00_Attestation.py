import os, sys, mmap
from datetime import datetime,timedelta
from regression import Regression

loader = os.environ['PAL_LOADER']
sgx = os.environ.get('SGX_RUN') == '1'

if sgx:
    regression = Regression(loader, "Attestation1.manifest.sgx")

    def check_attestation(res):
        for line in res[0].log:
            if line.startswith("Attestation status:"):
                status = line[19:].strip()
                if status not in ["OK", "GROUP_OUT_OF_DATE"]:
                    return False
            if line.startswith("Attestation timestamp:"):
                timestamp = datetime.strptime(line[22:].strip(), "%Y-%m-%dT%H:%M:%S.%f")
                # The timestamp may be in another time zone, but should be
                # within 24 hours of the current time.
                if datetime.now() - timedelta(hours=24) > timestamp or \
                   datetime.now() + timedelta(hours=24) < timestamp:
                    return False
        return True

    regression.add_check(name="Remote Attestation (SGX Only)",
            check=check_attestation)

    rv = regression.run_checks()
    if rv: sys.exit(rv)
