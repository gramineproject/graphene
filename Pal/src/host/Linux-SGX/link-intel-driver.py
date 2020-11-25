#!/usr/bin/env python3

import sys, os, shutil

DRIVER_VERSIONS = {
        'sgx_user.h':                 '/dev/isgx',
        'include/uapi/asm/sgx_oot.h': '/dev/sgx/enclave',
        'include/uapi/asm/sgx.h':     '/dev/sgx/enclave',
        'sgx_in_kernel.h':            '/dev/sgx/enclave',
}

def find_intel_sgx_driver():
    """
    Graphene only needs one header from the Intel SGX Driver:
      - sgx_user.h for non-DCAP, older version of the driver
        (https://github.com/intel/linux-sgx-driver)
      - include/uapi/asm/sgx_oot.h for DCAP 1.6+ version of the driver
        (https://github.com/intel/SGXDataCenterAttestationPrimitives)
      - include/uapi/asm/sgx.h for in-kernel 20+ version of the driver
        (https://lore.kernel.org/linux-sgx/20190417103938.7762-1-jarkko.sakkinen@linux.intel.com/)
      - default sgx_in_kernel.h for in-kernel 32+ version of the driver
        (https://lore.kernel.org/linux-sgx/20200716135303.276442-1-jarkko.sakkinen@linux.intel.com)

    This function returns the required header from the SGX driver.
    """
    isgx_driver_path = os.getenv("ISGX_DRIVER_PATH")
    if not isgx_driver_path:
        msg = 'Enter the Intel SGX driver dir with C headers (or press ENTER for in-kernel driver): '
        isgx_driver_path = os.path.expanduser(input(msg))

    if not isgx_driver_path or isgx_driver_path.strip() == '':
        # user did not specify any driver path, use default in-kernel driver's C header
        isgx_driver_path = os.path.dirname(os.path.abspath(__file__))

    for header_path, dev_path in DRIVER_VERSIONS.items():
        abs_header_path = os.path.abspath(os.path.join(isgx_driver_path, header_path))
        if os.path.exists(abs_header_path):
            return abs_header_path, dev_path

    raise Exception("Could not find the header from the Intel SGX Driver")


def main():
    """ Find and copy header/device paths from Intel SGX Driver"""
    header_path, dev_path = find_intel_sgx_driver()

    this_header_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sgx.h')
    shutil.copyfile(header_path, this_header_path)

    with open(this_header_path, 'a') as f:
        f.write('\n\n#ifndef ISGX_FILE\n#define ISGX_FILE "%s"\n#endif\n' % dev_path)
        if dev_path == '/dev/sgx' or dev_path == '/dev/sgx/enclave':
            f.write('\n\n#ifndef SGX_DCAP\n#define SGX_DCAP 1\n#endif\n')
        if dev_path == '/dev/sgx/enclave':
            f.write('\n\n#ifndef SGX_DCAP_16_OR_LATER\n#define SGX_DCAP_16_OR_LATER 1\n#endif\n')


if __name__ == "__main__":
    sys.exit(main())
