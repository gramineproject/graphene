#!/usr/bin/env python3

import os
import string
import sys

DRIVER_VERSIONS = {
        'sgx_user.h':                 '/dev/isgx',
        'include/uapi/asm/sgx_oot.h': '/dev/sgx/enclave',
        'sgx_in_kernel.h':            '/dev/sgx/enclave',
}

def find_intel_sgx_driver(isgx_driver_path):
    '''
    Graphene only needs one header from the Intel SGX Driver:
      - sgx_user.h for non-DCAP, older version of the driver
        (https://github.com/intel/linux-sgx-driver)
      - include/uapi/asm/sgx_oot.h for DCAP 1.6+ version of the driver
        (https://github.com/intel/SGXDataCenterAttestationPrimitives)
      - default sgx_in_kernel.h for in-kernel 32+ version of the driver
        (https://lore.kernel.org/linux-sgx/20200716135303.276442-1-jarkko.sakkinen@linux.intel.com)

    This function returns the required header from the SGX driver.
    '''
    for header_path, dev_path in DRIVER_VERSIONS.items():
        abs_header_path = os.path.abspath(os.path.join(isgx_driver_path, header_path))
        if os.path.exists(abs_header_path):
            return abs_header_path, dev_path

    print('Could not find the header from the Intel SGX Driver (ISGX_DRIVER_PATH={!r})'.format(
        isgx_driver_path), file=sys.stderr)
    sys.exit(1)

class MesonTemplate(string.Template):
    pattern = '''
        @(?:
            (?P<escaped>@) |
            (?P<named>[A-Za-z0-9_]+)@ |
            (?P<braced>[A-Za-z0-9_]+)@ |
            (?P<invalid>)
        )
    '''

def main():
    '''
    Find and copy header/device paths from Intel SGX Driver
    '''
    try:
        isgx_driver_path = os.environ['ISGX_DRIVER_PATH']
    except KeyError:
        print(
            'ISGX_DRIVER_PATH environment variable is undefined. You can define\n'
            'ISGX_DRIVER_PATH="" to use the default in-kernel driver\'s C header.',
            file=sys.stderr)
        sys.exit(1)

    if not isgx_driver_path:
        # user did not specify any driver path, use default in-kernel driver's C header
        isgx_driver_path = os.path.dirname(os.path.abspath(__file__))

    header_path, dev_path = find_intel_sgx_driver(isgx_driver_path)

    with sys.stdin:
        template = MesonTemplate(sys.stdin.read())

    sys.stdout.write(template.safe_substitute(
        DRIVER_SGX_H=header_path,
        ISGX_FILE=dev_path,
        DEFINE_DCAP=('#define SGX_DCAP 1' if dev_path == '/dev/sgx/enclave' else '')
    ))


if __name__ == '__main__':
    main()
