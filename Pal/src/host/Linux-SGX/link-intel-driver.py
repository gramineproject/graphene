#!/usr/bin/env python3

import argparse
import os
import string
import sys

DRIVER_VERSIONS = {
        # For Non-DCAP, older versions of legacy OOT SGX driver
        'sgx_user.h':                 '/dev/isgx',
        # For DCAP driver 1.6+, but below 1.10
        'include/uapi/asm/sgx_oot.h': '/dev/sgx/enclave',
        # For DCAP driver 1.10+
        'include/sgx_user.h':         '/dev/sgx/enclave',
        # For custom-built Linux kernels (5.10-) with the Intel SGX driver
        'include/uapi/asm/sgx.h':     '/dev/sgx/enclave',
        # By default, using sgx_in_kernel.h in current dir of this script --
        # this corresponds to the upstreamed in-kernel SGX driver (Linux 5.11+)
        'sgx_in_kernel.h':            '/dev/sgx_enclave',
}

def find_intel_sgx_driver(isgx_driver_path):
    '''
    Graphene only needs one header from the Intel SGX Driver:
      - sgx_user.h for non-DCAP, older version of the driver
        (https://github.com/intel/linux-sgx-driver)
      - include/uapi/asm/sgx_oot.h for DCAP 1.6+ version but below 1.10 of the driver
        (https://github.com/intel/SGXDataCenterAttestationPrimitives)
      - include/sgx_user.h for DCAP 1.10+ version of the driver
        (https://github.com/intel/SGXDataCenterAttestationPrimitives)
      - include/uapi/asm/sgx.h for in-kernel (but not upstreamed) version of the driver
        (https://lore.kernel.org/linux-sgx/20200716135303.276442-1-jarkko.sakkinen@linux.intel.com)
      - default sgx_in_kernel.h for upstreamed in-kernel driver from mainline Linux kernel 5.11+
        (https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git)

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

argparser = argparse.ArgumentParser()
argparser.add_argument('--input', '-input', metavar='TEMPLATE',
                       type=argparse.FileType('r'), required=True,
                       help='Input .h.in file (template for SGX-driver header)')
argparser.add_argument('--output', '-output', metavar='FINAL',
                       type=str, required=True,
                       help='Output .h file (final SGX-driver header)')

def main(args=None):
    '''
    Find and copy header/device paths from Intel SGX Driver
    '''
    args = argparser.parse_args(args)

    try:
        isgx_driver_path = os.environ['ISGX_DRIVER_PATH']
    except KeyError:
        print(
            'ISGX_DRIVER_PATH environment variable is undefined. You can define\n'
            'ISGX_DRIVER_PATH="" to use the upstreamed in-kernel driver (if you\n'
            'are using Linux kernel 5.11+). For a custom-built Linux kernel\n'
            '(versions 5.10-), specify a complete path to SGX driver headers:\n'
            'ISGX_DRIVER_PATH="/usr/src/linux-headers-$(uname -r)/arch/x86"\n',
            file=sys.stderr)
        sys.exit(1)

    if not isgx_driver_path:
        # user did not specify any driver path, use default in-kernel driver's C header
        isgx_driver_path = os.path.dirname(os.path.abspath(__file__))

    header_path, dev_path = find_intel_sgx_driver(isgx_driver_path)

    template = MesonTemplate(args.input.read())

    final = template.safe_substitute(
        DRIVER_SGX_H=header_path,
        ISGX_FILE=dev_path,
        DEFINE_DCAP=('#define SGX_DCAP 1' if dev_path != '/dev/isgx' else '')
    )

    with open(args.output, 'w') as f:
        f.write(final)

if __name__ == '__main__':
    main()
