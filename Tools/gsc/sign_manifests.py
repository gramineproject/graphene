#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2020 Intel Corp.
#                    Anjo Vahldiek-Oberwagner <anjo.lucas.vahldiek-oberwagner@intel.com>

import os
import sys
import subprocess
import argparse

def generate_signature(exec_):
    sign_process = subprocess.Popen([
        '/graphene/python/graphene-sgx-sign',
        '-exec', exec_,
        '-libpal', '/graphene/Runtime/libpal-Linux-SGX.so',
        '-key', '/gsc-signer-key.pem',
        '-output', f'{exec_}.manifest.sgx',
        '-manifest', f'{exec_}.manifest',
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=os.environ.update({'PYTHONDONTWRITEBYTECODE':'1'}))

    _, err = sign_process.communicate()

    if (sign_process.returncode != 0
        or not os.path.exists(os.path.join('./', exec_ + '.manifest.sgx'))
        or not os.path.exists(os.path.join('./', exec_ + '.sig'))):
        print(err.decode())
        print('Finalize manifests failed due to graphene-sgx-sign failure.')
        sys.exit(1)

# Iterate over manifest file to find enclave size definition and return it
def extract_enclave_size(manifest):
    with open(manifest, 'r') as file:
        for line in file:
            if not line.strip().startswith('sgx.enclave_size'):
                continue

            tokens = line.split('=')
            if len(tokens) != 2:
                continue
            return tokens[1].strip()

    return '0M'

argparser = argparse.ArgumentParser()
argparser.add_argument('signing_order', default='signing_order.txt',
    help='File specifying the order in which executables should be signed. '
         'Default: signing_order.txt')

def main(args=None):
    args = argparser.parse_args(args[1:])

    print('Signing manifests:')

    sig_order_file = args.signing_order
    if not os.path.exists(sig_order_file):
        print(f'Failed to generate signatures, since image misses {sig_order_file}.')

    # To deal with multi-process applications, we sign the application manifests in the order
    # specified by finalize_manifests.py. The order is stored in a temporary file called
    # signature_order.txt.
    with open(sig_order_file, 'r') as sig_order:
        executables = sig_order.read().splitlines()
        for executable in executables:
            generate_signature(executable)

            print(f'\t{executable}')

        # In case multiple manifest files were generated, ensure that their enclave sizes are
        # compatible
        if len(executables) > 1:
            main_encl_size = extract_enclave_size(executables[0] + '.manifest.sgx')
            for executable in executables:
                if main_encl_size != extract_enclave_size(executable + '.manifest.sgx'):
                    print('Error: Detected a child manifest with an enclave size different than '
                          'its parent.')
                    sys.exit(1)

if __name__ == '__main__':
    main(sys.argv)
