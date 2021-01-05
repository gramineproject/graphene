#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2020 Intel Corp.
#                    Anjo Vahldiek-Oberwagner <anjo.lucas.vahldiek-oberwagner@intel.com>

import os
import sys
import subprocess

def generate_signature(exec_):
    sign_process = subprocess.Popen([
        '/graphene/python/graphene-sgx-sign',
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

def main(args=None):
    print('Signing application:', args[1])
    generate_signature(args[1])

if __name__ == '__main__':
    main(sys.argv)
