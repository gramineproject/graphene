#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later */
# Copyright (C) 2014 Stony Brook University
# Copyright (C) 2021 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>

import struct
import subprocess
from . import _offsets as offs # pylint: disable=import-error,no-name-in-module

# Generate final SIGSTRUCT based on enclave attributes and MRENCLAVE.
# TODO: This uses one-step signing process (SIGSTRUCT is signed on the same machine where it was
#       generated). Need to update to the two-step signing process.

class EnclaveSign:

    def __init__(self, attr, mrenclave_final):
        self.attr = attr
        self.mrenclave_final = mrenclave_final

    def gen_sigstruct(self):
        '''Generate Sigstruct.

        field format: (offset, type, value)
        ''' # pylint: disable=too-many-locals

        self.fields = {
            'header': (offs.SGX_ARCH_ENCLAVE_CSS_HEADER,
                       '<4L', 0x00000006, 0x000000e1, 0x00010000, 0x00000000),
            'module_vendor': (offs.SGX_ARCH_ENCLAVE_CSS_MODULE_VENDOR, '<L', 0x00000000),
            'date': (offs.SGX_ARCH_ENCLAVE_CSS_DATE, '<HBB', self.attr['year'], self.attr['month'], self.attr['day']),
            'header2': (offs.SGX_ARCH_ENCLAVE_CSS_HEADER2,
                        '<4L', 0x00000101, 0x00000060, 0x00000060, 0x00000001),
            'hw_version': (offs.SGX_ARCH_ENCLAVE_CSS_HW_VERSION, '<L', 0x00000000),
            'misc_select': (offs.SGX_ARCH_ENCLAVE_CSS_MISC_SELECT, '4s', self.attr['misc_select']),
            'misc_mask': (offs.SGX_ARCH_ENCLAVE_CSS_MISC_MASK, '4s', self.attr['misc_select']),
            'attributes': (offs.SGX_ARCH_ENCLAVE_CSS_ATTRIBUTES, '8s8s', self.attr['flags'], self.attr['xfrms']),
            'attribute_mask': (offs.SGX_ARCH_ENCLAVE_CSS_ATTRIBUTE_MASK,
                               '8s8s', self.attr['flags'], self.attr['xfrms']),
            'enclave_hash': (offs.SGX_ARCH_ENCLAVE_CSS_ENCLAVE_HASH, '32s', self.mrenclave_final),
            'isv_prod_id': (offs.SGX_ARCH_ENCLAVE_CSS_ISV_PROD_ID, '<H', self.attr['isv_prod_id']),
            'isv_svn': (offs.SGX_ARCH_ENCLAVE_CSS_ISV_SVN, '<H', self.attr['isv_svn']),
        }

        self.sigstruct_buf_to_sign = bytearray(128 + 128)

        for field in self.fields.values():
            if field[0] >= offs.SGX_ARCH_ENCLAVE_CSS_MISC_SELECT:
                struct.pack_into(field[1], self.sigstruct_buf_to_sign,
                                 field[0] - offs.SGX_ARCH_ENCLAVE_CSS_MISC_SELECT + 128,
                                 *field[2:])
            else:
                struct.pack_into(field[1], self.sigstruct_buf_to_sign, field[0], *field[2:])

    def gen_signature(self, keyfile):
        proc = subprocess.Popen(
            ['openssl', 'rsa', '-modulus', '-in', keyfile, '-noout'],
            stdout=subprocess.PIPE)
        modulus_out, _ = proc.communicate()
        modulus = bytes.fromhex(modulus_out[8:8+offs.SE_KEY_SIZE*2].decode())
        modulus = bytes(reversed(modulus))

        proc = subprocess.Popen(
            ['openssl', 'sha256', '-binary', '-sign', keyfile],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        signature, _ = proc.communicate(self.sigstruct_buf_to_sign)
        signature = signature[::-1]

        modulus_int = int.from_bytes(modulus, byteorder='little')
        signature_int = int.from_bytes(signature, byteorder='little')

        tmp1 = signature_int * signature_int
        q1_int = tmp1 // modulus_int
        tmp2 = tmp1 % modulus_int
        q2_int = tmp2 * signature_int // modulus_int

        q1 = q1_int.to_bytes(384, byteorder='little') # pylint: disable=invalid-name
        q2 = q2_int.to_bytes(384, byteorder='little') # pylint: disable=invalid-name

        self.fields.update({
            'modulus': (offs.SGX_ARCH_ENCLAVE_CSS_MODULUS, '384s', modulus),
            'exponent': (offs.SGX_ARCH_ENCLAVE_CSS_EXPONENT, '<L', 3),
            'signature': (offs.SGX_ARCH_ENCLAVE_CSS_SIGNATURE, '384s', signature),

            'q1': (offs.SGX_ARCH_ENCLAVE_CSS_Q1, '384s', q1),
            'q2': (offs.SGX_ARCH_ENCLAVE_CSS_Q2, '384s', q2),
        })

        self.sigstruct_buf_final = bytearray(offs.SGX_ARCH_ENCLAVE_CSS_SIZE)

        for field in self.fields.values():
            struct.pack_into(field[1], self.sigstruct_buf_final, field[0], *field[2:])

    def write(self, sigfile):
        with open(sigfile, 'wb') as file:
            file.write(self.sigstruct_buf_final)
        return 0
