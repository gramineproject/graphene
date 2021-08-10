#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later */
# Copyright (C) 2014 Stony Brook University
# Copyright (C) 2021 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>

import struct
import hashlib
from . import _offsets as offs # pylint: disable=import-error,no-name-in-module
from . import (
    sgx_get_enclave_mem_areas as memory,
    sgx_utils as util
    )

# Generating the final SGX measurement of the enclave (MRENCLAVE) based on the manifest,
# enclave runtime, designated binary and its trusted dependencies.

ZERO_PAGE = bytes(offs.PAGESIZE)

class EnclaveMeasurement:
    def __init__(self, manifest, libpal_file):
        self.manifest = manifest
        self.libpal_file = libpal_file
        self.mrenclave = hashlib.sha256()
        self.attr = self.manifest.get_sgx_attr()
        self.enclave_base, self.enclave_heap_min = self.manifest.get_enclave_addresses(self.attr)

    def do_ecreate(self, size):
        data = struct.pack('<8sLQ44s', b'ECREATE', offs.SSA_FRAME_SIZE // offs.PAGESIZE, size, b'')
        self.mrenclave.update(data)

    def do_eadd(self, offset, flags):
        assert offset < self.attr['enclave_size']
        data = struct.pack('<8sQQ40s', b'EADD', offset, flags, b'')
        self.mrenclave.update(data)

    def do_eextend(self, offset, content):
        assert offset < self.attr['enclave_size']

        if len(content) != 256:
            raise ValueError('Exactly 256 bytes expected')

        data = struct.pack('<8sQ48s', b'EEXTEND', offset, b'')
        self.mrenclave.update(data)
        self.mrenclave.update(content)

    def include_page(self, addr, flags, content, measure):
        if len(content) != offs.PAGESIZE:
            raise ValueError('Exactly one page expected')

        self.do_eadd(addr - self.enclave_base, flags)
        if measure:
            for i in range(0, offs.PAGESIZE, 256):
                self.do_eextend(addr - self.enclave_base + i, content[i:i + 256])

    def print_area(self, addr, size, flags, desc, measured):
        if flags & util.PAGEINFO_REG:
            type_ = 'REG'
        if flags & util.PAGEINFO_TCS:
            type_ = 'TCS'
        prot = ['-', '-', '-']
        if flags & util.PAGEINFO_R:
            prot[0] = 'R'
        if flags & util.PAGEINFO_W:
            prot[1] = 'W'
        if flags & util.PAGEINFO_X:
            prot[2] = 'X'
        prot = ''.join(prot)

        desc = f'({desc})'
        if measured:
            desc += ' measured'

        print(f'    {addr:016x}-{addr+size:016x} [{type_}:{prot}] {desc}')

    def load_file(self, file, offset, addr, filesize, memsize, desc, flags):
        # pylint: disable=too-many-arguments
        f_addr = util.rounddown(offset)
        m_addr = util.rounddown(addr)
        m_size = util.roundup(addr + memsize) - m_addr

        self.print_area(m_addr, m_size, flags, desc, True)

        for page in range(m_addr, m_addr + m_size, offs.PAGESIZE):
            start = page - m_addr + f_addr
            end = start + offs.PAGESIZE
            start_zero = b''
            if start < offset:
                if offset - start >= offs.PAGESIZE:
                    start_zero = ZERO_PAGE
                else:
                    start_zero = bytes(offset - start)
            end_zero = b''
            if end > offset + filesize:
                if end - offset - filesize >= offs.PAGESIZE:
                    end_zero = ZERO_PAGE
                else:
                    end_zero = bytes(end - offset - filesize)
            start += len(start_zero)
            end -= len(end_zero)
            if start < end:
                file.seek(start)
                data = file.read(end - start)
            else:
                data = b''
            if len(start_zero + data + end_zero) != offs.PAGESIZE:
                raise Exception('wrong calculation')

            self.include_page(page, flags, start_zero + data + end_zero, True)

    def generate_measurement(self, enclave):
        # pylint: disable=too-many-statements,too-many-branches,too-many-locals
        print('Memory:')

        self.do_ecreate(self.attr['enclave_size'])

        for area in enclave.get_areas():
            if area.elf_filename is not None:
                with open(area.elf_filename, 'rb') as file:
                    loadcmds = util.get_loadcmds(area.elf_filename)
                    if loadcmds:
                        mapaddr = 0xffffffffffffffff
                        for (offset, addr, filesize, memsize,
                             prot) in loadcmds:
                            if util.rounddown(addr) < mapaddr:
                                mapaddr = util.rounddown(addr)
                    baseaddr_ = area.addr - mapaddr
                    for (offset, addr, filesize, memsize, prot) in loadcmds:
                        flags = area.flags
                        if prot & 4:
                            flags = flags | util.PAGEINFO_R
                        if prot & 2:
                            flags = flags | util.PAGEINFO_W
                        if prot & 1:
                            flags = flags | util.PAGEINFO_X

                        if flags & util.PAGEINFO_X:
                            desc = 'code'
                        else:
                            desc = 'data'
                        self.load_file(file, offset, baseaddr_ + addr, filesize, memsize,
                                  desc, flags)
            else:
                for addr in range(area.addr, area.addr + area.size, offs.PAGESIZE):
                    data = ZERO_PAGE
                    if area.content is not None:
                        start = addr - area.addr
                        end = start + offs.PAGESIZE
                        data = area.content[start:end]
                        data += b'\0' * (offs.PAGESIZE - len(data)) # pad last page
                    self.include_page(addr, area.flags, data, area.measure)

                self.print_area(area.addr, area.size, area.flags, area.desc,
                           area.measure)

        mrenclave_digest = self.mrenclave.digest()
        print('Measurement:')
        print(f'    {mrenclave_digest.hex()}')
        return mrenclave_digest

    def measure_enclave(self):
        enclave_memory = memory.EnclaveMemory(self.manifest, self.libpal_file)
        enclave_memory.init_memory_areas()
        enclave_memory.add_manifest_to_memory_areas()
        enclave_memory.populate_memory_areas()
        self.mrenclave_final = self.generate_measurement(enclave_memory)

    def get_mrenclave_final(self):
        return self.mrenclave_final
