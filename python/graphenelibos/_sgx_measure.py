#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later */
# Copyright (C) 2014 Stony Brook University
# Copyright (C) 2021 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>

import struct
import hashlib
from pathlib import Path
from . import _offsets as offs # pylint: disable=import-error,no-name-in-module
from . import _sgx_utility as util
from . import _sgx_memory as memory

ZERO_PAGE = bytes(offs.PAGESIZE)

# Populate Enclave Memory

PAGEINFO_R = 0x1
PAGEINFO_W = 0x2
PAGEINFO_X = 0x4
PAGEINFO_TCS = 0x100
PAGEINFO_REG = 0x200

class EnclaveMeasurement:
    def __init__(self, manifest, output_file, libpal_file):
        self.manifest = manifest
        self.output_file = output_file
        self.libpal_file = libpal_file
        self.mrenclave = hashlib.sha256()
        self.attr = self.manifest.get_sgx_attr()
        self.enclave_base, self.enclave_heap_min = self.manifest.get_enclave_info(self.attr)

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
        if flags & PAGEINFO_REG:
            type_ = 'REG'
        if flags & PAGEINFO_TCS:
            type_ = 'TCS'
        prot = ['-', '-', '-']
        if flags & PAGEINFO_R:
            prot[0] = 'R'
        if flags & PAGEINFO_W:
            prot[1] = 'W'
        if flags & PAGEINFO_X:
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
                            flags = flags | PAGEINFO_R
                        if prot & 2:
                            flags = flags | PAGEINFO_W
                        if prot & 1:
                            flags = flags | PAGEINFO_X

                        if flags & PAGEINFO_X:
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

        return self.mrenclave.digest()

    def measure_enclave(self):
        # pylint: disable=too-many-statements,too-many-branches,too-many-locals

        self.manifest.get_client_spid()

        self.manifest.attach_trusted_file_hashs()

        enclave = memory.EnclaveMemory(self.manifest, self.libpal_file)

        # Populate memory areas
        enclave.init_memory_areas()

        self.manifest.output_manifest(self.output_file)

        enclave.load_manifest_file(self.output_file)

        enclave.populate_memory_areas()

        print('Memory:')
        # Generate measurement
        self.mrenclave_final = self.generate_measurement(enclave)
        print('Measurement:')
        print(f'    {self.mrenclave_final.hex()}')

    def get_mrenclave_final(self):
        return self.mrenclave_final

    def get_attr(self):
        return self.attr
