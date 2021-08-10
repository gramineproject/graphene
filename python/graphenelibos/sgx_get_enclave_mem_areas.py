#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later */
# Copyright (C) 2014 Stony Brook University
# Copyright (C) 2021 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>

import struct
from pathlib import Path
from . import _offsets as offs # pylint: disable=import-error,no-name-in-module
from . import sgx_utils as util

# Collect memory areas that constitute the enclave. Used to generate the final SGX measurement
# (MRENCLAVE) in `sgx_get_enclave_mem_areas.py`.

class MemoryArea:
    # pylint: disable=too-few-public-methods,too-many-instance-attributes
    def __init__(self, desc, elf_filename=None, content=None, addr=None, size=None,
                 flags=None, measure=True):
        # pylint: disable=too-many-arguments
        self.desc = desc
        self.elf_filename = elf_filename
        self.content = content
        self.addr = addr
        self.size = size
        self.flags = flags
        self.measure = measure

        if elf_filename:
            loadcmds = util.get_loadcmds(elf_filename)
            mapaddr = 0xffffffffffffffff
            mapaddr_end = 0
            for (_, addr_, _, memsize, _) in loadcmds:
                if util.rounddown(addr_) < mapaddr:
                    mapaddr = util.rounddown(addr_)
                if util.roundup(addr_ + memsize) > mapaddr_end:
                    mapaddr_end = util.roundup(addr_ + memsize)

            self.size = mapaddr_end - mapaddr
            if mapaddr > 0:
                self.addr = mapaddr

        if self.addr is not None:
            self.addr = util.rounddown(self.addr)
        if self.size is not None:
            self.size = util.roundup(self.size)

class EnclaveMemory:
    def __init__(self, manifest, libpal_file):
        self.manifest = manifest
        self.attr = self.manifest.get_sgx_attr()
        self.libpal_file = libpal_file
        self.areas = []
        self.enclave_base, self.enclave_heap_min = self.manifest.get_enclave_addresses(self.attr)

    def init_memory_areas(self):
        self.areas.append(
            MemoryArea('ssa',
                       size=self.attr['thread_num'] * offs.SSA_FRAME_SIZE * offs.SSA_FRAME_NUM,
                       flags=util.PAGEINFO_R | util.PAGEINFO_W | util.PAGEINFO_REG))
        self.areas.append(MemoryArea('tcs', size=self.attr['thread_num'] * offs.TCS_SIZE,
                                flags=util.PAGEINFO_TCS))
        self.areas.append(MemoryArea('tls', size=self.attr['thread_num'] * offs.PAGESIZE,
                                flags=util.PAGEINFO_R | util.PAGEINFO_W | util.PAGEINFO_REG))

        for _ in range(self.attr['thread_num']):
            self.areas.append(MemoryArea('stack', size=offs.ENCLAVE_STACK_SIZE,
                                    flags=util.PAGEINFO_R | util.PAGEINFO_W | util.PAGEINFO_REG))
        for _ in range(self.attr['thread_num']):
            self.areas.append(MemoryArea('sig_stack', size=offs.ENCLAVE_SIG_STACK_SIZE,
                                    flags=util.PAGEINFO_R | util.PAGEINFO_W | util.PAGEINFO_REG))

        self.areas.append(MemoryArea('pal', elf_filename=self.libpal_file, flags=util.PAGEINFO_REG))

    def find_areas(self, desc):
        return [area for area in self.areas if area.desc == desc]

    def find_area(self, desc, allow_none=False):
        matching = self.find_areas(desc)

        if not matching and allow_none:
            return None

        if len(matching) != 1:
            raise KeyError(f'Could not find exactly one MemoryArea {desc!r}')

        return matching[0]

    def gen_area_content(self):
        # pylint: disable=too-many-locals
        manifest_area = self.find_area('manifest')
        pal_area = self.find_area('pal')
        ssa_area = self.find_area('ssa')
        tcs_area = self.find_area('tcs')
        tls_area = self.find_area('tls')
        stacks = self.find_areas('stack')
        sig_stacks = self.find_areas('sig_stack')

        tcs_data = bytearray(tcs_area.size)

        def set_tcs_field(t, offset, pack_fmt, value):
            struct.pack_into(pack_fmt, tcs_data, t * offs.TCS_SIZE + offset, value)

        tls_data = bytearray(tls_area.size)

        def set_tls_field(t, offset, value):
            struct.pack_into('<Q', tls_data, t * offs.PAGESIZE + offset, value)

        enclave_heap_max = pal_area.addr

        # Sanity check that we measure everything except the heap which is zeroed
        # on enclave startup.
        for area in self.areas:
            if (area.addr + area.size <= self.enclave_heap_min or
                    area.addr >= enclave_heap_max):
                if not area.measure:
                    raise ValueError('Memory area, which is not the heap, is not measured')
            elif area.desc != 'free':
                raise ValueError('Unexpected memory area is in heap range')

        for t in range(0, self.attr['thread_num']):
            ssa = ssa_area.addr + offs.SSA_FRAME_SIZE * offs.SSA_FRAME_NUM * t
            ssa_offset = ssa - self.enclave_base
            set_tcs_field(t, offs.TCS_OSSA, '<Q', ssa_offset)
            set_tcs_field(t, offs.TCS_NSSA, '<L', offs.SSA_FRAME_NUM)
            set_tcs_field(t, offs.TCS_OENTRY, '<Q',
                          pal_area.addr + util.entry_point(pal_area.elf_filename) - self.enclave_base)
            set_tcs_field(t, offs.TCS_OGS_BASE, '<Q', tls_area.addr - self.enclave_base + offs.PAGESIZE * t)
            set_tcs_field(t, offs.TCS_OFS_LIMIT, '<L', 0xfff)
            set_tcs_field(t, offs.TCS_OGS_LIMIT, '<L', 0xfff)

            set_tls_field(t, offs.SGX_COMMON_SELF, tls_area.addr + offs.PAGESIZE * t)
            set_tls_field(t, offs.SGX_COMMON_STACK_PROTECTOR_CANARY,
                          offs.STACK_PROTECTOR_CANARY_DEFAULT)
            set_tls_field(t, offs.SGX_ENCLAVE_SIZE, self.attr['enclave_size'])
            set_tls_field(t, offs.SGX_TCS_OFFSET, tcs_area.addr - self.enclave_base + offs.TCS_SIZE * t)
            set_tls_field(t, offs.SGX_INITIAL_STACK_ADDR, stacks[t].addr + stacks[t].size)
            set_tls_field(t, offs.SGX_SIG_STACK_LOW, sig_stacks[t].addr)
            set_tls_field(t, offs.SGX_SIG_STACK_HIGH, sig_stacks[t].addr + sig_stacks[t].size)
            set_tls_field(t, offs.SGX_SSA, ssa)
            set_tls_field(t, offs.SGX_GPR, ssa + offs.SSA_FRAME_SIZE - offs.SGX_GPR_SIZE)
            set_tls_field(t, offs.SGX_MANIFEST_SIZE, len(manifest_area.content))
            set_tls_field(t, offs.SGX_HEAP_MIN, self.enclave_heap_min)
            set_tls_field(t, offs.SGX_HEAP_MAX, enclave_heap_max)

        tcs_area.content = tcs_data
        tls_area.content = tls_data

    def populate_memory_areas(self):
        last_populated_addr = self.enclave_base + self.attr['enclave_size']

        for area in self.areas:
            if area.addr is not None:
                continue

            area.addr = last_populated_addr - area.size
            if area.addr < self.enclave_heap_min:
                raise Exception('Enclave size is not large enough')
            last_populated_addr = area.addr

        free_areas = []
        for area in self.areas:
            addr = area.addr + area.size
            if addr < last_populated_addr:
                flags = util.PAGEINFO_R | util.PAGEINFO_W | util.PAGEINFO_X | util.PAGEINFO_REG
                free_areas.append(
                    MemoryArea('free', addr=addr, size=last_populated_addr - addr,
                               flags=flags, measure=False))
                last_populated_addr = area.addr

        if last_populated_addr > self.enclave_heap_min:
            flags = util.PAGEINFO_R | util.PAGEINFO_W | util.PAGEINFO_X | util.PAGEINFO_REG
            free_areas.append(
                MemoryArea('free', addr=self.enclave_heap_min,
                           size=last_populated_addr - self.enclave_heap_min, flags=flags,
                           measure=False))

        self.gen_area_content()

        self.areas += free_areas

    def add_manifest_to_memory_areas(self):
        manifest_data = self.manifest.get_manifest_sgx()

        self.areas = [
            MemoryArea('manifest', content=manifest_data, size=len(manifest_data),
                       flags=util.PAGEINFO_R | util.PAGEINFO_REG)
            ] + self.areas

    def get_areas(self):
        return self.areas
