#!/usr/bin/env python3

import argparse
import datetime
import functools
import hashlib
import os
import struct
import subprocess
import sys

try:
    from . import _offsets as offs # pylint: disable=import-error
except ImportError:
    # when we're in repo, _offsets does not exist and pal-sgx-sign sets sys.path
    # so we can import as follows
    import generated_offsets as offs # pylint: disable=import-error

# pylint: enable=invalid-name

# Default / Architectural Options

ARCHITECTURE = 'amd64'

DEFAULT_ENCLAVE_SIZE = '"256M"'
DEFAULT_THREAD_NUM = 4

# Utilities

ZERO_PAGE = bytes(offs.PAGESIZE)


def roundup(addr):
    remaining = addr % offs.PAGESIZE
    if remaining:
        return addr + (offs.PAGESIZE - remaining)
    return addr


def rounddown(addr):
    return addr - addr % offs.PAGESIZE


def parse_size(value):
    if len(value) < 2 or not value.startswith('"') or not value.endswith('"'):
        raise Exception('Cannot parse size `' + value + '` (must be put in double quotes).')
    value = value[1:-1]

    scale = 1
    if value.endswith('K'):
        scale = 1024
    if value.endswith('M'):
        scale = 1024 * 1024
    if value.endswith('G'):
        scale = 1024 * 1024 * 1024
    if scale != 1:
        value = value[:-1]
    return int(value, 0) * scale


# Reading / Writing Manifests

def read_manifest(filename):
    manifest = dict()
    manifest_layout = []
    with open(filename, 'r', encoding='UTF-8') as file:
        for line in file:
            if line == '':
                manifest_layout.append((None, None))
                break

            pound = line.find('#')
            if pound != -1:
                comment = line[pound:].strip()
                line = line[:pound]
            else:
                comment = None

            line = line.strip()
            equal = line.find('=')
            if equal != -1:
                key = line[:equal].strip()
                manifest[key] = line[equal + 1:].strip()
            else:
                key = None

            manifest_layout.append((key, comment))

    return (manifest, manifest_layout)


def exec_sig_manifest(args):
    sigfile = args['output']
    for ext in ['.manifest.sgx.d', '.manifest.sgx', '.manifest']:
        if sigfile.endswith(ext):
            sigfile = sigfile[:-len(ext)]
            break
    args['sigfile'] = sigfile + '.sig'

    if args.get('libpal', None) is None:
        print('Option --libpal must be given', file=sys.stderr)
        return 1

    return 0


def output_manifest(filename, manifest, manifest_layout):
    with open(filename, 'w', encoding='UTF-8') as file:
        written = []

        file.write('# DO NOT MODIFY. THIS FILE WAS AUTO-GENERATED.\n\n')

        for (key, comment) in manifest_layout:
            line = ''
            if key is not None:
                line += key + ' = ' + manifest[key]
                written.append(key)
            if comment is not None:
                if line != '':
                    line += ' '
                line += comment
            file.write(line)
            file.write('\n')

        file.write('\n')
        file.write('# Generated by Graphene\n')
        file.write('\n')

        for key in sorted(manifest):
            if key not in written:
                file.write('%s = %s\n' % (key, manifest[key]))


# Loading Enclave Attributes

def get_enclave_attributes(manifest):
    sgx_flags = {
        'FLAG_DEBUG': struct.pack('<Q', offs.SGX_FLAGS_DEBUG),
        'FLAG_MODE64BIT': struct.pack('<Q', offs.SGX_FLAGS_MODE64BIT),
    }

    sgx_xfrms = {
        'XFRM_LEGACY': struct.pack('<Q', offs.SGX_XFRM_LEGACY),
        'XFRM_AVX': struct.pack('<Q', offs.SGX_XFRM_AVX),
        'XFRM_AVX512': struct.pack('<Q', offs.SGX_XFRM_AVX512),
        'XFRM_MPX': struct.pack('<Q', offs.SGX_XFRM_MPX),
        'XFRM_PKRU': struct.pack("<Q", offs.SGX_XFRM_PKRU),
    }

    sgx_miscs = {
        'MISC_EXINFO': struct.pack('<L', offs.SGX_MISCSELECT_EXINFO),
    }

    default_attributes = {
        'FLAG_DEBUG',
        'XFRM_LEGACY',
    }

    if ARCHITECTURE == 'amd64':
        default_attributes.add('FLAG_MODE64BIT')

    manifest_options = {
        'debug': 'FLAG_DEBUG',
        'require_avx': 'XFRM_AVX',
        'require_avx512': 'XFRM_AVX512',
        'require_mpx': 'XFRM_MPX',
        'require_pkru': 'XFRM_PKRU',
        'support_exinfo': 'MISC_EXINFO',
    }

    attributes = default_attributes

    for opt in manifest_options:
        key = 'sgx.' + opt
        if key in manifest:
            if manifest[key] == '1':
                attributes.add(manifest_options[opt])
            else:
                attributes.discard(manifest_options[opt])

    flags_raw = struct.pack('<Q', 0)
    xfrms_raw = struct.pack('<Q', 0)
    miscs_raw = struct.pack('<L', 0)

    for attr in attributes:
        if attr in sgx_flags:
            flags_raw = bytes([a | b for a, b in
                               zip(flags_raw, sgx_flags[attr])])
        if attr in sgx_xfrms:
            xfrms_raw = bytes([a | b for a, b in
                               zip(xfrms_raw, sgx_xfrms[attr])])
        if attr in sgx_miscs:
            miscs_raw = bytes([a | b for a, b in
                               zip(miscs_raw, sgx_miscs[attr])])

    return flags_raw, xfrms_raw, miscs_raw


# Generate Checksums / Measurement

def resolve_uri(uri, check_exist=True):
    if len(uri) > 1 and uri.startswith('"') and uri.endswith('"'):
        uri = uri[1:-1]

    orig_uri = uri
    if uri.startswith('file:'):
        target = os.path.normpath(uri[len('file:'):])
    else:
        target = os.path.normpath(uri)
    if check_exist and not os.path.exists(target):
        raise Exception(
            'Cannot resolve ' + orig_uri + ' or the file does not exist.')
    return target


def get_checksum(filename):
    digest = hashlib.sha256()
    with open(filename, 'rb') as file:
        digest.update(file.read())
    return digest.digest()


def get_trusted_files(manifest, check_exist=True, do_checksum=True):
    targets = dict()

    if 'loader.preload' in manifest:
        preload_str = manifest['loader.preload']
        if len(preload_str) < 2 or not preload_str.startswith('"') or not preload_str.endswith('"'):
            raise Exception('Cannot parse loader.preload (value must be put in double quotes).')
        preload_str = preload_str[1:-1]

        for i, uri in enumerate(str.split(preload_str, ',')):
            targets['preload' + str(i)] = (uri, resolve_uri(uri, check_exist))

    for (key, val) in manifest.items():
        if not key.startswith('sgx.trusted_files.'):
            continue
        key = key[len('sgx.trusted_files.'):]
        if key in targets:
            raise Exception(
                'repeated key in manifest: sgx.trusted_files.' + key)
        targets[key] = (val, resolve_uri(val, check_exist))

    if do_checksum:
        for (key, val) in targets.items():
            (uri, target) = val
            checksum = get_checksum(target).hex()
            targets[key] = (uri, target, checksum)

    return targets


# Populate Enclave Memory

PAGEINFO_R = 0x1
PAGEINFO_W = 0x2
PAGEINFO_X = 0x4
PAGEINFO_TCS = 0x100
PAGEINFO_REG = 0x200


def get_loadcmds(elf_filename):
    loadcmds = []
    proc = subprocess.Popen(['readelf', '-l', '-W', elf_filename],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        line = line.decode()
        stripped = line.strip()
        if not stripped.startswith('LOAD'):
            continue
        tokens = stripped.split()
        if len(tokens) < 6:
            continue
        if len(tokens) >= 7 and tokens[7] == 'E':
            tokens[6] += tokens[7]
        prot = 0
        for token in tokens[6]:
            if token == 'R':
                prot = prot | 4
            if token == 'W':
                prot = prot | 2
            if token == 'E':
                prot = prot | 1

        loadcmds.append((int(tokens[1][2:], 16),  # offset
                         int(tokens[2][2:], 16),  # addr
                         int(tokens[4][2:], 16),  # filesize
                         int(tokens[5][2:], 16),  # memsize
                         prot))
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError('Parsing %s as ELF failed' % elf_filename)
    return loadcmds


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
            loadcmds = get_loadcmds(elf_filename)
            mapaddr = 0xffffffffffffffff
            mapaddr_end = 0
            for (_, addr_, _, memsize, _) in loadcmds:
                if rounddown(addr_) < mapaddr:
                    mapaddr = rounddown(addr_)
                if roundup(addr_ + memsize) > mapaddr_end:
                    mapaddr_end = roundup(addr_ + memsize)

            self.size = mapaddr_end - mapaddr
            if mapaddr > 0:
                self.addr = mapaddr

        if self.addr is not None:
            self.addr = rounddown(self.addr)
        if self.size is not None:
            self.size = roundup(self.size)


def get_memory_areas(attr, args):
    areas = []
    areas.append(
        MemoryArea('ssa',
                   size=attr['thread_num'] * offs.SSA_FRAME_SIZE * offs.SSA_FRAME_NUM,
                   flags=PAGEINFO_R | PAGEINFO_W | PAGEINFO_REG))
    areas.append(MemoryArea('tcs', size=attr['thread_num'] * offs.TCS_SIZE,
                            flags=PAGEINFO_TCS))
    areas.append(MemoryArea('tls', size=attr['thread_num'] * offs.PAGESIZE,
                            flags=PAGEINFO_R | PAGEINFO_W | PAGEINFO_REG))

    for _ in range(attr['thread_num']):
        areas.append(MemoryArea('stack', size=offs.ENCLAVE_STACK_SIZE,
                                flags=PAGEINFO_R | PAGEINFO_W | PAGEINFO_REG))
    for _ in range(attr['thread_num']):
        areas.append(MemoryArea('sig_stack', size=offs.ENCLAVE_SIG_STACK_SIZE,
                                flags=PAGEINFO_R | PAGEINFO_W | PAGEINFO_REG))

    areas.append(MemoryArea('pal', elf_filename=args['libpal'], flags=PAGEINFO_REG))
    return areas


def find_areas(areas, desc):
    return [area for area in areas if area.desc == desc]


def find_area(areas, desc, allow_none=False):
    matching = find_areas(areas, desc)

    if not matching and allow_none:
        return None

    if len(matching) != 1:
        raise KeyError('Could not find exactly one MemoryArea "{}"'.format(desc))

    return matching[0]


def entry_point(elf_path):
    env = os.environ
    env['LC_ALL'] = 'C'
    out = subprocess.check_output(
        ['readelf', '-l', '--', elf_path], env=env)
    for line in out.splitlines():
        line = line.decode()
        if line.startswith('Entry point '):
            return int(line[12:], 0)
    raise ValueError('Could not find entry point of elf file')


def gen_area_content(attr, areas, enclave_base, enclave_heap_min):
    # pylint: disable=too-many-locals
    manifest_area = find_area(areas, 'manifest')
    pal_area = find_area(areas, 'pal')
    ssa_area = find_area(areas, 'ssa')
    tcs_area = find_area(areas, 'tcs')
    tls_area = find_area(areas, 'tls')
    stacks = find_areas(areas, 'stack')
    sig_stacks = find_areas(areas, 'sig_stack')

    tcs_data = bytearray(tcs_area.size)

    def set_tcs_field(t, offset, pack_fmt, value):
        struct.pack_into(pack_fmt, tcs_data, t * offs.TCS_SIZE + offset, value)

    tls_data = bytearray(tls_area.size)

    def set_tls_field(t, offset, value):
        struct.pack_into('<Q', tls_data, t * offs.PAGESIZE + offset, value)

    enclave_heap_max = pal_area.addr

    # Sanity check that we measure everything except the heap which is zeroed
    # on enclave startup.
    for area in areas:
        if (area.addr + area.size <= enclave_heap_min or
                area.addr >= enclave_heap_max):
            if not area.measure:
                raise ValueError('Memory area, which is not the heap, is not measured')
        elif area.desc != 'free':
            raise ValueError('Unexpected memory area is in heap range')

    for t in range(0, attr['thread_num']):
        ssa = ssa_area.addr + offs.SSA_FRAME_SIZE * offs.SSA_FRAME_NUM * t
        ssa_offset = ssa - enclave_base
        set_tcs_field(t, offs.TCS_OSSA, '<Q', ssa_offset)
        set_tcs_field(t, offs.TCS_NSSA, '<L', offs.SSA_FRAME_NUM)
        set_tcs_field(t, offs.TCS_OENTRY, '<Q',
                      pal_area.addr + entry_point(pal_area.elf_filename) - enclave_base)
        set_tcs_field(t, offs.TCS_OGS_BASE, '<Q', tls_area.addr - enclave_base + offs.PAGESIZE * t)
        set_tcs_field(t, offs.TCS_OFS_LIMIT, '<L', 0xfff)
        set_tcs_field(t, offs.TCS_OGS_LIMIT, '<L', 0xfff)

        set_tls_field(t, offs.SGX_COMMON_SELF, tls_area.addr + offs.PAGESIZE * t)
        set_tls_field(t, offs.SGX_COMMON_STACK_PROTECTOR_CANARY,
                      offs.STACK_PROTECTOR_CANARY_DEFAULT)
        set_tls_field(t, offs.SGX_ENCLAVE_SIZE, attr['enclave_size'])
        set_tls_field(t, offs.SGX_TCS_OFFSET, tcs_area.addr - enclave_base + offs.TCS_SIZE * t)
        set_tls_field(t, offs.SGX_INITIAL_STACK_ADDR, stacks[t].addr + stacks[t].size)
        set_tls_field(t, offs.SGX_SIG_STACK_LOW, sig_stacks[t].addr)
        set_tls_field(t, offs.SGX_SIG_STACK_HIGH, sig_stacks[t].addr + sig_stacks[t].size)
        set_tls_field(t, offs.SGX_SSA, ssa)
        set_tls_field(t, offs.SGX_GPR, ssa + offs.SSA_FRAME_SIZE - offs.SGX_GPR_SIZE)
        set_tls_field(t, offs.SGX_MANIFEST_SIZE, len(manifest_area.content))
        set_tls_field(t, offs.SGX_HEAP_MIN, enclave_heap_min)
        set_tls_field(t, offs.SGX_HEAP_MAX, enclave_heap_max)

    tcs_area.content = tcs_data
    tls_area.content = tls_data


def populate_memory_areas(attr, areas, enclave_base, enclave_heap_min):
    last_populated_addr = enclave_base + attr['enclave_size']

    for area in areas:
        if area.addr is not None:
            continue

        area.addr = last_populated_addr - area.size
        if area.addr < enclave_heap_min:
            raise Exception('Enclave size is not large enough')
        last_populated_addr = area.addr

    free_areas = []
    for area in areas:
        addr = area.addr + area.size
        if addr < last_populated_addr:
            flags = PAGEINFO_R | PAGEINFO_W | PAGEINFO_X | PAGEINFO_REG
            free_areas.append(
                MemoryArea('free', addr=addr, size=last_populated_addr - addr,
                           flags=flags, measure=False))
            last_populated_addr = area.addr

    if last_populated_addr > enclave_heap_min:
        flags = PAGEINFO_R | PAGEINFO_W | PAGEINFO_X | PAGEINFO_REG
        free_areas.append(
            MemoryArea('free', addr=enclave_heap_min,
                       size=last_populated_addr - enclave_heap_min, flags=flags,
                       measure=False))

    gen_area_content(attr, areas, enclave_base, enclave_heap_min)

    return areas + free_areas

def generate_measurement(enclave_base, attr, areas):
    # pylint: disable=too-many-statements,too-many-branches,too-many-locals

    def do_ecreate(digest, size):
        data = struct.pack('<8sLQ44s', b'ECREATE', offs.SSA_FRAME_SIZE // offs.PAGESIZE,
                           size, b'')
        digest.update(data)

    def do_eadd(digest, offset, flags):
        assert offset < attr['enclave_size']
        data = struct.pack('<8sQQ40s', b'EADD', offset, flags, b'')
        digest.update(data)

    def do_eextend(digest, offset, content):
        assert offset < attr['enclave_size']

        if len(content) != 256:
            raise ValueError('Exactly 256 bytes expected')

        data = struct.pack('<8sQ48s', b'EEXTEND', offset, b'')
        digest.update(data)
        digest.update(content)

    def include_page(digest, addr, flags, content, measure):
        if len(content) != offs.PAGESIZE:
            raise ValueError('Exactly one page expected')

        do_eadd(digest, addr - enclave_base, flags)
        if measure:
            for i in range(0, offs.PAGESIZE, 256):
                do_eextend(digest, addr - enclave_base + i, content[i:i + 256])

    mrenclave = hashlib.sha256()
    do_ecreate(mrenclave, attr['enclave_size'])

    def print_area(addr, size, flags, desc, measured):
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

        desc = '(' + desc + ')'
        if measured:
            desc += ' measured'

        print('    %016x-%016lx [%s:%s] %s' % (addr, addr + size, type_, prot, desc))

    def load_file(digest, file, offset, addr, filesize, memsize, desc, flags):
        # pylint: disable=too-many-arguments
        f_addr = rounddown(offset)
        m_addr = rounddown(addr)
        m_size = roundup(addr + memsize) - m_addr

        print_area(m_addr, m_size, flags, desc, True)

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

            include_page(digest, page, flags, start_zero + data + end_zero, True)

    edmm_enable_heap = attr['edmm_enable_heap']
    for area in areas:
        if area.elf_filename is not None:
            with open(area.elf_filename, 'rb') as file:
                loadcmds = get_loadcmds(area.elf_filename)
                if loadcmds:
                    mapaddr = 0xffffffffffffffff
                    for (offset, addr, filesize, memsize,
                         prot) in loadcmds:
                        if rounddown(addr) < mapaddr:
                            mapaddr = rounddown(addr)
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
                    load_file(mrenclave, file, offset, baseaddr_ + addr, filesize, memsize,
                              desc, flags)
        else:
            # Skip EADDing of heap("free") pages when EDMM is enabled.
            if edmm_enable_heap == 1 and area.desc == "free":
                continue
            for addr in range(area.addr, area.addr + area.size, offs.PAGESIZE):
                data = ZERO_PAGE
                if area.content is not None:
                    start = addr - area.addr
                    end = start + offs.PAGESIZE
                    data = area.content[start:end]
                    data += b'\0' * (offs.PAGESIZE - len(data)) # pad last page
                include_page(mrenclave, addr, area.flags, data, area.measure)

            print_area(area.addr, area.size, area.flags, area.desc,
                       area.measure)

    return mrenclave.digest()


def generate_sigstruct(attr, args, mrenclave):
    '''Generate Sigstruct.

    field format: (offset, type, value)
    ''' # pylint: disable=too-many-locals

    fields = {
        'header': (offs.SGX_ARCH_ENCLAVE_CSS_HEADER,
                   '<4L', 0x00000006, 0x000000e1, 0x00010000, 0x00000000),
        'module_vendor': (offs.SGX_ARCH_ENCLAVE_CSS_MODULE_VENDOR, '<L', 0x00000000),
        'date': (offs.SGX_ARCH_ENCLAVE_CSS_DATE, '<HBB', attr['year'], attr['month'], attr['day']),
        'header2': (offs.SGX_ARCH_ENCLAVE_CSS_HEADER2,
                    '<4L', 0x00000101, 0x00000060, 0x00000060, 0x00000001),
        'hw_version': (offs.SGX_ARCH_ENCLAVE_CSS_HW_VERSION, '<L', 0x00000000),
        'misc_select': (offs.SGX_ARCH_ENCLAVE_CSS_MISC_SELECT, '4s', attr['misc_select']),
        'misc_mask': (offs.SGX_ARCH_ENCLAVE_CSS_MISC_MASK, '4s', attr['misc_select']),
        'attributes': (offs.SGX_ARCH_ENCLAVE_CSS_ATTRIBUTES, '8s8s', attr['flags'], attr['xfrms']),
        'attribute_mask': (offs.SGX_ARCH_ENCLAVE_CSS_ATTRIBUTE_MASK,
                           '8s8s', attr['flags'], attr['xfrms']),
        'enclave_hash': (offs.SGX_ARCH_ENCLAVE_CSS_ENCLAVE_HASH, '32s', mrenclave),
        'isv_prod_id': (offs.SGX_ARCH_ENCLAVE_CSS_ISV_PROD_ID, '<H', attr['isv_prod_id']),
        'isv_svn': (offs.SGX_ARCH_ENCLAVE_CSS_ISV_SVN, '<H', attr['isv_svn']),
    }

    sign_buffer = bytearray(128 + 128)

    for field in fields.values():
        if field[0] >= offs.SGX_ARCH_ENCLAVE_CSS_MISC_SELECT:
            struct.pack_into(field[1], sign_buffer,
                             field[0] - offs.SGX_ARCH_ENCLAVE_CSS_MISC_SELECT + 128,
                             *field[2:])
        else:
            struct.pack_into(field[1], sign_buffer, field[0], *field[2:])

    proc = subprocess.Popen(
        ['openssl', 'rsa', '-modulus', '-in', args['key'], '-noout'],
        stdout=subprocess.PIPE)
    modulus_out, _ = proc.communicate()
    modulus = bytes.fromhex(modulus_out[8:8+offs.SE_KEY_SIZE*2].decode())
    modulus = bytes(reversed(modulus))

    proc = subprocess.Popen(
        ['openssl', 'sha256', '-binary', '-sign', args['key']],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    signature, _ = proc.communicate(sign_buffer)
    signature = signature[::-1]

    modulus_int = int.from_bytes(modulus, byteorder='little')
    signature_int = int.from_bytes(signature, byteorder='little')

    tmp1 = signature_int * signature_int
    q1_int = tmp1 // modulus_int
    tmp2 = tmp1 % modulus_int
    q2_int = tmp2 * signature_int // modulus_int

    q1 = q1_int.to_bytes(384, byteorder='little') # pylint: disable=invalid-name
    q2 = q2_int.to_bytes(384, byteorder='little') # pylint: disable=invalid-name

    fields.update({
        'modulus': (offs.SGX_ARCH_ENCLAVE_CSS_MODULUS, '384s', modulus),
        'exponent': (offs.SGX_ARCH_ENCLAVE_CSS_EXPONENT, '<L', 3),
        'signature': (offs.SGX_ARCH_ENCLAVE_CSS_SIGNATURE, '384s', signature),

        'q1': (offs.SGX_ARCH_ENCLAVE_CSS_Q1, '384s', q1),
        'q2': (offs.SGX_ARCH_ENCLAVE_CSS_Q2, '384s', q2),
    })

    buffer = bytearray(offs.SGX_ARCH_ENCLAVE_CSS_SIZE)

    for field in fields.values():
        struct.pack_into(field[1], buffer, field[0], *field[2:])

    return buffer


# Main Program

argparser = argparse.ArgumentParser(
    epilog='With sign mode (without -depend), libpal and key are also required.')
argparser.add_argument('--output', '-output', metavar='OUTPUT',
                       type=str, required=True,
                       help='Output .manifest.sgx file '
                            '(manifest augmented with autogenerated fields)')
argparser.add_argument('--libpal', '-libpal', metavar='LIBPAL',
                       type=str, required=True,
                       help='Input libpal file '
                            '(required as part of the enclave measurement)')
argparser.add_argument('--key', '-key', metavar='KEY',
                       type=str, required=False,
                       help='specify signing key(.pem) file')
argparser.add_argument('--manifest', '-manifest', metavar='MANIFEST',
                       type=str, required=True,
                       help='Input .manifest file '
                            '(user-prepared manifest template)')
argparser.add_argument('--depend', '-depend',
                       action='store_true', required=False,
                       help='Generate dependency for Makefile')


def parse_args(args):
    args = argparser.parse_args(args)
    args_dict = {
        'output': args.output,
        'libpal': args.libpal,
        'key': args.key,
        'manifest': args.manifest,
    }
    if args.depend:
        args_dict['depend'] = True
    else:
        # key is required and not found in manifest
        if args.key is None:
            argparser.error('a key is required to sign')
            return None

    return args_dict


def main_sign(args):
    # pylint: disable=too-many-statements,too-many-branches,too-many-locals
    manifest, manifest_layout = read_manifest(args['manifest'])

    if exec_sig_manifest(args) != 0:
        return 1

    # Get attributes from manifest
    attr = dict()

    parse_int = functools.partial(int, base=0)

    for key, default, parse, attr_key in [
            ('enclave_size', DEFAULT_ENCLAVE_SIZE, parse_size, 'enclave_size'),
            ('thread_num', str(DEFAULT_THREAD_NUM), parse_int, 'thread_num'),
            ('isvprodid', '0', parse_int, 'isv_prod_id'),
            ('isvsvn', '0', parse_int, 'isv_svn'),
            ('edmm_enable_heap', '0', parse_int, 'edmm_enable_heap'),
    ]:
        attr[attr_key] = parse(manifest.setdefault('sgx.' + key, default))

    (attr['flags'], attr['xfrms'], attr['misc_select']) = get_enclave_attributes(manifest)

    today = datetime.date.today()
    attr['year'] = today.year
    attr['month'] = today.month
    attr['day'] = today.day

    print('Attributes:')
    print('    size:             0x%x' % attr['enclave_size'])
    print('    thread_num:       %d' % attr['thread_num'])
    print('    isv_prod_id:      %d' % attr['isv_prod_id'])
    print('    isv_svn:          %d' % attr['isv_svn'])
    print('    attr.flags:       %016x' % int.from_bytes(attr['flags'], byteorder='big'))
    print('    attr.xfrm:        %016x' % int.from_bytes(attr['xfrms'], byteorder='big'))
    print('    misc_select:      %08x' % int.from_bytes(attr['misc_select'], byteorder='big'))
    print('    date:             %d-%02d-%02d' % (attr['year'], attr['month'], attr['day']))
    print("    edmm_enable_heap: %d" % (attr['edmm_enable_heap']))

    if manifest.get('sgx.remote_attestation', '0') == '1':
        spid = manifest.get('sgx.ra_client_spid', '')
        linkable = manifest.get('sgx.ra_client_linkable', '0')
        print('SGX remote attestation:')
        if not spid:
            print('    DCAP/ECDSA')
        else:
            print('    EPID (spid = %s, linkable = %s)' % (spid, linkable))

    # Get trusted checksums and measurements
    print('Trusted files:')
    for key, val in get_trusted_files(manifest).items():
        (uri, _, checksum) = val
        print('    %s %s' % (checksum, uri))
        manifest['sgx.trusted_checksum.' + key] = '"' + checksum + '"'

    # Try populate memory areas
    memory_areas = get_memory_areas(attr, args)

    if manifest.get('sgx.nonpie_binary', None) == '1':
        enclave_base = offs.DEFAULT_ENCLAVE_BASE
        enclave_heap_min = offs.MMAP_MIN_ADDR
    else:
        enclave_base = attr['enclave_size']
        enclave_heap_min = enclave_base

    if manifest.get('sgx.enable_stats', None) is None:
        manifest['sgx.enable_stats'] = '0'

    output_manifest(args['output'], manifest, manifest_layout)

    with open(args['output'], 'rb') as file:
        manifest_data = file.read()
    manifest_data += b'\0' # in-memory manifest needs NULL-termination

    memory_areas = [
        MemoryArea('manifest', content=manifest_data, size=len(manifest_data),
                   flags=PAGEINFO_R | PAGEINFO_REG)
        ] + memory_areas

    memory_areas = populate_memory_areas(attr, memory_areas, enclave_base, enclave_heap_min)

    print('Memory:')
    # Generate measurement
    mrenclave = generate_measurement(enclave_base, attr, memory_areas)
    print('Measurement:')
    print('    %s' % mrenclave.hex())

    # Generate sigstruct
    with open(args['sigfile'], 'wb') as file:
        file.write(generate_sigstruct(attr, args, mrenclave))
    return 0


def make_depend(args):
    manifest_file = args['manifest']
    output = args['output']

    (manifest, _) = read_manifest(manifest_file)
    if exec_sig_manifest(args) != 0:
        return 1

    dependencies = set()
    for filename in get_trusted_files(manifest, check_exist=False,
                                      do_checksum=False).values():
        dependencies.add(filename[1])
    dependencies.add(args['libpal'])
    dependencies.add(args['key'])

    with open(output, 'w', encoding='UTF-8') as file:
        manifest_sgx = output
        if manifest_sgx.endswith('.d'):
            manifest_sgx = manifest_sgx[:-len('.d')]
        file.write('%s %s:' % (manifest_sgx, args['sigfile']))
        for filename in dependencies:
            file.write(' \\\n\t%s' % filename)
        file.write('\n')

    return 0


def main(args=None):
    args = parse_args(args)
    if args is None:
        return 1

    if args.get('depend'):
        return make_depend(args)
    return main_sign(args)
