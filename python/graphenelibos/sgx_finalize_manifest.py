#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later */
# Copyright (C) 2014 Stony Brook University
# Copyright (C) 2021 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>

import datetime
import toml
import struct
from pathlib import Path
from . import (
    _CONFIG_PKGLIBDIR,
    _offsets as offs,
    sgx_utils as util
    )

# Loading the manifest file, modifying it, and extracting options from it.

ARCHITECTURE = 'amd64'

DEFAULT_ENCLAVE_SIZE = '256M'
DEFAULT_THREAD_NUM = 4

class Manifest:

    def __init__(self, manifest_file, sgx_outfile):
        self.manifest_file = manifest_file
        self.sgx_outfile = sgx_outfile
        self.load()
        self.set_defaults()
        self.attr = None

    def load(self):
        try:
            self.manifest = toml.load(self.manifest_file)
        except toml.TomlDecodeError as exc:
            raise util.ManifestError(f'Parsing {self.manifest_file} as TOML file failed: {exc}')

    def set_defaults(self):
        # set defaults to simplify lookup code (otherwise we'd need to check keys existence each time)

        sgx = self.manifest.setdefault('sgx', {})
        sgx.setdefault('trusted_files', {})
        sgx.setdefault('trusted_checksum', {})
        sgx.setdefault('enclave_size', DEFAULT_ENCLAVE_SIZE)
        sgx.setdefault('thread_num', DEFAULT_THREAD_NUM)
        sgx.setdefault('isvprodid', 0)
        sgx.setdefault('isvsvn', 0)
        sgx.setdefault('remote_attestation', False)
        sgx.setdefault('debug', True)
        sgx.setdefault('require_avx', False)
        sgx.setdefault('require_avx512', False)
        sgx.setdefault('require_mpx', False)
        sgx.setdefault('require_pkru', False)
        sgx.setdefault('support_exinfo', False)
        sgx.setdefault('nonpie_binary', False)
        sgx.setdefault('enable_stats', False)

        loader = self.manifest.setdefault('loader', {})
        loader.setdefault('preload', '')

    def collect_trusted_files(self, check_exist=True, do_hash=True):
        targets = {}

        preload_str = self.manifest['loader']['preload']
        # `filter` below is needed for the case where preload_str == '' (`split` returns [''] then)
        for i, uri in enumerate(filter(None, preload_str.split(','))):
            targets[f'preload{i}'] = uri, util.resolve_uri(uri, check_exist)

        for key, val in self.manifest['sgx']['trusted_files'].items():
            path = Path(util.resolve_uri(val, check_exist))
            if path.is_dir():
                for sub_path in util.walk_dir(path):
                    sub_key = util.path_to_key(str(sub_path))
                    uri = f'file:{sub_path}'
                    targets[sub_key] = uri, sub_path
            else:
                targets[key] = val, path

        if do_hash:
            for key, val in targets.items():
                uri, target = val
                hash_ = util.get_hash(target).hex()
                targets[key] = uri, target, hash_

        return targets

    def get_enclave_attributes(self):
        sgx_flags = {
            'FLAG_DEBUG': struct.pack('<Q', offs.SGX_FLAGS_DEBUG),
            'FLAG_MODE64BIT': struct.pack('<Q', offs.SGX_FLAGS_MODE64BIT),
        }

        sgx_xfrms = {
            'XFRM_LEGACY': struct.pack('<Q', offs.SGX_XFRM_LEGACY),
            'XFRM_AVX': struct.pack('<Q', offs.SGX_XFRM_AVX),
            'XFRM_AVX512': struct.pack('<Q', offs.SGX_XFRM_AVX512),
            'XFRM_MPX': struct.pack('<Q', offs.SGX_XFRM_MPX),
            'XFRM_PKRU': struct.pack('<Q', offs.SGX_XFRM_PKRU),
        }

        sgx_miscs = {
            'MISC_EXINFO': struct.pack('<L', offs.SGX_MISCSELECT_EXINFO),
        }

        manifest_options = [
            ('debug', 'FLAG_DEBUG'),
            ('require_avx', 'XFRM_AVX'),
            ('require_avx512', 'XFRM_AVX512'),
            ('require_mpx', 'XFRM_MPX'),
            ('require_pkru', 'XFRM_PKRU'),
            ('support_exinfo', 'MISC_EXINFO'),
        ]

        attributes = {'XFRM_LEGACY'} # this one always needs to be set in SGX (it means "SSE supported")
        if ARCHITECTURE == 'amd64':
            attributes.add('FLAG_MODE64BIT')

        for opt, flag in manifest_options:
            if self.manifest['sgx'][opt] == 1:
                attributes.add(flag)

        flags_raw = struct.pack('<Q', 0)
        xfrms_raw = struct.pack('<Q', 0)
        miscs_raw = struct.pack('<L', 0)

        for attr in attributes:
            if attr in sgx_flags:
                flags_raw = util.or_bytes(flags_raw, sgx_flags[attr])
            if attr in sgx_xfrms:
                xfrms_raw = util.or_bytes(xfrms_raw, sgx_xfrms[attr])
            if attr in sgx_miscs:
                miscs_raw = util.or_bytes(miscs_raw, sgx_miscs[attr])

        return flags_raw, xfrms_raw, miscs_raw

    def get_sgx_attr(self):
        if self.attr is not None:
            return self.attr

        # Get attributes from manifest
        attr = {}

        manifest_sgx = self.manifest['sgx']

        attr['enclave_size'] = util.parse_size(manifest_sgx['enclave_size'])
        attr['thread_num'] = manifest_sgx['thread_num']
        attr['isv_prod_id'] = manifest_sgx['isvprodid']
        attr['isv_svn'] = manifest_sgx['isvsvn']
        attr['flags'], attr['xfrms'], attr['misc_select'] = self.get_enclave_attributes()
        today = datetime.date.today()
        attr['year'] = today.year
        attr['month'] = today.month
        attr['day'] = today.day

        print('Attributes:')
        print(f'    size:        {attr["enclave_size"]:#x}')
        print(f'    thread_num:  {attr["thread_num"]}')
        print(f'    isv_prod_id: {attr["isv_prod_id"]}')
        print(f'    isv_svn:     {attr["isv_svn"]}')
        print(f'    attr.flags:  {attr["flags"].hex()}')
        print(f'    attr.xfrm:   {attr["xfrms"].hex()}')
        print(f'    misc_select: {attr["misc_select"].hex()}')
        print(f'    date:        {attr["year"]:04d}-{attr["month"]:02d}-{attr["day"]:02d}')

        self.attr = attr
        return self.attr

    def get_sgx_ra_attr(self):
        spid, linkable = None, False
        manifest_sgx = self.manifest['sgx']
        if manifest_sgx['remote_attestation']:
            spid = manifest_sgx.get('ra_client_spid', '')
            linkable = manifest_sgx.get('ra_client_linkable', False)
            print('SGX remote attestation:')
            if not spid:
                print('    DCAP/ECDSA')
            else:
                print(f'    EPID (spid = {spid}, linkable = {linkable})')
        return spid, linkable

    def get_enclave_addresses(self, attr):
        manifest_sgx = self.manifest['sgx']
        if manifest_sgx['nonpie_binary']:
            enclave_base = offs.DEFAULT_ENCLAVE_BASE
            enclave_heap_min = offs.MMAP_MIN_ADDR
        else:
            enclave_base = attr['enclave_size']
            enclave_heap_min = enclave_base
        return enclave_base, enclave_heap_min

    def append_trusted_files_and_hashes(self):
        manifest_sgx = self.manifest['sgx']

        # Use `list()` to ensure non-laziness (`manifest_sgx` is a part of `manifest`, and we'll be
        # changing it while iterating).
        expanded_trusted_files = list(self.collect_trusted_files().items())
        manifest_sgx['trusted_files'] = {} # generate the list from scratch, dropping directory entries
        for key, val in expanded_trusted_files:
            uri, _, hash_ = val
            manifest_sgx['trusted_files'][key] = uri
            manifest_sgx['trusted_checksum'][key] = hash_

    def gen_manifest_sgx_file(self):
        self.append_trusted_files_and_hashes()
        with open(self.sgx_outfile, 'w', encoding='UTF-8') as file:
            file.write('# DO NOT MODIFY. THIS FILE WAS AUTO-GENERATED.\n\n')
            toml.dump(self.manifest, file)

    def get_manifest_sgx(self):
        with open(self.sgx_outfile, 'rb') as file:
            manifest_data = file.read()
        manifest_data += b'\0' # in-memory manifest needs NULL-termination
        return manifest_data

