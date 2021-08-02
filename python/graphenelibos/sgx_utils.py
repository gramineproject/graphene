#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later */
# Copyright (C) 2014 Stony Brook University
# Copyright (C) 2021 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>

import os
import hashlib
import subprocess
from pathlib import Path
from sys import stderr
from . import _offsets as offs # pylint: disable=import-error,no-name-in-module

PAGEINFO_R = 0x1
PAGEINFO_W = 0x2
PAGEINFO_X = 0x4
PAGEINFO_TCS = 0x100
PAGEINFO_REG = 0x200

class ManifestError(Exception):
    pass

def resolve_uri(uri, check_exist=True):
    if not uri.startswith('file:'):
        raise ManifestError(f'Unsupported URI type: {uri}')
    path = Path(uri[len('file:'):])
    if check_exist and not path.exists():
        raise ManifestError(f'Cannot resolve {uri} or the file does not exist.')
    return str(path)

def sha256(data):
    sha = hashlib.sha256()
    sha.update(data)
    return sha.digest()

def get_hash(filename):
    with open(filename, 'rb') as file:
        return sha256(file.read())

# TODO: this function should be deleted after we start using TOML lists instead of key-values for
# trusted files.
def path_to_key(path):
    # anything which is unique to the path should do the work
    return sha256(path.encode()).hex()

def walk_dir(path):
    return sorted(filter(Path.is_file, path.rglob('*')))

def get_sigfile_name(manifest_file):
    for ext in ['.manifest.sgx.d', '.manifest.sgx', '.manifest']:
        if manifest_file.endswith(ext):
            sigfile = manifest_file[:-len(ext)]
            break
    else:
        raise ManifestError(f'Unsupported output file type: {manifest_file}')
    return sigfile + '.sig'

def roundup(addr):
    remaining = addr % offs.PAGESIZE
    if remaining:
        return addr + (offs.PAGESIZE - remaining)
    return addr

def rounddown(addr):
    return addr - addr % offs.PAGESIZE

def parse_size(value):
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

def or_bytes(bytes_a, bytes_b):
    return bytes([a | b for a, b in zip(bytes_a, bytes_b)])

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
        raise RuntimeError(f'Parsing {elf_filename} as ELF failed')
    return loadcmds

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
