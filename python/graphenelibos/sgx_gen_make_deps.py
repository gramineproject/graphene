#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later */
# Copyright (C) 2014 Stony Brook University
# Copyright (C) 2021 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>

# Generator of Makefile dependency files (`.d`): the final Graphene manifest.sgx file depends on
# all trusted-files listed in the manifest, the libpal.so library, and the signer key.

# This is Makefile-specific and will be removed after the complete transition to Meson.

class DependGenerator:

    def __init__(self, manifest, libpal_file, key, sigfile_name):
        self.manifest = manifest
        self.libpal_file = libpal_file
        self.key = key
        self.sigfile_name = sigfile_name

    def generate(self):
        self.dependencies = set()
        for _, filename in self.manifest.collect_trusted_files(check_exist=False,
                                                               do_hash=False).values():
            self.dependencies.add(filename)
        self.dependencies.add(self.libpal_file)
        self.dependencies.add(self.key)

    def write(self, depfile):
        with open(depfile, 'w', encoding='UTF-8') as file:
            manifest_sgx = depfile
            if manifest_sgx.endswith('.d'):
                manifest_sgx = manifest_sgx[:-len('.d')]
            file.write(f'{manifest_sgx} {self.sigfile_name}:')
            for filename in self.dependencies:
                file.write(f' \\\n\t{filename}')
            file.write('\n')
        return 0
