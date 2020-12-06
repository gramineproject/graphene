# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2020 Intel Corporation
#                    Wojtek Porczyk <woju@invisiblethingslab.com>
#

import contextlib
import os
import pathlib
import shlex
import string
import subprocess
import time


class MesonTemplate(string.Template):
    pattern = '''
        @(?:
            (?P<escaped>@) |
            (?P<named>[A-Za-z0-9_]+)@ |
            (?P<braced>[A-Za-z0-9_]+)@ |
            (?P<invalid>)
        )
    '''

def which(command):
    return subprocess.run('command -v {}'.format(shlex.quote(command)),
        shell=True, check=True, stdout=subprocess.PIPE).stdout.strip().decode()

class Exec:
    def __init__(self, executable, manifest_template, **kwds):
        self.executable = pathlib.Path(executable)
        self.manifest_template = manifest_template
        self.template_vars = kwds

    @property
    def graphene_path(self):
        return pathlib.Path(os.environ['ASV_BUILD_DIR'])

    @property
    def conf_path(self):
        return pathlib.Path(os.environ['ASV_CONF_DIR']) / 'benchmarks'

    @property
    def benchmarks_path(self):
        return self.graphene_path / 'tests/benchmarks'

    @property
    def manifest_path(self):
        return (self.benchmarks_path / self.executable.name).with_suffix('.manifest')

    @property
    def manifest_sgx_path(self):
        return self.manifest_path.with_suffix('.manifest.sgx')

    @property
    def executable_path(self):
        return self.benchmarks_path / self.executable.name


    def setup(self, *_args):
        self.benchmarks_path.mkdir(parents=True, exist_ok=True)
        try:
            self.executable_path.unlink()
        except FileNotFoundError:
            pass
        self.executable_path.symlink_to(self.conf_path / self.executable)

        with open(self.conf_path / self.manifest_template) as file:
            template = MesonTemplate(file.read())

        with open(self.manifest_path, 'w') as file:
            file.write(template.substitute(
                GRAPHENEDIR=os.environ['ASV_BUILD_DIR'],
                ARCH_LIBDIR='/lib/x86_64-linux-gnu',
                **self.template_vars))

        signer_path = self.graphene_path / 'Pal/src/host/Linux-SGX/signer'

        subprocess.run([os.fspath(signer_path / 'pal-sgx-sign'),
            '--manifest', os.fspath(self.manifest_path),
            '--output', os.fspath(self.manifest_sgx_path),
            '--key', os.fspath(signer_path / 'enclave-key.pem'),
            '--libpal', os.fspath(self.graphene_path / 'Runtime/libpal-Linux-SGX.so'),
        ], check=True, stdout=subprocess.PIPE)

        subprocess.run([os.fspath(signer_path / 'pal-sgx-get-token'),
            '--sig', os.fspath(self.manifest_path.with_suffix('.sig')),
            '--output', os.fspath(self.manifest_path.with_suffix('.token')),
        ], check=True, stdout=subprocess.PIPE)

    def add_setup(self, func):
        func.setup = self.setup
        return func

    @staticmethod
    def _set_sgx(sgx):
        if sgx:
            os.environ['SGX'] = '1'
        else:
            os.environ.pop('SGX', None)

    @property
    def pal_loader(self):
        return os.fspath(self.graphene_path / 'Runtime/pal_loader')


    def run_in_graphene(self, *args, sgx=True):
        self._set_sgx(sgx)
        return subprocess.run([self.pal_loader, os.fspath(self.manifest_sgx_path), *args],
            check=True, cwd=self.benchmarks_path)

    @contextlib.contextmanager
    def graphene_server(self, *args, sgx=True, sleep=30):
        self._set_sgx(sgx)

        try:
            server = subprocess.Popen(
                [self.pal_loader, os.fspath(self.manifest_sgx_path), *args],
                cwd=self.benchmarks_path)
            if sleep > 0:
                time.sleep(sleep) # so the server starts
            yield

        finally:
            server.kill()
            server.wait()

    @contextlib.contextmanager
    def native_server(self, *args, sleep=5):
        try:
            server = subprocess.Popen([os.fspath(self.executable), *args])
            if sleep > 0:
                time.sleep(sleep) # so the server starts
            yield

        finally:
            server.kill()
            server.wait()
