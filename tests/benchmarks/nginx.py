# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2020 Intel Corporation
#                    Wojtek Porczyk <woju@invisiblethingslab.com>
#

'''
Nginx benchmark
---------------

This benchmark can be configured with the following environment variables:

.. envvar:: NGINX
    Command executed as nginx server. Default would be equivalent to ``nginx -p . -c nginx.conf`` if
    it was executed from current directory. Unfortunately this is not run from cwd, so always pass
    absolute path to ``-p``.

.. envvar:: AB
    Command executed as ``ab``. Default is ``ab -dSqk -n 10000
    http://127.0.0.1:8002/random/10K.1.html`` and should be in sync with ``NGINX=`` (i.e., the
    URI should be whatever is served by nginx). This variable is treated specially: ``-c`` parameter
    and the concurrency value is added by benchmark just before the last argument, so the ab
    argument parser is not confused.
'''

import os
import pathlib
import shlex
import subprocess

from . import Exec, which

NGINX = shlex.split(os.getenv('NGINX', 'nginx -p {} -c nginx.conf'.format(
    shlex.quote(os.fspath(pathlib.Path(os.getenv('ASV_CONF_DIR')) / 'benchmarks')))))
AB = shlex.split(os.getenv('AB', 'ab -dSqk -n 10000 http://127.0.0.1:8002/random/10K.1.html'))

def _parse_line(line):
    return line.split(':', maxsplit=1)[1].strip().split(maxsplit=1)[0]

def _run_ab(metric, concurrency):
    proc = subprocess.run([*AB[:-1], '-c', str(concurrency), AB[-1]],
        check=True, stdout=subprocess.PIPE)

    found_failed = False
    ret = None
    for line in proc.stdout.decode().split('\n'):
        if line.startswith(metric):
            ret = float(_parse_line(line))
        elif line.startswith('Failed requests:'):
            found_failed = True
            if int(_parse_line(line)):
                raise RuntimeError(line)
        if ret is not None and found_failed:
            return ret
    raise RuntimeError(f'metric not found: {metric!r}')

class Nginx:
    nginx = Exec(which(NGINX[0]), manifest_template='nginx.manifest.template')
    _metric = {
        'latency': 'Time per request',
        'throughput': 'Requests per second',
    }

    params = (
        list(_metric),
        [1, 2, 4, 8, 16, 32, 64, 128, 256],
    )
    param_names = ('metric', 'concurrency')

    def track_native(self, metric, concurrency):
        with self.nginx.native_server(*NGINX[1:]):
            return _run_ab(self._metric[metric], concurrency)

    def track_graphene_nosgx(self, metric, concurrency):
        with self.nginx.graphene_server(*NGINX[1:], sgx=False):
            return _run_ab(self._metric[metric], concurrency)

    def track_graphene_sgx(self, metric, concurrency):
        with self.nginx.graphene_server(*NGINX[1:], sgx=True):
            return _run_ab(self._metric[metric], concurrency)
