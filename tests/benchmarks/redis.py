'''
Redis benchmark
---------------

This benchmark can be configured with three environment variables:

.. envvar:: REDIS_SERVER
    Full path to redis-server. Default is found in ``$PATH``.

.. envvar:: REDIS_SERVER_ARGS
    Arguments to redis-server. Defaults to ``--save '' --protected-mode no``.
'''

import csv
import os
import shlex
import subprocess

from . import Exec, which

REDIS_BENCHMARK = shlex.split(os.getenv('REDIS_BENCHMARK',
    'redis-benchmark'))
REDIS_SERVER = shlex.split(os.getenv('REDIS_SERVER',
    'redis-server --save "" --protected-mode no'))


def _run_benchmark(t): # pylint: disable=inconsistent-return-statements
    proc = subprocess.run([*REDIS_BENCHMARK, '--csv', '-t', t],
        check=True, stdout=subprocess.PIPE)
    for row in csv.reader(proc.stdout.decode().split('\n')):
        name, value = row
        if name.startswith(t):
            return float(value)
    assert False

class Redis:
    # pylint: disable=no-self-use

    redis_server = Exec(which(REDIS_SERVER[0]), manifest_template='redis-server.manifest.template')
    params = [
        'PING_INLINE', 'PING_BULK', 'SET', 'GET', 'INCR', 'LPUSH', 'RPUSH', 'LPOP',
        'RPOP', 'SADD', 'HSET', 'SPOP', 'LPUSH', 'LRANGE_100', 'LRANGE_300',
        'LRANGE_500', 'LRANGE_600', 'MSET',
    ]
    unit = 'requests/s'
    setup = redis_server.setup

    def track_native(self, t):
        with self.redis_server.native_server(*REDIS_SERVER[1:]):
            return _run_benchmark(t)

    def track_graphene_nosgx(self, t):
        with self.redis_server.graphene_server(*REDIS_SERVER[1:], sgx=False):
            return _run_benchmark(t)

    def track_graphene_sgx(self, t):
        with self.redis_server.graphene_server(*REDIS_SERVER[1:], sgx=True):
            return _run_benchmark(t)
