import os
import pathlib
import subprocess


def setup():
    os.environ['SGX'] = '1'

_cwd = pathlib.Path(__file__).parent.absolute()
def _run(stem):
    subprocess.run([os.fspath('../Runtime/pal_loader'), stem + '.manifest.sgx'],
        check=True, cwd=os.fspath(_cwd))

def time_000_helloworld():
    _run('helloworld')

def time_014_write_1e4():
    _run('write_1e4')
def time_015_write_1e5():
    _run('write_1e5')
def time_016_write_1e6():
    _run('write_1e6')
def time_017_write_1e7():
    _run('write_1e7')
