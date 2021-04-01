# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (c) 2021 Wojtek Porczyk <woju@invisiblethingslab.com>
# Copyright (c) 2020 Intel Corporation
#                    Michał Kowalczyk <mkow@invisiblethingslab.com>

'''
Graphene manifest renderer
'''

import os
import pathlib
import subprocess
import sys
import sysconfig

import click
import jinja2

from . import (
    _CONFIG_PKGLIBDIR,
)

try:
    from . import _offsets as offsets
except ImportError: # no SGX graphene installed, skipping
    class Empty:
        pass
    offsets = Empty() # object() is not sufficient, because it lacks __dict__

def ldd(*args):
    '''
    Args:
        binaries for which to generate manifest trusted files list.
    '''
    # Be careful: We have to skip vdso, which doesn't have a corresponding file on the disk (we
    # assume that such files have paths starting with '/', seems ldd aways prints absolute paths).
    # Also, old ldd (from Ubuntu 16.04) prints vdso differently than newer ones:
    # old:
    #     linux-vdso.so.1 =>  (0x00007ffd31fee000)
    # new:
    #     linux-vdso.so.1 (0x00007ffd31fee000)
    ret = set()
    for line in subprocess.check_output(['ldd', *(os.fspath(i) for i in args)]).decode('ascii'):
        line = line.strip().split()
        if line[1] == '=>' and line[2].startswith('/'):
            ret.add(line[2])
        elif line[0].startswith('/') and line[1].startswith('/'):
            ret.add(line[0])
    return sorted(ret)

def add_globals_from_offsets(env):
    env.globals.update((k, v) for k, v in offsets.__dict__.items()
        if not k.startswith('_'))

def add_globals_from_python(env):
    paths = sysconfig.get_paths()
    env.globals['python_stdlib'] = pathlib.Path(paths['stdlib'])
    env.globals['python_platstdlib'] = pathlib.Path(paths['platstdlib'])
    env.globals['python_purelib'] = pathlib.Path(paths['purelib'])

    # TODO rpm-based distros
    env.globals['python_distlib'] = pathlib.Path(sysconfig.get_path('stdlib',
        vars={'py_version_short': sys.version_info[0]})) / 'dist-packages'

    env.globals['python_get_config_var'] = sysconfig.get_config_var
    env.globals['python_ext_suffix'] = sysconfig.get_config_var('EXT_SUFFIX')

    env.globals['python_get_path'] = sysconfig.get_path
    env.globals['python_get_paths'] = sysconfig.get_paths

    env.globals['python_implementation'] = sys.implementation

def get_runtimedir(libc='glibc'):
    return (pathlib.Path(_CONFIG_PKGLIBDIR) / 'runtime' / libc).resolve()

def get_runtimedir_repo(libc='glibc'):
    # pylint: disable=unused-argument
    return (pathlib.Path(__file__).parent / '../../Runtime').resolve()

def add_globals_from_graphene(env):
    if _CONFIG_PKGLIBDIR.startswith('@'):
        # we're not installed
        env.globals['get_runtimedir'] = get_runtimedir_repo
        env.globals['libos'] = get_runtimedir_repo() / 'libsysdb.so'

    else:
        pkglibdir = pathlib.Path(_CONFIG_PKGLIBDIR)
        env.globals['get_runtimedir'] = get_runtimedir
        env.globals['libos'] = pkglibdir / 'libsysdb.so'

def add_globals_misc(env):
    env.globals['env'] = os.environ
    env.globals['ldd'] = ldd

def make_env():
    env = jinja2.Environment(loader=jinja2.PackageLoader(__package__))
    add_globals_from_graphene(env)
    add_globals_from_offsets(env)
    add_globals_from_python(env)
    add_globals_misc(env)
    return env

_env = make_env()

def render(template, variables=None):
    '''Render template, given as string. Optional variables may be given as mapping.'''
    return _env.from_string(template).render(**(variables or {})) + '\n'

def validate_define(_ctx, _param, values):
    ret = {}
    for value in values:
        try:
            k, v = value.split('=', 1)
        except ValueError:
            k, v = value, True
        ret[k] = v
    return ret

@click.command()
@click.option('--define', '-D', multiple=True, callback=validate_define)
@click.argument('infile', type=click.File('r'))
@click.argument('outfile', type=click.File('w'), default='-')
def main(define, infile, outfile):
    outfile.write(render(infile.read(), define))

if __name__ == '__main__':
    main() # pylint: disable=no-value-for-parameter
