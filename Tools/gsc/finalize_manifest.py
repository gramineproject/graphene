#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2020-2021 Intel Corp.
#                         Anjo Vahldiek-Oberwagner <anjo.lucas.vahldiek-oberwagner@intel.com>
#                         Dmitrii Kuvaiskii <dmitrii.kuvaiskii@intel.com>

import argparse
import os
import re
import subprocess
import sys

import jinja2

def is_utf8(string):
    try:
        string.encode('utf-8')
        return True
    except UnicodeError:
        return False


def generate_trusted_files(root_dir):
    cwd = os.getcwd() if os.getcwd() != '/' else ''
    # Exclude files and paths from list of trusted files
    excluded_paths_regex = (r'^/('
                                r'boot/.*'
                                r'|dev/.*'
                                r'|etc/rc(\d|.)\.d/.*'
                                r'|graphene/python/.*'
                                r'|proc/.*'
                                r'|sys/.*'
                                r'|var/.*)'
                            f'|^{cwd}/('
                                r'.*\.manifest'
                                r'|finalize_manifest\.py)$')
    exclude_re = re.compile(excluded_paths_regex)

    num_trusted = 0
    trusted_files = ''
    for root, _, files in os.walk(root_dir, followlinks=False):
        for file in files:
            filename = os.path.join(root, file)
            if exclude_re.match(filename) or not os.path.isfile(filename):
                continue
            if not is_utf8(filename) or '\n' in filename or '\r' in filename:
                # we use TOML's basic single-line UTF-8 strings, can't have newlines
                continue
            escaped_filename = filename.translate(str.maketrans({'\\': r'\\', '"': r'\"'}))
            trusted_files += f'sgx.trusted_files.file{num_trusted} = "file:{escaped_filename}"\n'
            num_trusted += 1

    print(f'\t[from inside Docker container] Found {num_trusted} files in `{root_dir}`.')
    return trusted_files


def generate_library_paths():
    ld_paths = subprocess.check_output('ldconfig -v', stderr=subprocess.PIPE, shell=True)
    ld_paths = ld_paths.decode().splitlines()

    # Library paths start without whitespace (in contrast to libraries found under this path)
    ld_paths = (line for line in ld_paths if not re.match(r'(^\s)', line))
    return ''.join(ld_paths) + os.getenv('LD_LIBRARY_PATH', default='')


argparser = argparse.ArgumentParser()
argparser.add_argument('-d', '--dir', default='/',
    help='Search directory tree from this root to generate list of trusted files.')

def main(args=None):
    args = argparser.parse_args(args[1:])
    if not os.path.isdir(args.dir):
        argparser.error(f'\t[from inside Docker container] Could not find directory `{args.dir}`.')

    env = jinja2.Environment(loader=jinja2.FileSystemLoader('.'))
    env.globals.update({'library_paths': generate_library_paths(), 'env_path': os.getenv('PATH')})

    manifest = 'entrypoint.manifest'
    rendered_manifest = env.get_template(manifest).render()
    trusted_files = generate_trusted_files(args.dir)
    with open(manifest, 'wb') as manifest_file:
        trusted_files_string = '\n'.join((rendered_manifest, trusted_files, '\n'))
        manifest_file.write(trusted_files_string.encode('utf-8'))

    print(f'\t[from inside Docker container] Successfully finalized `{manifest}`.')

if __name__ == '__main__':
    main(sys.argv)
