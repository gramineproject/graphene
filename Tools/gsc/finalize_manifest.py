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

def is_utf8(filename_bytes):
    try:
        filename_bytes.decode('UTF-8')
        return True
    except UnicodeError:
        return False


def extract_files_from_user_manifest(manifest):
    # files list contains entries as they appear in manifest (i.e., `"file:escaped-file-name"`)
    files = []
    for line in manifest.splitlines():
        line = line.strip()
        if line.startswith((f'sgx.trusted_files', f'sgx.allowed_files', f'sgx.protected_files')):
            if line.count('=') != 1:
                # TODO: process manifest lines like `sgx.allowed_files.a = "file:=weird=file="`
                continue
            filename = line.split('=')[1].strip()
            files.append(filename)
    return files


def generate_trusted_files(root_dir, already_added_files):
    excluded_paths_regex = (r'^/('
                                r'boot/.*'
                                r'|\.dockerenv'
                                r'|\.dockerinit'
                                r'|etc/mtab'
                                r'|dev/.*'
                                r'|etc/rc(\d|.)\.d/.*'
                                r'|graphene/python/.*'
                                r'|finalize_manifest\.py'
                                r'|proc/.*'
                                r'|sys/.*'
                                r'|var/.*)$')
    exclude_re = re.compile(excluded_paths_regex)

    num_trusted = 0
    trusted_files = ''
    for root, _, files in os.walk(root_dir.encode('UTF-8'), followlinks=False):
        for file in files:
            filename = os.path.join(root, file)
            if not os.path.isfile(filename):
                # only regular files are added as trusted files
                continue
            if not is_utf8(filename):
                # we append filenames as TOML strings which must be in UTF-8
                print(f'\t[from inside Docker container] File {filename} is not in UTF-8!')
                sys.exit(1)

            # convert from bytes to str for further string handling
            filename = filename.decode('UTF-8')

            if exclude_re.match(filename):
                # exclude special files and paths from list of trusted files
                continue
            if '\n' in filename:
                # we use TOML's basic single-line strings, can't have newlines
                continue

            escaped_filename = filename.translate(str.maketrans({'\\': r'\\', '"': r'\"'}))
            trusted_file_entry = f'"file:{escaped_filename}"'
            if trusted_file_entry in already_added_files:
                # user manifest already contains this file (probably as allowed or protected)
                continue

            trusted_files += f'sgx.trusted_files.file{num_trusted} = {trusted_file_entry}\n'
            num_trusted += 1

    print(f'\t[from inside Docker container] Found {num_trusted} files in `{root_dir}`.')
    return trusted_files


def generate_library_paths():
    encoding = sys.stdout.encoding if sys.stdout.encoding is not None else 'UTF-8'
    ld_paths = subprocess.check_output('ldconfig -v', stderr=subprocess.PIPE, shell=True)
    ld_paths = ld_paths.decode(encoding).splitlines()

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

    env = jinja2.Environment(loader=jinja2.FileSystemLoader('/'))
    env.globals.update({'library_paths': generate_library_paths(), 'env_path': os.getenv('PATH')})

    manifest = '/entrypoint.manifest'
    rendered_manifest = env.get_template(manifest).render()
    already_added_files = extract_files_from_user_manifest(rendered_manifest)
    trusted_files = generate_trusted_files(args.dir, already_added_files)
    with open(manifest, 'wb') as manifest_file:
        trusted_files_string = '\n'.join((rendered_manifest, trusted_files, '\n'))
        manifest_file.write(trusted_files_string.encode('UTF-8'))

    print(f'\t[from inside Docker container] Successfully finalized `{manifest}`.')

if __name__ == '__main__':
    main(sys.argv)
