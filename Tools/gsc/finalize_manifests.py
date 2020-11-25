#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2020 Intel Corp.
#                    Anjo Vahldiek-Oberwagner <anjo.lucas.vahldiek-oberwagner@intel.com>


import argparse
import os
import re
import subprocess
import sys
import jinja2

def is_ascii(chars):
    return all(ord(c) < 128 for c in chars)

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
                                r'|finalize_manifests\.py'
                                r'|sign_manifests\.py)$')
    exclude_re = re.compile(excluded_paths_regex)
    num_trusted = 0
    trusted_files = ''
    script_file = os.path.basename(__file__)

    for root, _, files in os.walk(root_dir, followlinks=False):
        for file in files:
            filename = os.path.join(root, file)
            if  (not exclude_re.match(filename)
                # The check for ascii-only characters is required, since the manifest syntax does
                # not support other encodings (e.g., UTF-8).
                and is_ascii(filename)
                and os.path.isfile(filename)
                and filename != script_file):
                trusted_files += f'sgx.trusted_files.file{num_trusted} = "file:{filename}"\n'
                num_trusted += 1

    print(f'Found {num_trusted} files in \'{root_dir}\'.')

    return trusted_files

def generate_library_paths():
    ld_paths = subprocess.check_output('ldconfig -v',
                                       stderr=subprocess.PIPE, shell=True).decode().splitlines()

    # Library paths start without whitespace. Libraries found under a path start with an
    # indentation.
    ld_paths = (line for line in ld_paths if not re.match(r'(^\s)', line))

    ld_library_paths = os.getenv('LD_LIBRARY_PATH')

    return ''.join(ld_paths) + (ld_library_paths if ld_library_paths is not None else '')

def get_binary_path(executable):
    path = subprocess.check_output(f'which {executable}',
                                   stderr=subprocess.STDOUT, shell=True).decode()
    return path.replace('\n', '')


argparser = argparse.ArgumentParser()
argparser.add_argument('directory', default='/',
    help='Search the directory tree from this root for files and generate list of trusted files')
argparser.add_argument('manifests',
    nargs='+',
    help='Application-specific manifest files. The first manifest will be used for the entry '
         'point of the docker image. If file does not exist, manifest will be generated '
         'without application-specific values.')

def main(args=None):
    args = argparser.parse_args(args[1:])

    if not os.path.isdir(args.directory):
        argparser.error(f'Could not find directory {args.directory}.')

    trusted_files = generate_trusted_files(args.directory)
    library_paths = generate_library_paths()
    env_path = os.getenv('PATH')

    print(f'LD_LIBRARY_PATH = \'{library_paths}\'\nPATH = \'{env_path}\'.')

    env = jinja2.Environment(loader=jinja2.FileSystemLoader('.'))
    env.globals.update({
                        'library_paths': library_paths,
                        'env_path': env_path
                        })

    trusted_signatures = []

    # To deal with multi-process applications, we allow multiple manifest files to be specified.
    # User must specify manifest files in the order of parent to child. Here we reverse the list
    # of manifests to include the signature files of children in the parent. The actual signatures
    # are generated during 'gsc sign-image' command in a second step.
    for manifest in reversed(args.manifests):
        print(f'{manifest}:')

        executable = manifest[:manifest.rfind('.manifest')] if (
            manifest.rfind('.manifest') != -1) else manifest

        print(f'\tSetting exec file to \'{executable}\'.')

        # Write final manifest file with trusted files and children
        rendered_manifest = env.get_template(manifest).render()
        # Graphene requires binaries to be in the same folder with their manifests.
        # This is a temporary workaround till the next loader update.
        os.symlink(get_binary_path(executable), executable)

        with open(manifest, 'w') as manifest_file:
            manifest_file.write('\n'.join((rendered_manifest,
                                trusted_files,
                                '\n'.join(trusted_signatures),
                                '\n')))

        print(f'\tWrote {manifest}.')

        trusted_signatures.append(f'sgx.trusted_children.child{len(trusted_signatures)}'
                                  f' = "file:{executable}.sig"')

        with open('signing_order.txt', 'a+') as sig_order:
            print(executable, file=sig_order)

if __name__ == '__main__':
    main(sys.argv)
