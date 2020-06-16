#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2020 Intel Corp.
#                    Anjo Vahldiek-Oberwagner <anjo.lucas.vahldiek-oberagner@intel.com>

import os
import sys
import subprocess
import re
import argparse
import jinja2

def is_ascii(chars):
    return all(ord(c) < 128 for c in chars)

def generate_trusted_files(root_dir):
    # Exclude directories from list of trusted files
    exclude_dirs = ['boot', 'dev', 'etc/rc', 'proc', 'sys', 'var']
    exclude_re = re.compile('^/(' + '|'.join(exclude_dirs) + ').*')
    num_trusted = 0
    trusted_files = ''
    script_file = os.path.basename(__file__)

    for root, _, files in os.walk(root_dir, followlinks=False):
        for file in files:
            filename = os.path.join(root, file)
            if  (not exclude_re.match(filename)
                and is_ascii(filename)
                and os.path.isfile(filename)
                and filename != script_file):
                trusted_files += f'sgx.trusted_files.file{num_trusted} = file:{filename}\n'
                num_trusted += 1

    print(f'Found {str(num_trusted)} files in \'{root_dir}\'.')

    return trusted_files

def generate_library_paths():
    ld_paths = subprocess.check_output('ldconfig -v',
           stderr=subprocess.PIPE, shell=True).decode().splitlines()

    # Library paths start without whitespace. Libraries found under a path start with an
    # indentation.
    ld_paths = (line for line in ld_paths if not re.match(r'(^\s)', line))

    ld_library_paths = os.getenv('LD_LIBRARY_PATH')

    return ''.join(ld_paths) + (ld_library_paths[1:] if ld_library_paths is not None else '')

def get_binary_path(executable):
    path = subprocess.check_output(f'which {executable}',
           stderr=subprocess.STDOUT, shell=True).decode()
    return path.replace('\n', '')

def generate_signature(manifest):
    sign_process = subprocess.Popen([
        '/graphene/signer/pal-sgx-sign',
        '-libpal', '/graphene/Runtime/libpal-Linux-SGX.so',
        '-key', '/graphene/signer/enclave-key.pem',
        '-output', f'{manifest}.sgx',
        '-manifest', manifest
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    _, err = sign_process.communicate()

    if (sign_process.returncode != 0
        or not os.path.exists(os.path.join(os.getcwd(), manifest + '.sgx'))
        or not os.path.exists(os.path.join(os.getcwd(),
                     manifest[:manifest.rfind('.manifest')] + '.sig'))):
        print(err.decode())
        print('Finalize manifests failed due to pal-sgx-sign failure.')
        sys.exit(1)

# Iterate over manifest file to find enclave size definition and return it
def extract_enclave_size(manifest):
    with open(manifest, 'r') as file:
        for line in file:
            if not line.strip().startswith('sgx.enclave_size'):
                continue

            tokens = line.split('=')
            if len(tokens) != 2 or '#' in tokens[1]:
                continue
            return tokens[1].strip()

    return '0M'

ARGPARSER = argparse.ArgumentParser()
ARGPARSER.add_argument('directory', default='/',
    help='Search the directory tree from this root for files and generate list of trusted files')
ARGPARSER.add_argument('manifests',
    nargs='+',
    help='Application-specific manifest files. The first manifest will be used for the entry '
         'point of the docker image. If file does not exist, manifest will be generated '
         'without application-specific values.')

def main(args=None):
    args = ARGPARSER.parse_args(args[1:])

    if not os.path.isdir(args.directory):
        ARGPARSER.error(f'Could not find directory {args.directory}.')

    trusted_files = generate_trusted_files(args.directory)
    library_paths = generate_library_paths()
    env_path = os.getenv('PATH')

    print(f'LD_LIBRARY_PATH to \'{library_paths}\'\n'f'$PATH to \'{env_path}\'.')

    env = jinja2.Environment(loader=jinja2.FileSystemLoader('.'))
    env.globals.update({
                        'library_paths': library_paths,
                        'env_path': env_path
                        })

    trusted_signatures = []

    # To deal with multi-process applications, we allow multiple manifest files to be specified.
    # User must specify manifest files in the order of parent to child. Here we reverse the list
    # of manifests to include the signatures of children in the parent.
    for manifest in reversed(args.manifests):
        print(f'{manifest}:')

        executable = manifest[:manifest.rfind('.manifest')] if (
                                    manifest.rfind('.manifest') != -1) else manifest
        binary_path = get_binary_path(executable)

        print(f'\tSetting exec file to \'{binary_path}\'.')

        # Write final manifest file with trusted files and children
        rendered_manifest = env.get_template(manifest).render(binary_path=binary_path)
        with open(manifest, 'w') as manifest_file:
            manifest_file.write('\n'.join((rendered_manifest,
                                trusted_files,
                                '\n'.join(trusted_signatures),
                                '\n')))

        print(f'\tWrote {manifest}.')

        generate_signature(manifest)

        print(f'\tGenerated {manifest}.sgx and generated signature.')

        trusted_signatures.append(f'sgx.trusted_children.child{str(len(trusted_signatures))}'
                                  f' = file:{executable}.sig')

    # In case multiple manifest files were generated, ensure that their enclave sizes are compatible
    if len(args.manifests) > 1:
        main_encl_size = extract_enclave_size(args.manifests[0] + '.sgx')
        for manifest in args.manifests[1:]:
            if main_encl_size != extract_enclave_size(manifest + '.sgx'):
                print('Error: Detected a child manifest with an enclave size different than its '
                    'parent.')
                sys.exit(1)

if __name__ == '__main__':
    main(sys.argv)
