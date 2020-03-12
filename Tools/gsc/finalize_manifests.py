#!/usr/bin/env python3

import os
import sys
import subprocess
import re
import string
import argparse

def is_ascii(chars):
    return all(ord(c) < 128 for c in chars)

def generate_trusted_files(root_dir):
    # Exclude directories from list of trusted files
    exclude_dirs = ['boot', 'dev', 'proc', 'var', 'sys', 'etc/rc']
    exclude_re = re.compile('^/(' + '|'.join(exclude_dirs) + ').*')
    num_trusted = 0
    trusted_files = ''
    script_file = os.path.basename(__file__)

    for root, _, files in os.walk(root_dir, followlinks=False):
        for file in files:
            filename = os.path.join(root, file)
            if  (not exclude_re.match(filename)
                and is_ascii(filename)
                and os.path.exists(filename)
                and filename != script_file):
                trusted_files += ('sgx.trusted_files.file' + str(num_trusted)
                                    + ' = file:' + filename + '\n')
                num_trusted += 1

    print('Found ' + str(num_trusted) + ' files in \'' + root_dir + '\'.')

    return trusted_files

def generate_library_paths():
    ld_paths = subprocess.check_output('ldconfig -v',
           stderr=subprocess.PIPE, shell=True).decode().splitlines()

    # Library paths start without whitespace. Libraries found under a path start with an
    # indentation.
    ld_paths = (line for line in ld_paths if not re.match(r'(^\s)', line))

    return ''.join(ld_paths)

def get_binary_path(executable):
    path = subprocess.check_output('which ' + executable,
           stderr=subprocess.STDOUT, shell=True).decode()
    return path.replace('\n', '')

def generate_signature(manifest):
    sign_process = subprocess.Popen([
        '/graphene/signer/pal-sgx-sign',
        '-libpal', '/graphene/Runtime/libpal-Linux-SGX.so',
        '-key', '/graphene/signer/enclave-key.pem',
        '-output', manifest + '.sgx',
        '-manifest', manifest + '.gsc'
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    _, err = sign_process.communicate()

    if (sign_process.returncode is not 0
        or not os.path.exists(os.path.join(os.getcwd(), manifest + '.sgx'))):
        print(err.decode())
        print("Finalize manifests failed due to pal-sgx-sign failure.")
        sys.exit(1)

ARGPARSER = argparse.ArgumentParser()
ARGPARSER.add_argument('finalize_manifests.py', metavar='SCRIPT',
    help='Script to be run.')
ARGPARSER.add_argument('directory', metavar='DIRNAME',
    help='Search the directory tree from this root for files and generate list of trusted files')
ARGPARSER.add_argument('manifests', metavar='APP.manifest',
    nargs='+',
    help='Application-specific manifest files. The first manifest will be used for the entry point '
        + 'of the docker image. If file does not exist, manifest will be generated without '
        + 'application-specific values.')

def main(args=None):
    args = ARGPARSER.parse_args(args)

    if not os.path.isdir(args.directory):
        print('Could not find directory ' + args.directory + '.')
        sys.exit(1)

    trusted_files = generate_trusted_files(args.directory)
    library_paths = generate_library_paths()

    print('Setting LD_LIBRARY_PATH to \'' + library_paths + '\'.')

    trusted_signatures = []

    # To deal with multi-process applications, we allow multiple manifest files to be specified.
    # User must specify manifest files in the order of parent to child. Reverse list of manifests
    # to include signatures of children in parent.
    for manifest in reversed(args.manifests):
        print(manifest + ':')

        executable = manifest[:manifest.rfind('.manifest')] if manifest.rfind('.manifest') != -1 else manifest
        binary_path = get_binary_path(executable)

        print('\tSetting exec file to \'' + binary_path + '\'.')

        with open(manifest, "r") as manifest_file:
            mf_template = string.Template(manifest_file.read())

        mf_instance = mf_template.substitute({
                                'binary_path': binary_path,
                                'library_paths': library_paths
                                })

        # Write final manifest file with trusted files and children
        with open(manifest + '.gsc', "w") as manifest_file:
            manifest_file.write('\n'.join((mf_instance,
                                           trusted_files,
                                           '\n'.join(trusted_signatures),
                                           '\n')))

        print('\tWrote ' + manifest + '.')

        generate_signature(manifest)

        print('\tGenerated ' + manifest + '.sgx and generated signature.')

        trusted_signatures.append('sgx.trusted_children.child' + str(len(trusted_signatures))
                                    + ' = file:' + executable + '.sig')

if __name__ == '__main__':
    main(sys.argv)
