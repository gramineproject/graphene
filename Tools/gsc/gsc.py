#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2020-2021 Intel Corp.
#                         Anjo Vahldiek-Oberwagner <anjo.lucas.vahldiek-oberwagner@intel.com>
#                         Dmitrii Kuvaiskii <dmitrii.kuvaiskii@intel.com>

import argparse
import json
import hashlib
import os
import pathlib
import shutil
import struct
import sys
import tempfile

import docker  # pylint: disable=import-error
import jinja2
import toml    # pylint: disable=import-error
import yaml    # pylint: disable=import-error

def gsc_image_name(original_image_name):
    return f'gsc-{original_image_name}'

def gsc_unsigned_image_name(original_image_name):
    return f'gsc-{original_image_name}-unsigned'

def gsc_tmp_build_path(original_image_name):
    return pathlib.Path('build') / f'gsc-{original_image_name}'


def get_docker_image(docker_socket, image_name):
    try:
        docker_image = docker_socket.images.get(image_name)
        return docker_image
    except (docker.errors.ImageNotFound, docker.errors.APIError):
        return None


def build_docker_image(docker_api, build_path, image_name, dockerfile, **kwargs):
    build_path = str(build_path) # Docker API doesn't understand PathLib's PosixPath type
    stream = docker_api.build(path=build_path, tag=image_name, dockerfile=dockerfile,
                              **kwargs)
    for chunk in stream:
        encoding = sys.stdout.encoding if sys.stdout.encoding is not None else 'UTF-8'
        json_output = json.loads(chunk.decode(encoding))
        if 'stream' in json_output:
            for line in json_output['stream'].splitlines():
                print(line)


def extract_binary_cmd_from_image_config(config, env):
    entrypoint = config['Entrypoint'] or []
    num_starting_entrypoint_items = len(entrypoint)
    cmd = config['Cmd'] or []

    # Some Docker images only use the optional CMD and have an empty entrypoint;
    # GSC has to make it explicit to prepare scripts and Intel SGX signatures
    entrypoint.extend(cmd)
    if not entrypoint:
        print('Could not find the entrypoint binary to the application image.')
        sys.exit(1)

    # Set binary to first executable in entrypoint
    binary = os.path.basename(entrypoint[0])

    # Check if we have fixed binary arguments as part of entrypoint
    if num_starting_entrypoint_items > 1:
        last_bin_arg = num_starting_entrypoint_items
        escaped_args = [s.replace('\\', '\\\\').replace('"', '\\"')
                        for s in entrypoint[1:last_bin_arg]]
        binary_arguments = '"' + '" "'.join(escaped_args) + '"'
    else:
        last_bin_arg = 0
        binary_arguments = ''

    # Place the remaining optional arguments previously specified as command in the new command.
    # Necessary since the first element of the command may be the binary of the resulting image.
    cmd = entrypoint[last_bin_arg + 1:] if len(entrypoint) > last_bin_arg + 1 else ''
    cmd = [s.replace('\\', '\\\\').replace('"', '\\"') for s in cmd]

    env.globals.update({'binary': binary, 'binary_arguments': binary_arguments, 'cmd': cmd})


def extract_working_dir_from_image_config(config, env):
    working_dir = config['WorkingDir']
    if working_dir == '':
        working_dir = '/'
    elif working_dir[-1] != '/':
        working_dir = working_dir + '/'
    env.globals.update({'working_dir': working_dir})

def extract_environment_from_image_config(config):
    env_list = config['Env']
    base_image_environment = ''
    for env_var in env_list:
        # TODO: switch to loader.env_src_file = "file:file_with_serialized_envs" if
        # the need for multi-line envvars arises
        if '\n' in env_var:
            # we use TOML's basic single-line strings, can't have newlines
            print(f'Skipping environment variable `{env_var.split("=", maxsplit=1)[0]}`: '
                    'its value contains newlines.')
            continue
        escaped_env_var = env_var.translate(str.maketrans({'\\': r'\\', '"': r'\"'}))
        env_var_name = escaped_env_var.split('=', maxsplit=1)[0]
        if env_var_name in ('PATH', 'LD_LIBRARY_PATH'):
            # PATH and LD_LIBRARY_PATH are already part of entrypoint.manifest.template.
            # Their values are provided in finalize_manifest.py, hence skipping here.
            continue
        env_var_value = escaped_env_var.split('=', maxsplit=1)[1]
        base_image_environment += f'loader.env.{env_var_name} = "{env_var_value}"\n'
    return base_image_environment

def extract_build_args(args):
    buildargs_dict = {}
    for item in args.build_arg:
        if '=' in item:
            key, value = item.split('=', maxsplit=1)
            buildargs_dict[key] = value
        else:
            # user specified --build-arg with key and without value, let's retrieve value from env
            if item in os.environ:
                buildargs_dict[item] = os.environ[item]
            else:
                print(f'Could not set build arg `{item}` from environment.')
                sys.exit(1)
    return buildargs_dict


# Command 1: Build unsigned graphenized Docker image from original app Docker image.
def gsc_build(args):
    original_image_name = args.image                           # input original-app image name
    unsigned_image_name = gsc_unsigned_image_name(args.image)  # output unsigned image name
    signed_image_name = gsc_image_name(args.image)             # final signed image name (to check)
    tmp_build_path = gsc_tmp_build_path(args.image)            # pathlib obj with build artifacts

    docker_socket = docker.from_env()

    if get_docker_image(docker_socket, signed_image_name) is not None:
        print(f'Final graphenized image `{signed_image_name}` already exists.')
        sys.exit(0)

    original_image = get_docker_image(docker_socket, original_image_name)
    if original_image is None:
        print(f'Cannot find original application Docker image `{original_image_name}`.')
        sys.exit(1)

    print(f'Building unsigned graphenized Docker image `{unsigned_image_name}` from original '
          f'application image `{original_image_name}`...')

    # initialize Jinja env with configurations extracted from the original Docker image

    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates/'))
    env.globals.update(yaml.safe_load(args.config_file))
    env.globals.update(vars(args))
    env.globals.update({'app_image': original_image_name})
    extract_binary_cmd_from_image_config(original_image.attrs['Config'], env)
    extract_working_dir_from_image_config(original_image.attrs['Config'], env)

    os.makedirs(tmp_build_path, exist_ok=True)

    # generate Dockerfile.build from Jinja-style templates/Dockerfile.<distro>.build.template
    # using the user-provided config file with info on OS distro, Graphene version and SGX driver
    # and other env configurations generated above
    build_template = env.get_template(f'Dockerfile.{env.globals["Distro"]}.build.template')
    with open(tmp_build_path / 'Dockerfile.build', 'w') as dockerfile:
        dockerfile.write(build_template.render())

    # generate apploader.sh from Jinja-style templates/apploader.template
    with open(tmp_build_path / 'apploader.sh', 'w') as apploader:
        apploader.write(env.get_template('apploader.template').render())

    # generate entrypoint.manifest from Jinja-style templates/entrypoint.manifest.template and
    # append additional, user-provided manifest options
    user_manifest_contents = ''
    if os.path.exists(args.manifest):
        with open(args.manifest, 'r') as user_manifest_file:
            user_manifest_contents = user_manifest_file.read()

    # extract base docker image's environment variables to append inside entrypoint.manifest file
    base_image_environment = extract_environment_from_image_config(original_image.attrs['Config'])

    with open(tmp_build_path / 'entrypoint.manifest', 'w') as entrypoint_manifest:
        entrypoint_manifest.write(env.get_template('entrypoint.manifest.template').render())
        entrypoint_manifest.write('\n')
        entrypoint_manifest.write(user_manifest_contents)
        entrypoint_manifest.write('\n')
        entrypoint_manifest.write(base_image_environment)
        entrypoint_manifest.write('\n')

    # copy helper script to finalize the manifest from within graphenized Docker image
    shutil.copyfile('finalize_manifest.py', tmp_build_path / 'finalize_manifest.py')

    build_docker_image(docker_socket.api, tmp_build_path, unsigned_image_name, 'Dockerfile.build',
                       rm=args.rm, nocache=args.no_cache, buildargs=extract_build_args(args))

    # Check if docker build failed
    if get_docker_image(docker_socket, unsigned_image_name) is None:
        print(f'Failed to build unsigned graphenized docker image `{unsigned_image_name}`.')
        sys.exit(1)

    print(f'Successfully built an unsigned graphenized Docker image `{unsigned_image_name}` from '
          f'original application image `{original_image_name}`.')


# Command 2: Build a "base Graphene" Docker image with the compiled runtime of Graphene.
def gsc_build_graphene(args):
    graphene_image_name = gsc_image_name(args.image)  # output base-Graphene image name
    tmp_build_path = gsc_tmp_build_path(args.image)   # pathlib obj with build artifacts

    config = yaml.safe_load(args.config_file)
    if 'Image' in config['Graphene']:
        print('`gsc build-graphene` does not allow `Graphene.Image` to be set.')
        sys.exit(1)

    docker_socket = docker.from_env()

    if get_docker_image(docker_socket, graphene_image_name) is not None:
        print(f'Base-Graphene Docker image `{graphene_image_name}` already exists.')
        sys.exit(0)

    print(f'Building base-Graphene image `{graphene_image_name}`...')

    # generate Dockerfile.compile from Jinja-style templates/Dockerfile.<distro>.compile.template
    # using the user-provided config file with info on OS distro, Graphene version and SGX driver
    # and other user-provided args (see argparser::gsc_build_graphene below)
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates/'))
    env.globals.update(config)
    env.globals.update(vars(args))
    compile_template = env.get_template(f'Dockerfile.{env.globals["Distro"]}.compile.template')

    os.makedirs(tmp_build_path, exist_ok=True)
    with open(tmp_build_path / 'Dockerfile.compile', 'w') as dockerfile:
        dockerfile.write(compile_template.render())

    if args.file_only:
        print(f'Successfully created Dockerfile.compile for base-Graphene image '
              f'`{graphene_image_name}`.')
        return

    build_docker_image(docker_socket.api, tmp_build_path, graphene_image_name, 'Dockerfile.compile',
                       rm=args.rm, nocache=args.no_cache, buildargs=extract_build_args(args))

    if get_docker_image(docker_socket, graphene_image_name) is None:
        print(f'Failed to build a base-Graphene image `{graphene_image_name}`.')
        sys.exit(1)

    print(f'Successfully built a base-Graphene image `{graphene_image_name}`.')


# Command 3: Sign Docker image which was previously built via `gsc build`.
def gsc_sign_image(args):
    unsigned_image_name = gsc_unsigned_image_name(args.image)  # input image name
    signed_image_name = gsc_image_name(args.image)             # output image name
    tmp_build_path = gsc_tmp_build_path(args.image)            # pathlib obj with build artifacts

    docker_socket = docker.from_env()

    unsigned_image = get_docker_image(docker_socket, unsigned_image_name)
    if unsigned_image is None:
        print(f'Cannot find unsigned graphenized Docker image `{unsigned_image_name}`.\n'
              f'You must first build this image via `gsc build` command.')
        sys.exit(1)

    print(f'Signing graphenized Docker image `unsigned_image_name` -> `{signed_image_name}`...')

    # generate Dockerfile.sign from Jinja-style templates/Dockerfile.<distro>.sign.template
    # using the user-provided config file with info on OS distro, Graphene version and SGX driver
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates/'))
    env.globals.update(yaml.safe_load(args.config_file))
    sign_template = env.get_template(f'Dockerfile.{env.globals["Distro"]}.sign.template')

    os.makedirs(tmp_build_path, exist_ok=True)
    with open(tmp_build_path / 'Dockerfile.sign', 'w') as dockerfile:
        dockerfile.write(sign_template.render(image=unsigned_image_name))

    # copy user-provided signing key to our tmp build dir (to copy it later inside Docker image)
    tmp_build_key_path = tmp_build_path / 'gsc-signer-key.pem'
    shutil.copyfile(os.path.abspath(args.key), tmp_build_key_path)

    try:
        # `forcerm` parameter forces removal of intermediate Docker images even after unsuccessful
        # builds, to not leave the signing key lingering in any Docker containers
        build_docker_image(docker_socket.api, tmp_build_path, signed_image_name, 'Dockerfile.sign',
                           forcerm=True)
    finally:
        os.remove(tmp_build_key_path)

    if get_docker_image(docker_socket, signed_image_name) is None:
        print(f'Failed to build a signed graphenized Docker image `{signed_image_name}`.')
        sys.exit(1)

    print(f'Successfully built a signed Docker image `{signed_image_name}` from '
          f'`{unsigned_image_name}`.')


# Simplified version of read_sigstruct from python/graphenelibos/sgx_get_token.py
def read_sigstruct(sig):
    # Offsets for fields in SIGSTRUCT (defined by the SGX HW architecture, they never change)
    SGX_ARCH_ENCLAVE_CSS_DATE = 20
    SGX_ARCH_ENCLAVE_CSS_MODULUS = 128
    SGX_ARCH_ENCLAVE_CSS_ENCLAVE_HASH = 960
    SGX_ARCH_ENCLAVE_CSS_ISV_PROD_ID = 1024
    SGX_ARCH_ENCLAVE_CSS_ISV_SVN = 1026
    # Field format: (offset, type, value)
    fields = {
        'date': (SGX_ARCH_ENCLAVE_CSS_DATE, '<HBB', 'year', 'month', 'day'),
        'modulus': (SGX_ARCH_ENCLAVE_CSS_MODULUS, '384s', 'modulus'),
        'enclave_hash': (SGX_ARCH_ENCLAVE_CSS_ENCLAVE_HASH, '32s', 'enclave_hash'),
        'isv_prod_id': (SGX_ARCH_ENCLAVE_CSS_ISV_PROD_ID, '<H', 'isv_prod_id'),
        'isv_svn': (SGX_ARCH_ENCLAVE_CSS_ISV_SVN, '<H', 'isv_svn'),
    }
    attr = {}
    for field in fields.values():
        values = struct.unpack_from(field[1], sig, field[0])
        for i, value in enumerate(values):
            attr[field[i + 2]] = value

    return attr

# Retrieve information about a previously built graphenized Docker image
def gsc_info_image(args):
    docker_socket = docker.from_env()
    gsc_image = get_docker_image(docker_socket, args.image)
    if gsc_image is None:
        print(f'Could not find graphenized Docker image {args.image}.\n'
              'Please make sure to build the graphenized image first by using \'gsc build\''
              ' command.')
        sys.exit(1)

    # Create temporary directory on the host for sigstruct file
    with tempfile.TemporaryDirectory() as tmpdirname:
        # Copy sigstruct file from Docker container into temporary directory on the host
        docker_socket.containers.run(args.image,
                                 '\'cp entrypoint.sig /tmp/host/ 2>/dev/null || :\'',
                                 entrypoint=['sh', '-c'], remove=True,
                                 volumes={tmpdirname: {'bind': '/tmp/host', 'mode': 'rw'}})
        sigstruct = {}
        with open(os.path.join(tmpdirname, "entrypoint.sig"), 'rb') as sig:
            attr = read_sigstruct(sig.read())
            # calculate MRSIGNER as sha256 hash over RSA public key's modulus
            mrsigner = hashlib.sha256()
            mrsigner.update(attr['modulus'])
            sigstruct['mr_enclave'] = attr['enclave_hash'].hex()
            sigstruct['mr_signer'] = mrsigner.digest().hex()
            sigstruct['isv_prod_id'] = attr['isv_prod_id']
            sigstruct['isv_svn'] = attr['isv_svn']
            sigstruct['date'] = '%d-%02d-%02d' % (attr['year'], attr['month'], attr['day'])

        if not sigstruct:
            print(f'Could not extract Intel SGX-related information from image {args.image}.')
            sys.exit(1)

        print(toml.dumps(sigstruct))


argparser = argparse.ArgumentParser()
subcommands = argparser.add_subparsers(metavar='<command>')
subcommands.required = True

sub_build = subcommands.add_parser('build', help='Build graphenized Docker image')
sub_build.set_defaults(command=gsc_build)
sub_build.add_argument('-d', '--debug', action='store_true',
    help='Compile Graphene with debug flags and output.')
sub_build.add_argument('-L', '--linux', action='store_true',
    help='Compile Graphene with Linux PAL in addition to Linux-SGX PAL.')
sub_build.add_argument('--insecure-args', action='store_true',
    help='Allow to specify untrusted arguments during Docker run. '
         'Otherwise arguments are ignored.')
sub_build.add_argument('-nc', '--no-cache', action='store_true',
    help='Build graphenized Docker image without any cached images.')
sub_build.add_argument('--rm', action='store_true',
    help='Remove intermediate Docker images when build is successful.')
sub_build.add_argument('--build-arg', action='append', default=[],
    help='Set build-time variables (same as "docker build --build-arg").')
sub_build.add_argument('-c', '--config_file', type=argparse.FileType('r', encoding='UTF-8'),
    default='config.yaml', help='Specify configuration file.')
sub_build.add_argument('image', help='Name of the application Docker image.')
sub_build.add_argument('manifest', help='Manifest file to use.')

sub_build_graphene = subcommands.add_parser('build-graphene',
    help='Build base-Graphene Docker image')
sub_build_graphene.set_defaults(command=gsc_build_graphene)
sub_build_graphene.add_argument('-d', '--debug', action='store_true',
    help='Compile Graphene with debug flags and output.')
sub_build_graphene.add_argument('-L', '--linux', action='store_true',
    help='Compile Graphene with Linux PAL in addition to Linux-SGX PAL.')
sub_build_graphene.add_argument('-nc', '--no-cache', action='store_true',
    help='Build graphenized Docker image without any cached images.')
sub_build_graphene.add_argument('--rm', action='store_true',
    help='Remove intermediate Docker images when build is successful.')
sub_build_graphene.add_argument('--build-arg', action='append', default=[],
    help='Set build-time variables (same as "docker build --build-arg").')
sub_build_graphene.add_argument('-c', '--config_file',
    type=argparse.FileType('r', encoding='UTF-8'),
    default='config.yaml', help='Specify configuration file.')
sub_build_graphene.add_argument('-f', '--file-only', action='store_true',
    help='Stop after Dockerfile is created and do not build the Docker image.')
sub_build_graphene.add_argument('image',
    help='Name of the output base-Graphene Docker image.')

sub_sign = subcommands.add_parser('sign-image', help='Sign graphenized Docker image')
sub_sign.set_defaults(command=gsc_sign_image)
sub_sign.add_argument('-c', '--config_file', type=argparse.FileType('r', encoding='UTF-8'),
    default='config.yaml', help='Specify configuration file.')
sub_sign.add_argument('image', help='Name of the application (base) Docker image.')
sub_sign.add_argument('key', help='Key to sign the Intel SGX enclaves inside the Docker image.')

sub_info = subcommands.add_parser('info-image', help='Retrieve information about a graphenized '
                                  'Docker image')
sub_info.set_defaults(command=gsc_info_image)
sub_info.add_argument('image', help='Name of the graphenized Docker image.')

def main(args):
    args = argparser.parse_args()
    return args.command(args)
