#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2020-2021 Intel Corp.
#                         Anjo Vahldiek-Oberwagner <anjo.lucas.vahldiek-oberwagner@intel.com>
#                         Dmitrii Kuvaiskii <dmitrii.kuvaiskii@intel.com>

import argparse
import jinja2
import json
import os
import pathlib
import re
import shutil
import sys

import docker  # pylint: disable=import-error
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


def build_docker_image(build_path, image_name, dockerfile, **kwargs):
    build_path = str(build_path) # Docker API doesn't under PathLib's PosixPath type
    docker_api = docker.APIClient(base_url = 'unix://var/run/docker.sock')
    stream = docker_api.build(path = build_path, tag = image_name, dockerfile = dockerfile,
                              **kwargs)
    for chunk in stream:
        encoding = sys.stdout.encoding if sys.stdout.encoding is not None else 'UTF-8'
        json_output = json.loads(chunk.decode(encoding))
        if 'stream' in json_output:
            for line in json_output['stream'].splitlines():
                print(line)


def extract_binary_cmd_from_image_config(config):
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

    return binary, binary_arguments, cmd


def extract_working_dir_from_image_config(config):
    working_dir = config['WorkingDir']
    if working_dir == '':
        working_dir = '/'
    elif working_dir[-1] != '/':
        working_dir = working_dir + '/'
    return working_dir


def extract_build_args(args):
    buildargs_dict = {}
    for item in args.build_arg:
        if '=' in item:
            key, value = item.split('=', 1)
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
    image_config = original_image.attrs['Config']
    binary, binary_arguments, cmd = extract_binary_cmd_from_image_config(image_config)
    working_dir = extract_working_dir_from_image_config(image_config)

    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates/'))
    env.globals.update(yaml.safe_load(args.config_file))
    env.globals.update(vars(args))
    env.globals.update({
            'app_image': original_image_name,
            'binary': binary,
            'binary_arguments': binary_arguments,
            'cmd': cmd,
            'working_dir': working_dir,
    })

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

    with open(tmp_build_path / 'entrypoint.manifest', 'w') as entrypoint_manifest:
        entrypoint_manifest.write(env.get_template('entrypoint.manifest.template').render())
        entrypoint_manifest.write('\n')
        entrypoint_manifest.write(user_manifest_contents)
        entrypoint_manifest.write('\n')

    # copy helper script to finalize the manifest from within graphenized Docker image
    shutil.copyfile('finalize_manifest.py', tmp_build_path / 'finalize_manifest.py')

    build_docker_image(tmp_build_path, unsigned_image_name, 'Dockerfile.build', rm = args.rm,
                       nocache = args.no_cache, buildargs = extract_build_args(args))

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

    build_docker_image(tmp_build_path, graphene_image_name, 'Dockerfile.compile', rm=args.rm,
                       nocache=args.no_cache, buildargs = extract_build_args(args))

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
        dockerfile.write(sign_template.render(image = unsigned_image_name))

    # copy user-provided signing key to our tmp build dir (to copy it later inside Docker image)
    tmp_build_key_path = tmp_build_path / 'gsc-signer-key.pem'
    shutil.copyfile(os.path.abspath(args.key), tmp_build_key_path)

    try:
        # forcerm parameter forces removal of intermediate Docker images even after unsuccessful
        # builds, to not leave the signing key lingering in any Docker containers
        build_docker_image(tmp_build_path, signed_image_name, 'Dockerfile.sign', forcerm=True)
    finally:
        os.remove(tmp_build_key_path)

    if get_docker_image(docker_socket, signed_image_name) is None:
        print(f'Failed to build a signed graphenized Docker image `{signed_image_name}`.')
        sys.exit(1)

    print(f'Successfully built a signed Docker image `{signed_image_name}` from '
          f'`{unsigned_image_name}`.')


argparser = argparse.ArgumentParser()
subcommands = argparser.add_subparsers(metavar='<command>')
subcommands.required = True

sub_build = subcommands.add_parser('build', help="Build graphenized Docker image")
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
    help="Build base-Graphene Docker image")
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

sub_sign = subcommands.add_parser('sign-image', help="Sign graphenized Docker image")
sub_sign.set_defaults(command=gsc_sign_image)
sub_sign.add_argument('-c', '--config_file', type=argparse.FileType('r', encoding='UTF-8'),
    default='config.yaml', help='Specify configuration file.')
sub_sign.add_argument('image', help='Name of the application (base) Docker image.')
sub_sign.add_argument('key', help='Key to sign the Intel SGX enclaves inside the Docker image.')

def main(args):
    args = argparser.parse_args()
    return args.command(args)
