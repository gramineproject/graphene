#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2020 Intel Corp.
#                    Anjo Vahldiek-Oberwagner <anjo.lucas.vahldiek-oberagner@intel.com>

import os
import re
import sys
import shutil
import json
import argparse
import pathlib
import yaml
import jinja2

import docker

def gsc_image_name(name):
    return 'gsc-' + name

def load_config(file):
    if not os.path.exists(file):
        print('Please create file named \'config.yaml\' based on the template configuration '
              'file called \'config.yaml.template\'.')
        sys.exit(1)

    with open(file) as config_file:
        return yaml.safe_load(config_file)

# Generate manifest from a template (see template/manifest.template) based on the binary name.
# The generated manifest is only partially completed. Later, during the docker build it is
# finished by adding the list of trusted files, the path to the binary, and LD_LIBRARY_PATH.
def generate_manifest(image, env, user_manifest, binary):

    user_mf = ''
    if os.path.exists(user_manifest):
        with open(user_manifest, 'r') as user_manifest_file:
            user_mf = user_manifest_file.read()

    manifest_path = (pathlib.Path(gsc_image_name(image)) / binary).with_suffix('.manifest')
    with open(manifest_path, 'w') as app_manifest:
        app_manifest.write(env.get_template('manifest.template').render(binary=binary))
        app_manifest.write('\n')
        app_manifest.write(user_mf)
        app_manifest.write('\n')

# Generate app loader script which generates the SGX token and starts the Graphene PAL loader with
# the manifest as an input (see template/apploader.template).
def generate_app_loader(image, env, binary):

    apploader_path = (pathlib.Path(gsc_image_name(image)) / 'apploader').with_suffix('.sh')
    with open(apploader_path, 'w') as apploader:
        apploader.write(env.get_template('apploader.template').render(binary=binary))

# Generate a dockerfile that compiles Graphene and includes the application image. This dockerfile
# is generated from a template (templates/Dockerfile.$distro.template). It follows a docker
# multistage build with two stages. The first stage compiles Graphene for the specified
# distribution. The second stage builds the final image based on the previously built Graphene and
# the base image. In addition, it completes the manifest generation and generates the signature.
def generate_dockerfile(image, env, binary):

    dockerfile_path = (pathlib.Path(gsc_image_name(image)) / 'Dockerfile')
    with open(dockerfile_path, 'w') as dockerfile:
        dockerfile.write(env.get_template(
            f'Dockerfile.{env.globals["Distro"]}.template').render(binary=binary))

def prepare_build_context(image, user_manifests, env, binary):
    # create directory for image specific files
    os.makedirs(f'gsc-{image}', exist_ok=True)

    # generate dockerfile to build graphenized docker image
    generate_dockerfile(image, env, binary)

    # generate app specific loader script
    generate_app_loader(image, env, binary)

    # generate manifest stub for this app
    generate_manifest(image, env, user_manifests[0], binary)

    for user_manifest in user_manifests[1:]:

        generate_manifest(image, env, user_manifest,
            user_manifest[user_manifest.rfind('/') + 1 : user_manifest.rfind('.manifest')])

    fm_path = (pathlib.Path(gsc_image_name(image)) / 'finalize_manifests').with_suffix('.py')
    shutil.copyfile('finalize_manifests.py', fm_path)

def extract_binary_cmd_from_image_config(config):
    entrypoint = config['Entrypoint'] if isinstance(config['Entrypoint'], list) else []
    entrypoint_len = len(entrypoint)
    cmd = config['Cmd'] if isinstance(config['Cmd'], list) else []

    # Some Docker images only use the optional CMD and have an empty entrypoint
    # GSC has to make it explicit to prepare scripts and Intel SGX signatures
    entrypoint.extend(cmd)

    if len(entrypoint) is 0:
        print('Could not find the entrypoint binary to the application image.')
        sys.exit(1)

    # Set binary to first executable in entrypoint
    binary = os.path.basename(entrypoint[0])

    # Check if we have fixed binary arguments as part of entrypoint
    if entrypoint_len > 1:
        last_bin_arg = entrypoint_len
        binary_arguments = '"' + '", "'.join(entrypoint[1: last_bin_arg]) + '"'
    else:
        last_bin_arg = 0
        binary_arguments = ''

    # Place the remaining optional arguments previously specified as command, in the
    # new command. This is necessary, since the first element of the command may be the
    # binary of the resulting image.
    remaining_args = '"' + '", "'.join(entrypoint[last_bin_arg + 1 : ]) + '"'
    cmd = entrypoint[last_bin_arg + 1 : ] if len(entrypoint) > last_bin_arg + 1 else ''

    return binary, binary_arguments, cmd

def prepare_env(base_image, image, args, user_manifests):
    env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates/'))

    env.globals.update({'args': args})
    config = load_config('config.yaml')
    env.globals.update(config)

    # Image names follow the format distro/package:tag
    image_re = re.match(r'([^:]*)(:?)(.*)', image[image.rfind('/')+1:])

    # Extract binary and command from base_image
    binary, binary_arguments, cmd = extract_binary_cmd_from_image_config(
                                                            base_image.attrs['Config'])

    working_dir = base_image.attrs['Config']['WorkingDir']

    env.globals.update({
            'app_image' : image,
            'app' : image_re.group(1),
            'binary_arguments' : binary_arguments,
            'cmd' : cmd,
            'working_dir': working_dir,
            'user_manifests': ' '.join([os.path.basename(manifest)
                                        for manifest in user_manifests[1:]])
            })

    return env, binary

# Build graphenized docker image. args has to follow [<options>] <base_image> <app.manifest>
# [<app2.manifest> ...].
def gsc_build(args):

    image = args.image
    user_manifests = args.manifests

    docker_socket = docker.DockerClient(base_url='unix://var/run/docker.sock')

    try:
        docker_socket.images.get(gsc_image_name(image))
        print(f'Image {gsc_image_name(image)} already exists, no gsc build required.')
        sys.exit(0)

    except (docker.errors.ImageNotFound, docker.errors.APIError):
        try:
            base_image = docker_socket.images.get(image)
        except (docker.errors.ImageNotFound, docker.errors.APIError):
            print(f'Unable to find base image {image}')
            sys.exit(1)

        print(f'Building graphenized image from base image {image}')

        env, binary = prepare_env(base_image, image, args,
                                                        user_manifests)

        prepare_build_context(image, user_manifests, env, binary)

        docker_api = docker.APIClient(base_url='unix://var/run/docker.sock')
        # docker build returns stream of json output
        stream = docker_api.build(path='gsc-' + image, tag=gsc_image_name(image),
                                  nocache=args.no_cache)

        # print continuously the stream of output by docker build
        for chunk in stream:
            json_output = json.loads(chunk.decode(sys.stdout.encoding
                                        if sys.stdout.encoding is not None else 'UTF-8'))
            if 'stream' in json_output:
                for line in json_output['stream'].splitlines():
                    print(line)

        # Check if docker build was successful
        try:
            base_image = docker_socket.images.get(gsc_image_name(image))

            print(f'Successfully graphenized docker image {image} into docker image '
                    + gsc_image_name(image))

        except (docker.errors.ImageNotFound, docker.errors.APIError):
            print(f'Failed to build graphenized image for {image}')
            sys.exit(1)

ARGPARSER = argparse.ArgumentParser()
subcommands = ARGPARSER.add_subparsers(metavar='<command>')
subcommands.required = True
sub_build = subcommands.add_parser('build', help="Build graphenized Docker image")
sub_build.set_defaults(command=gsc_build)
sub_build.add_argument('-d', '--debug', action='store_true',
    help='Compile Graphene with debug flags and output')
sub_build.add_argument('-L', '--linux', action='store_true',
    help='Compile Graphene with Linux PAL in addition to Linux-SGX PAL')
sub_build.add_argument('-G', '--graphene', action='store_true',
    help='Build Graphene only and ignore the application image (useful for Graphene development, '
         'irrelevant for end users of GSC)')
sub_build.add_argument('--insecure-args', action='store_true',
    help='Allow to specify untrusted arguments during Docker run. '
         'Otherwise arguments are ignored.')
sub_build.add_argument('-nc', '--no-cache', action='store_true',
    help='Build graphenized Docker image without any cached images.')
sub_build.add_argument('image',
    help='Name of the application Docker image')
sub_build.add_argument('manifests',
    nargs='+',
    help='Application-specific manifest files. The first manifest will be used for the entry '
         'point of the Docker image.')

def main(args):

    args = ARGPARSER.parse_args()

    return args.command(args)
