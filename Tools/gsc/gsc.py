#!/usr/bin/env python3

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
def generate_manifest(image, substitutions, user_manifest, binary):

    user_mf = ''
    if os.path.exists(user_manifest):
        with open(user_manifest, 'r') as user_manifest_file:
            user_mf = user_manifest_file.read()

    manifest_path = (pathlib.Path(gsc_image_name(image)) / binary).with_suffix('.manifest')
    with open(manifest_path, 'w') as app_manifest:
        app_manifest.write(substitutions.get_template('manifest.template').render(binary=binary))
        app_manifest.write('\n')
        app_manifest.write(user_mf)
        app_manifest.write('\n')

# Generate app loader script which generates the SGX token and starts the Graphene PAL loader with
# the manifest as an input (see template/apploader.template).
def generate_app_loader(image, substitutions, binary):

    apploader_path = (pathlib.Path(gsc_image_name(image)) / 'apploader').with_suffix('.sh')
    with open(apploader_path, 'w') as apploader:
        apploader.write(substitutions.get_template('apploader.template').render(binary=binary))

# Generate a dockerfile that compiles Graphene and includes the application image. This dockerfile
# is generated from two templates (templates/Dockerfile.$distro.template and
# templates/Dockerfile.distro.gscapp.template). It follows a docker multistage build with two
# stages. The first stage is based on Dockerfile.$distro.template which compiles Graphene for the
# specified distribution. The second stage based on Dockerfile.gscapp.template builds the final
# image based on the previously built Graphene and the base image. In addition, it completes the
# manifest generation and generates the signature.
def generate_dockerfile(image, substitutions, binary):

    dockerfile_path = (pathlib.Path(gsc_image_name(image)) / 'Dockerfile')
    with open(dockerfile_path, 'w') as dockerfile:
        dockerfile.write(substitutions.get_template(
            f'Dockerfile.{substitutions.globals["Distro"]}.template').render(binary=binary))

def prepare_build_context(image, user_manifests, substitutions, binary):
    # create directory for image specific files
    os.makedirs(f'gsc-{image}', exist_ok=True)

    # generate dockerfile to build graphenized docker image
    generate_dockerfile(image, substitutions, binary)

    # generate app specific loader script
    generate_app_loader(image, substitutions, binary)

    # generate manifest stub for this app
    generate_manifest(image, substitutions, user_manifests[0], binary)

    for user_manifest in user_manifests[1:]:

        generate_manifest(image, substitutions, user_manifest,
            user_manifest[user_manifest.rfind('/') + 1 : user_manifest.rfind('.manifest')])

    # copy markTrustedFiles.sh
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
    cmd = remaining_args if len(entrypoint) > last_bin_arg + 1 else ''

    return binary, binary_arguments, cmd

def prepare_substitutions(base_image, image, options, user_manifests):
    substitutions = jinja2.Environment(loader=jinja2.FileSystemLoader('templates/'))

    # default substitutions
    substitutions.globals.update({
        'DEBUG': '',
        'debug_output': 'none',
        'MAKE_LINUX_PAL': ''
    })

    flags = {
        'd': {
                'DEBUG' : 'DEBUG=1',
                'debug_output': 'inline'
            },
        'L': {
                'MAKE_LINUX_PAL': 1
            },
        'G': {
                'GSC_ONLY': 1
        }
    }
    for option in options:
        if options[option]:
            substitutions.globals.update(flags[option])

    # If debug option was selected make sure that the LINUX PAL is compiled with debug as well
    substitutions.globals['MAKE_LINUX_PAL'] = substitutions.globals['MAKE_LINUX_PAL']

    config = load_config('config.yaml')
    substitutions.globals.update(config)

    # Image names follow the format distro/package:tag
    image_re = re.match(r'([^:]*)(:?)(.*)', image[image.rfind('/')+1:])

    # Extract binary and command from base_image
    binary, binary_arguments, cmd = extract_binary_cmd_from_image_config(
                                                            base_image.attrs['Config'])

    working_dir = base_image.attrs['Config']['WorkingDir']

    substitutions.globals.update({
            'appImage' : image,
            'app' : image_re.group(1),
            'binary_arguments' : binary_arguments,
            'cmd' : cmd,
            'working_dir': working_dir,
            'user_manifests': ' '.join([os.path.basename(manifest)
                                        for manifest in user_manifests[1:]])
            })

    return substitutions, binary

# Build graphenized docker image. args has to follow [<options>] <base_image> <app.manifest>
# [<app2.manifest> ...].
def gsc_build(args):

    image = args.image
    user_manifests = args.manifests
    options = vars(args)
    del options['image']
    del options['command']
    del options['manifests']

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

        substitutions, binary = prepare_substitutions(base_image, image, options,
                                                        user_manifests)

        prepare_build_context(image, user_manifests, substitutions, binary)

        docker_api = docker.APIClient(base_url='unix://var/run/docker.sock')
        # docker build returns stream of json output
        stream = docker_api.build(path='gsc-' + image, tag=gsc_image_name(image))

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

def print_build_help():
    print('Build command usage:')
    print('   gsc build [<options>] <image-name>[:<tag>] <app>.manifest [<app2>.manifest ...]')
    print('      Options:')
    print('         -d - compile Graphene with debug')
    print('      image-name - name of the base image to be graphenized')
    print('      tag - tag of the image')
    print('      <app>.manifest - application-specific manifest for the first executable')
    print('      <app2>.manifest -  application-specific manifest for the second executable '
                 '(child of the first executable)')


def print_usage(cmd):
    #pylint: disable=unused-argument
    print('Usage:')
    print('gsc <cmd> [<cmd arguments>]\n')
    print('List of Commands:')
    print('   build - build a graphenized docker image')
    print('   help - print this information\n')

    print_build_help()

    print('\nTo run a graphenized Docker image, execute:')
    print('docker run --device=/dev/gsgx --device=/dev/isgx -v '
        '/var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket [options] gsc-<image-name>[:<tag>]'
        ' [application arguments]')

ARGPARSER = argparse.ArgumentParser()
ARGPARSER.add_argument('command',
    help='Command of GSC')
ARGPARSER.add_argument('-d', required=False, action='store_true',
    help='Compile Graphene with debug flags and output')
ARGPARSER.add_argument('-L', required=False, action='store_true',
    help='Compile Graphene with Linux PAL in addition to Linux-SGX PAL')
ARGPARSER.add_argument('-G', required=False, action='store_true',
    help='Build Graphene only and ignore the application image (useful for Graphene development, '
         'irrelevant for end users of GSC')
ARGPARSER.add_argument('image',
    help='Name of the application Docker image')
ARGPARSER.add_argument('manifests',
    nargs='+',
    help='Application-specific manifest files. The first manifest will be used for the entry '
         'point of the Docker image.')

def main(args):

    args = ARGPARSER.parse_args(args[1:])

    gsc_cmds = {
        'build': gsc_build,
    }

    # GSC command is the first argument if not provided print usage
    cmd = gsc_cmds.get(args.command, print_usage)
    cmd(args)
