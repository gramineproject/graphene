#!/usr/bin/env python3

import json
import os
import re
import sys
import string
import shutil

import docker

def gsc_image_name(name):
    return "gsc-" + name

def load_config(file):
    with open(file) as json_config_file:
        return json.load(json_config_file)

# Generate manifest from a template (see template/manifest.template) based on the binary name.
# The generated manifest is only partially completed. Later, during the docker build it is
# finished by adding the list of trusted files, the path to the binary, and LD_LIBRARY_PATH.
def generate_manifest(image, substitutions, user_manifest, binary):
    substitutions.update({'bin_name': binary})

    with open(user_manifest) as user_manifest_file:
        user_mf = user_manifest_file.read()

    with open('templates/manifest.template') as manifest_template:
        template_mf = string.Template(manifest_template.read())
        instantiated_mf = template_mf.substitute(substitutions)

    with open(image + '/' + binary + '.manifest', 'w') as app_manifest:
        app_manifest.write(instantiated_mf)
        app_manifest.write("\n")
        app_manifest.write(user_mf)
        app_manifest.write("\n")

# Generate app loader script which generates the SGX token and starts the Graphene PAL loader with
# the manifest as an input (see template/apploader.template).
def generate_app_loader(image, app, binary, binary_arguments):
    with open('templates/apploader.template') as apl:
        template_apl = string.Template(apl.read())
        instantiated_apl = template_apl.substitute({
                    'app' : app,
                    'binary' : binary,
                    'binary_arguments': binary_arguments})

    with open(image + '/apploader.sh', 'w') as apploader:
        apploader.write(instantiated_apl)

# Generate a dockerfile that compiles Graphene and includes the application image. This dockerfile
# is generated from two templates (templates/Dockerfile.$distro.template and
# templates/Dockerfile.distro.gscapp.template). It follows a docker multistage build with two
# stages. The first stage is based on Dockerfile.$distro.template which compiles Graphene for the
# specified distribution. The second stage based on Dockerfile.gscapp.template builds the final
# image based on the previously built Graphene and the base image. In addition, it completes the
# manifest generation and generates the signature.
def generate_dockerfile(image, substitutions, app, binary):
    config = load_config('config.json')
    if not config['sgxdriver_version']:
        config.update({'sgxdriver_version': "master"})

    config.update(substitutions)

    # generate stage 1 from distribution template
    with open('templates/Dockerfile.' + config['distro'] + '.template') as dfg:
        template_dfg = string.Template(dfg.read())
        instantiated_dfg = template_dfg.substitute(config)

    # generate 2nd stage (based on application image)
    with open('templates/Dockerfile.' + config['distro'] + '.gscapp.template') as dfapp:
        substitutions.update({
            "appImage" : image,
            "app" : app,
            "binary" : binary
            })
        template_dfapp = string.Template(dfapp.read())
        instantiated_dfapp = template_dfapp.substitute(substitutions)

    with open(image + "/Dockerfile", "w") as dockerfile:
        dockerfile.write(instantiated_dfg)
        dockerfile.write(instantiated_dfapp)

def prepare_build_context(image, user_manifest, substitutions, app, binary, binary_arguments):
    # create directory for image specific files
    os.makedirs(image, exist_ok=True)

    # generate dockerfile to build graphenized docker image
    generate_dockerfile(image, substitutions, app, binary)

    # generate app specific loader script
    generate_app_loader(image, app, binary, binary_arguments)

    # generate manifest stub for this app
    generate_manifest(image, substitutions, user_manifest, binary)

    # copy markTrustedFiles.sh
    shutil.copyfile("markTrustedFiles.sh", image + "/markTrustedFiles.sh")


def prepare_arguments_and_build_context(base_image, image, user_manifest, options):
    # image names follow the format distro/package:tag
    image_re = re.match(r'([^:]*)(:?)(.*)', image)
    if image_re.group(1):
        app = image_re.group(1)

    # remove possible distroname (i.e., ubuntu/app)
    app = app.split('/')[-1]

    # find command of image from base_image
    cmd = ' '.join(base_image.attrs['Config']['Cmd'])
    # remove /bin/sh -c prefix and extract binary and arguments
    cmd = cmd[cmd.startswith('[/bin/sh -c ') and len('[/bin/sh -c ') : ]
    split = cmd.split(None, 1)
    binary = split[0]
    binary_arguments = split[1] if len(split) > 1 else ""

    params = {
        '-d': {
                'DEBUG' : 'DEBUG=1',
                'debug_output': 'inline'
            },
        '-L': {
                'MAKE_LINUX_PAL': ' && make {DEBUG} WERROR=1'
            }
    }
    # default substitutions
    substitutions = {
        'DEBUG': '',
        'debug_output': 'none',
        'MAKE_LINUX_PAL': ''
    }

    for option in options:
        substitutions.update(params[option])

    # If debug option was selected make sure that the LINUX PAL is compiled with debug as well
    substitutions['MAKE_LINUX_PAL'] = substitutions['MAKE_LINUX_PAL'].format(
                                        DEBUG=substitutions['DEBUG'])

    prepare_build_context(image, user_manifest, substitutions, app, binary, binary_arguments)

# Build graphenized docker image. args has to follow <app manifest> <base_image> [<options>].
def gsc_build(args):
    if len(args) < 2:
        print("Too few arguments to command build")
        print_build_help()
        sys.exit(1)

    docker_socket = docker.DockerClient(base_url='unix://var/run/docker.sock')

    user_manifest = args[0]
    image = args[1]

    try:
        docker_socket.images.get(gsc_image_name(image))
        print("Image " + gsc_image_name(image) + " already exists, no gsc build required.")
        sys.exit(0)

    except (docker.errors.ImageNotFound, docker.errors.APIError):
        try:
            base_image = docker_socket.images.get(image)
        except (docker.errors.ImageNotFound, docker.errors.APIError):
            print("Unable to find base image " + image)
            sys.exit(1)

        print("Building graphenized image from base image " + image)
        prepare_arguments_and_build_context(base_image, image, user_manifest, args[2:])

        docker_api = docker.APIClient(base_url='unix://var/run/docker.sock')
        # docker build returns stream of json output
        stream = docker_api.build(path=image, tag=gsc_image_name(image))

        # print continuously the stream of output by docker build
        for chunk in stream:
            json_output = json.loads(chunk.decode('utf-8'))
            if 'stream' in json_output:
                for line in json_output['stream'].splitlines():
                    print(line)

        # Check if docker build was successful
        try:
            base_image = docker_socket.images.get(gsc_image_name(image))

            print("Successfully graphenized docker image " + image + " into docker image "
                    + gsc_image_name(image))

        except (docker.errors.ImageNotFound, docker.errors.APIError):
            print("Failed to build graphenized image for " + image)
            sys.exit(1)

def print_build_help():
    print("Build command usage:")
    print("   gsc build <manifest> <image name>[:<tag>] [<options>]")
    print("      manifest - application specific manifest to be included in the generated manifest")
    print("      image name - name of the base image to be graphenized")
    print("      tag - tag of the image\n")
    print("      Options:")
    print("         -d - compile Graphene with debug")

def print_usage(cmd):
    #pylint: disable=unused-argument
    print("Usage:")
    print("gsc <cmd> [<cmd arguments>]\n")
    print("List of Commands:")
    print("   build - build a graphenized docker image")
    print("   help - print this information\n")

    print_build_help()

    print("\nTo run a graphenized Docker image, execute:")
    print("docker run --device=/dev/gsgx --device=/dev/isgx -v "
        "/var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket [options] gsc-<image-name>[:<tag>]"
        " [application arguments]")

if __name__ == '__main__':

    if len(sys.argv) < 2:
        print_usage("")
        sys.exit(1)

    GSC_CMDS = {
        'build': gsc_build,
        'help': print_usage,
    }

    # GSC command is the first argument if not provided print usage
    CMD = GSC_CMDS.get(sys.argv[1], print_usage)
    CMD(sys.argv[2:])
