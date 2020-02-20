#!/usr/bin/env python3

import json
import os
import os.path
import re
import sys
from string import Template
from shutil import copyfile

import docker

def gsc_image_name(name):
    return "gsc-" + name

# load config of GSC
def load_config(file):
    with open(file) as json_config_file:
        return json.load(json_config_file)

# generate manifest from a template based on the binary name
# manifest is not finished only prepared. During docker build
# this manifest is completed with trusted files and the path to the binary.
def generate_manifest(image, default, user_manifest, binary):
    with open('templates/manifest.template') as manifest_template:
        replace = {'bin_name': binary}
        replace.update(default)
        template_mf = Template(manifest_template.read())
        instantiated_mf = template_mf.substitute(replace)

        with open(user_manifest) as u_m_content:
            app_manifest = open(image + '/' + binary + '.manifest', 'w')
            app_manifest.write(instantiated_mf)
            app_manifest.write("\n")
            app_manifest.write(u_m_content.read())
            app_manifest.write("\n")
            app_manifest.close()

# generate app loader scirpt which generates a token and runs the manifest
# this is based on a template
def generate_app_loader(image, app, binary, binary_arguments):
    with open('templates/app.loader.template') as apl:
        template_apl = Template(apl.read())
        instantiated_apl = template_apl.substitute({
                    'app' : app,
                    'binary' : binary,
                    'binary_arguments': binary_arguments})

        dockerfile = open(image + '/apploader.sh', 'w')
        dockerfile.write(instantiated_apl)
        dockerfile.close()

# Dockerfile generated from a template depends which Ubuntu version to be used
# currently fixed to 18.04.
# Build via multistage build process:
# 1) Build graphene with the correct driver version
# 2) Build application image with additions of graphene
def generate_dockerfile(image, substitutions, app, binary):
    # load config
    config = load_config('config.json')
    config.update(substitutions)

    # generate build stage 1 from graphene template
    with open('templates/Dockerfile.ubuntu' + config['ubuntu'] + '.template') as dfg:
        template_dfg = Template(dfg.read())
        instantiated_dfg = template_dfg.substitute(config)

        # build app specific 2nd stage
        with open('templates/Dockerfile.gscapp.template') as dfapp:
            replacements = {
             "appImage" : image,
             "app" : app,
             "binary" : binary
            }
            replacements.update(substitutions)
            template_dfapp = Template(dfapp.read())
            instantiated_dfapp = template_dfapp.substitute(replacements)

            dockerfile = open(image + "/Dockerfile", "w")
            dockerfile.write(instantiated_dfg)
            dockerfile.write(instantiated_dfapp)
            dockerfile.close()

def prepare_build_context(image, user_manifest, substitutions, app, binary, binary_arguments):
    # create directory for image specific files
    os.makedirs(image, exist_ok=True)

    # generate dockerfile to build grapheneized docker image
    generate_dockerfile(image, substitutions, app, binary)

    # generate app specific loader script
    generate_app_loader(image, app, binary, binary_arguments)

    # generate manifest stub for this app
    generate_manifest(image, substitutions, user_manifest, binary)

    # copy markTrustedFiles.sh
    copyfile("markTrustedFiles.sh", image + "/markTrustedFiles.sh")

def build_gsc_image(dclient, image, user_manifest, options):
    # receive base docker image info
    try:
        app_img = dclient.images.get(image)

        # get app name and tag
        image_re = re.match(r'([^:]*)(:?)(.*)', image)
        if image_re.group(1):
            app = image_re.group(1)

        # remove trailing slashes
        app = app.split('/')[-1]

        # find command of image
        cmd = ' '.join(app_img.attrs['Config']['Cmd'])
        # possibly if starts with bin/sh
        cmd = cmd[cmd.startswith('[/bin/sh -c ') and len('[/bin/sh -c ') : ]
        split = cmd.split(" ", 1)
        binary = split[0]
        binary_arguments = ""
        if len(split) > 1:
            binary_arguments = split[1]
        print("args:", binary_arguments)

        params = {
            '-d': {
                    'DEBUG' : 'DEBUG=1',
                    'debug_output': 'inline'
                },
        }
        # default substitutions
        default = {
            'DEBUG': '',
            'debug_output': 'none'
        }

        for option in options:
            default.update(params[option])

        prepare_build_context(image, user_manifest, default, app, binary, binary_arguments)

        # build graphenized docker image
        os.chdir(image)
        os.system('docker build -t ' + gsc_image_name(image) + ' . \n')

    except (docker.errors.ImageNotFound, docker.errors.APIError):

        print("Unable to find base image " + image)

#
# Build graphenized docker image (aka. docker build)
#
def gsc_build(args):
    if len(args) < 2:
        print("Too few arguments to command build")
        print_run_help()
        sys.exit(1)

    dclient = docker.DockerClient(base_url='unix://var/run/docker.sock')

    user_manifest = args[0]
    image = args[1]

    print("Graphenizing docker image " + image)

    # test if image exists
    try:
        dclient.images.get(gsc_image_name(image))

        print("Image already exists, no build required.")

    except (docker.errors.ImageNotFound, docker.errors.APIError):

        print("Building graphenized image")

        # build image, since it doesn't exist locally
        build_gsc_image(dclient, image, user_manifest, args[2:])

#
# Run graphenized version of docker image (aka. docker run)
#
def gsc_run(args):
    if len(args) < 1:
        print("Too few arguments to command run")
        print_run_help()
        sys.exit(1)

    if (not os.path.exists("/dev/isgx")
        or not os.path.exists("/dev/gsgx")
        or not os.path.exists("/var/run/aesmd/aesm.socket")):
        print("Please install sgx driver, graphene kernel module and SGX SDK/aesm")
        exit(1)

    dclient = docker.DockerClient(base_url='unix://var/run/docker.sock')

    opt = 0
    for arg in args:
        if arg.startswith('-'):
            opt += 1
        else:
            try:
                dclient.images.get(gsc_image_name(arg))
                # if image exists exit
                break
            except (docker.errors.APIError, docker.errors.ImageNotFound):
                opt += 1

    options = ""
    if opt > 0:
        options = ' '.join(args[0:opt])
    # run grapheneized docker container
    image = args[opt]
    if len(args) > opt+1:
        app_args = '\'' + '\' \''.join(args[opt+1:]) + '\''
    else:
        app_args = ""

    try:
        dclient.images.get(gsc_image_name(image))

        print("Running graphenized docker image " + gsc_image_name(image)
            + " with arguments ("+ str(len(app_args)) + ") " + app_args
            + " options " + options)

        os.system("docker run --device=/dev/gsgx --device=/dev/isgx "
            +"-v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket "
            + options + " " + gsc_image_name(image) + " " + app_args + "\n")

    except (docker.errors.ImageNotFound, docker.errors.APIError):
        print("Unable to find image " + gsc_image_name(image))

#
# Print Usage
#
def print_build_help():
    print("Build command usage:")
    print("gsc build <manifest> <image name>[:<tag>] [<options>]")
    print("manifest - Application specific manifest to be included in the generated manifest")
    print("image name - name of the base image to be graphenized")
    print("tag - tag of the image\n")
    print("Options:")
    print("-d - compile Graphene with debug")

def print_run_help():
    print("Run command usage:")
    print("gsc run [options] <image name>[:<tag>] [application arguments]")
    print("image name - Name of image without GSC build")
    print("tag - Tag of the image to be used\n")
    print("application arguments - Arguments given to the application")
    print("Options are passed through to docker run.")
    print("Common options include -t -i")

def print_usage(cmd):
    #pylint: disable=unused-argument
    print("Usage:")
    print("gsc <cmd> [<cmd arguments>]\n")
    print("List of Commands:")
    print("build - Build a graphenized docker image")
    print("run - Run a previously build graphenized docker image")
    print("help - Print this information\n")

    print_build_help()
    print_run_help()

#
# Main entry (split by command)
#
if __name__ == '__main__':

    if len(sys.argv) < 2:
        print_usage("")
        sys.exit(1)

    GSC_CMDS = {
        'run': gsc_run,
        'build': gsc_build,
        'help': print_usage,
    }

    # GSC command is the first argument
    # if not provided print usage
    CMD = GSC_CMDS.get(sys.argv[1], print_usage)
    # handle command
    CMD(sys.argv[2:])
