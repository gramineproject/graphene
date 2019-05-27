#!/usr/bin/env python3

import os
import shutil
import subprocess
import sys
from pkg_resources import parse_version

def prependText(filename, text) :
    data = ""
    with open(filename, 'r') as original:
        data = original.read()
    with open(filename, 'w') as modified:
        modified.write(text)
        modified.write(data)

def appendText(filename, text) :
    with open(filename, "a") as myfile:
        myfile.write(text)


home = os.getcwd()
glibc = "glibc-2.19"
glibcParent = "" # glibc parent directory
glibcDir = ""    # glibc dir (ex. glibc-2.19)
buildDir = "glibc-build"
installDir = os.path.dirname(home) + '/Runtime/'
commandStr = ""
commandOutput = ""
quiet = False
debug_flags = ""

index = 0
for arg in sys.argv[1:]:
    index += 1
    if (arg == '--src' or arg == '-s') and index + 1 < len(sys.argv):
        glibc = sys.argv[index + 1]
    if arg == '--quiet' or arg == '-q':
        quiet = True
    if arg == '--debug':
        debug_flags = "-g"

version = parse_version(glibc.replace("glibc-", ""))

if True:

    #########################################
    #### get the locations of directories ###
    #########################################

    if not quiet:
        iput = input('use {0} as the source of GNU libc? ([y]/n):'.format(glibc)).lower()
        if not iput == 'y' and not iput == '' :
            glibc = input('enter the glibc source to install with: ')

    if not quiet:
        iput = input('{0} contains glibc code to compile? ([y]/n): '.format(glibc)).lower()
        if not iput == 'y' and not iput == '':
            glibc = input('directory containing glibc code to compile: ')

    if os.path.isdir(glibc) :
        glibc = os.path.abspath(glibc)
        glibcParent,glibcDir = os.path.split(glibc)
        print('building in {0}: {1}'.format(glibcParent, glibcDir))

    if not quiet:
        iput = input('use {0} as the directory to build glibc in? ([y]/n): '.format(buildDir)).lower()
        if not iput == 'y' and not iput == '':
            buildDir = input('the directory to build glibc in:  ')

    buildDir = os.path.abspath(buildDir)
    print('using build dir: {0}'.format(buildDir))

    if os.path.isdir(buildDir) :
        if not quiet:
            clean = input('clean build (delete {0}, rerun configure, etc.)? ([y]/n): '.format(buildDir))
        else:
            clean = 'y'

        if clean == 'y' or clean == '':
            shutil.rmtree(buildDir)
            os.makedirs(buildDir)
        else :
            print('Then just go to {0} and type make...'.format(buildDir))
            exit(0)
    else :
        os.makedirs(buildDir)

    if not quiet:
        iput = input('use {0} as the directory to install glibc in? ([y]/n): '.format(installDir)).lower()
        if not iput == 'y' and not iput == '':
            installDir = input('the directory to install glibc in:  ')

    installDir = os.path.abspath(installDir)
    print('using install dir: {0}'.format(installDir))


if True:

    ################################
    #### doctor glibc's Makefile ###
    ################################

    os.chdir(buildDir)

    cflags = '{0} -O2 -U_FORTIFY_SOURCE -fno-stack-protector -Wno-unused-value'.format(debug_flags)
    extra_defs = ''
    disabled_features = { 'nscd' }
    extra_flags = '--with-tls --without-selinux --disable-test {0}'.format(' '.join(['--disable-' + f for f in disabled_features]))

    if version <= parse_version('2.21'):
        extra_flags += ' --enable-add-ons=nptl'

    ##    configure
    commandStr = r'CFLAGS="{2}" {3} {0}/configure --prefix={1} {4} | tee configure.out'.format(glibc, installDir, cflags, extra_defs, extra_flags)
    print(commandStr)
    commandOutput = subprocess.call(commandStr, shell=True)
