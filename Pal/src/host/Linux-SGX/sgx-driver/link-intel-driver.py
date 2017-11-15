#!/usr/bin/python

import sys, os, re


isgx_path    = os.getenv("ISGX_DRIVER_PATH")
isgx_version = os.getenv("ISGX_DRIVER_VERSION")

try:
    # get the locations of directories
    print "\n" + \
          "*****************************************************************\n" + \
          "Make sure you have downloaded and installed the Intel sgx driver \n" + \
          "from https://github.com/01org/linux-sgx-driver.\n" + \
          "*****************************************************************\n" + \
          "\n"

    while True:
        if not isgx_path:
            isgx_path = raw_input('Enter the Intel SGX driver derctory: ')
        if os.path.exists(isgx_path + '/sgx.h'):
            break
        if os.path.exists(isgx_path + '/isgx.h'):
            break
        print '{0} is not a directory for the Intel SGX driver'.format(isgx_path)
        isgx_path = None


    # get the driver version
    while True:
        if not isgx_version:
            isgx_version = raw_input('Enter the driver version (default: 1.9, 1.9 means "1.9 and above"): ')
        if not isgx_version:
            isgx_version_major = 1
            isgx_version_minor = 9
            break
        m = re.match('([1-9])\.([0-9]+)', isgx_version)
        if m:
            isgx_version_major = m.group(1)
            isgx_version_minor = m.group(2)
            break
        print '{0} is not a valid version (x.xx)'.format(isgx_version)
        isgx_version = None


    # create a symbolic link called 'linux-sgx-driver'
    isgx_link = 'linux-sgx-driver'
    isgx_path = os.path.abspath(isgx_path)
    print isgx_link + ' -> ' + isgx_path
    if os.path.exists(isgx_link):
        os.unlink(isgx_link)
    os.symlink(isgx_path, isgx_link)


    # create isgx_version.h
    with open('isgx_version.h', 'w') as versionfile:
        print 'create isgx_version.h'
        print >> versionfile, '#include <linux/version.h>'
        print >> versionfile
        print >> versionfile, '#define SDK_DRIVER_VERSION KERNEL_VERSION(' + \
                              str(isgx_version_major) + ',' + \
                              str(isgx_version_minor) + ',0)'
        print >> versionfile, '#define SDK_DRIVER_VERSION_STRING "' + \
                              str(isgx_version_major) + '.' + \
                              str(isgx_version_minor) + '"'

except:
    print 'uh-oh: {0}'.format(sys.exc_info()[0])
    exit(-1)
