#!/usr/bin/python


import sys, os, string, subprocess, shutil, fileinput, multiprocessing, re, resource

try:
    #########################################
    #### get the locations of directories ###
    #########################################

    print "Make sure you have downloaded and installed the Intel sgx driver " + \
          "from https://github.com/01org/linux-sgx-driver."
    while True:
        isgx = raw_input('Enter the Intel sgx driver derctory: ')
        if os.path.exists(isgx + '/isgx.h'):
            break
        print '{0} is not a directory for the Intel sgx driver'.format(isgx)

    isgx_link = 'linux-sgx-driver'
    isgx = os.path.abspath(isgx)
    print isgx_link + ' -> ' + isgx
    if os.path.exists(isgx_link):
        os.unlink(isgx_link)
    os.symlink(isgx, isgx_link)

except:
    print 'uh-oh: {0}'.format(sys.exc_info()[0])
    exit(-1)
