# Lighttpd Example

This directory contains an example for running lighttpd in Graphene, including
the Makefile and a template for generating the manifest.

# Building lighttpd source

For this example, we build lighttpd from source instead of using an existing
binary. To build lighttpd on Ubuntu 18.04, please make sure that the following
packages are installed:

    sudo apt-get install -y build-essential apache2-utils

## Linux

Run `make` (non-debug) or `make DEBUG=1` (debug) in the directory.

## SGX

Run `make SGX=1` (non-debug) or `make SGX=1 DEBUG=1` (debug) in the directory to
prepare lighttpd to run on SGX.

# Running lighttpd natively, under Graphene, and under Graphene-SGX

Execute one of the following commands to start lighttpd either natively
(non-Graphene), on Graphene or Graphene-SGX, respectively.

    make start-native-server
    make start-graphene-server
    SGX=1 make start-graphene-server

Because these commands will start the lighttpd server in the foreground, you
will need to open another console to run the client.

Once the server has started, you can test it with `wget` or `curl`

    wget http://127.0.0.1:8003/random/10K.1.html
    curl --compressed http://127.0.0.1:8003/random/10K.1.html -o 10K.1.html

You may also run the benchmark script using `ab` (Apachebench)

    ../common_tools/benchmark-http.sh 127.0.0.1:8003

Use Ctrl-C to terminate the server once you are finished testing lighttpd.

# Clean up

There are two commands to clean up the directory:

* `make clean`: Remove manifest, signature, and token files.
* `make distclean`: Remove the lighttpd source code and installation directory.
