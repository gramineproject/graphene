# Python example

This directory contains an example for running Python 3 in Graphene, including
the Makefile and a template for generating the manifest.

# Generating the manifest

## Installing prerequisites

For generating the manifest and running the test scripts, please run the following
command to install the required packages (Ubuntu-specific):

    sudo apt-get install libnss-mdns python3-numpy python3-scipy

## Building for Linux

Run `make` (non-debug) or `make DEBUG=1` (debug) in the directory.

## Building for SGX

Run `make SGX=1` (non-debug) or `make SGX=1 DEBUG=1` (debug) in the directory.

## Building with a local Python installation

By default, the `make` command creates the manifest for the Python binary from
the system installation. If you have a local installation, you may create the
manifest with the `PYTHONPATH` variable set accordingly. You can also specify
a particular version of Python. For example:

```
make PYTHONPATH=<python install path> PYTHONVERSION=python3.6 SGX=1
```

# Run Python with Graphene

Here's an example of running Python scripts under Graphene:

Without SGX:
```
graphene-direct ./python scripts/helloworld.py
graphene-direct ./python scripts/test-numpy.py
graphene-direct ./python scripts/test-scipy.py
```

With SGX:
```
graphene-sgx ./python scripts/helloworld.py
graphene-sgx ./python scripts/test-numpy.py
graphene-sgx ./python scripts/test-scipy.py
```

You can also manually run included tests:
```
SGX=1 ./run-tests.sh
```
