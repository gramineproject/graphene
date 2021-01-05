# Python example

This directory contains an example for running Python 3 with SciPy/NumPy in Graphene,
including the Makefile and a template for generating the manifest. The application is
tested on Ubuntu 16.04, with both normal Linux and SGX platforms.

This example is *insecure*: the manifest file uses `sgx.allowed_files` to allow all
Python libraries/scripts without any integrity checks. This example simply shows
the functionality of Graphene but *does not* prevent the attacker from silently
modifying Python files. For secure Python usage, see the `python-simple` example.

# Generating the manifest

## Installing prerequisites

For generating the manifest and running the test scripts, please run the following
command to install the required Python packages (Ubuntu-specific):

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
make PYTHONPATH=<python install path> PYTHONVERSION=python3.2 SGX=1
```

By default, `PYTHONPATH=/usr` and `PYTHONVERSION=python3.5`.


# Run Python with Graphene

Here's an example of running Python scripts under Graphene:

Without SGX:
```
./pal_loader ./python scripts/test-numpy.py
./pal_loader ./python scripts/test-scipy.py
```

With SGX:
```
SGX=1 ./pal_loader ./python scripts/test-numpy.py
SGX=1 ./pal_loader ./python scripts/test-scipy.py
```
