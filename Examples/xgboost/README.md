# Python example

This directory contains an example for running XGBoost in Graphene, including
the Makefile and a template for generating the manifest.

# Generating the manifest

## Installing prerequisites

For generating the manifest and running the test scripts, please run the following
command to install the required utility packages (Ubuntu-specific):

    sudo apt-get install libnss-mdns

## Building for Linux

Run `make` (non-debug) or `make DEBUG=1` (debug) in the directory.

## Building for SGX

Run `make SGX=1` (non-debug) or `make SGX=1 DEBUG=1` (debug) in the directory.

## Make's explicit arguments

Please specify conda environment and python version:
```
make PYTHONVERSION=python3.6 CONDAPATH=<path-to-conda-dir>/miniconda3/envs/my_env SGX=1
```

# Run XGBoost with Graphene

Here's an example of running Python scripts under Graphene:

Without SGX:
```
./pal_loader python.manifest xgboost_example_airline.py
```

With SGX:
```
SGX=1 ./pal_loader python.manifest xgboost_example_airline.py
```
