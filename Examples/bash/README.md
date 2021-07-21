# Bash example

This directory contains an example for running Bash in Graphene, including
the Makefile and a template for generating the manifest.

# Generating the manifest

## Building for Linux

Run `make` (non-debug) or `make DEBUG=1` (debug) in the directory.

## Building for SGX

Run `make SGX=1` (non-debug) or `make SGX=1 DEBUG=1` (debug) in the directory.

# Running Bash with Graphene

Here's an example of running Bash scripts under Graphene:

Without SGX:
```
graphene-direct ./bash -c "ls"
graphene-direct ./bash -c "cd scripts && bash bash_test.sh 2"
```

With SGX:
```
graphene-sgx ./bash -c "ls"
graphene-sgx ./bash -c "cd scripts && bash bash_test.sh 2"
```
