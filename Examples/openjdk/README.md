# Java example

This directory contains an example for running a OpenJDK example in Graphene,
including the Makefile and a template for generating the manifest.

## Installing prerequisites

For generating the manifest and running the OpenJDK example, run the
following command to install the required packages (Ubuntu-specific):

    sudo apt-get install openjdk-11-jdk

## Building for graphene-direct

Run `make` (non-debug) or `make DEBUG=1` (debug) in the directory.

## Building for graphene-sgx

Run `make SGX=1` (non-debug) or `make SGX=1 DEBUG=1` (debug) in the directory.

## Run OpenJDK example with Graphene

Without SGX:

    graphene-direct java MultiThreadMain

With SGX:

    graphene-sgx java -Xmx8G MultiThreadMain

Note: If using 64G or greater enclave sizes, the JVM flag `-Xmx8G` can be omitted in graphene-sgx.
