# java sample  execution steps:

This directory contains an example for running a java Sample in Graphene, 
including the Makefile and a template for generating the manifest.
The application is tested on Ubuntu 18.04 with both normal Linux and SGX platforms.
This example is tested with openjdk11.

# Generating the manifest

## Installing prerequisites

For generating the manifest and running the Java Sample, run the
following command to install the required packages (Ubuntu-specific):

    `sudo apt-get install openjdk-11-jdk`

## Building for Linux

    Run `make` (non-debug) or `make DEBUG=1` (debug) in the directory.

## Building for SGX

    Run `make SGX=1` (non-debug) or `make SGX=1 DEBUG=1` (debug) in the directory.
## Building hello.jar

    Run `javac hello.java`
    Run `jar cvfm hello.jar hello.mf hello.class`

## Run hello world java sample with graphene

Without SGX:
    `graphene-direct java -jar hello.jar`
With SGX:
    `graphene-sgx java -jar hello.jar`

#Note: By default this example uses 64G enclave size. This example also works with 8G enclave
 size also but in that case Max Heap size should be restricted to 4G using jvm flag -Xmx4G.
