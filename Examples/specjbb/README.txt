# SPECjbb setup and  execution steps:

This directory contains an example for running a java workload SPECjbb2015
in Graphene, including the Makefile and a template for generating the manifest.
The application is tested on Ubuntu 18.04 with both normal Linux and SGX platforms.
This example is tested with openjdk11.

# Generating the manifest

## Installing prerequisites

For generating the manifest and running the SPECjbb2015 workload, please run the
following command to install the required packages (Ubuntu-specific):

    sudo apt-get install openjdk-11-jdk

## Building for Linux

    Run `make` (non-debug) or `make DEBUG=1` (debug) in the directory.

## Building for SGX

    Run `make SGX=1` (non-debug) or `make SGX=1 DEBUG=1` (debug) in the directory.

# Run hello world java sample with graphene

Without SGX:
    graphene-direct java -jar files/hello.jar
With SGX:
    graphene-sgx java -jar files/hello.jar

# Run SPECjbb2015 with Graphene
Here's an example of running Python scripts under Graphene:

Without SGX:
    ./run_composite.sh graphene-direct <JVM Stack Size> <Max JVM Heap Size>
example: 
    ./run_composite.sh graphene-direct -Xss256K -Xmx32G

With SGX:
    ./run_composite.sh graphene-sgx <JVM Stack Size> <Max JVM Heap Size>

example:
    ./run_composite.sh graphene-sgx -Xss256K -Xmx32G

Note1: 64GB enclave size and 32 GB Max Heap Size(-Xmx32G) is the minimum requirement to load a JVM or run java sample.
Note2: specjbb2015 results are generated under /specjbb/result directory.
