# LMBench example

This directory contains an example for running LMBench in Graphene, including
the Makefile and a template for generating the manifest. The configuration
is only tested with LMBench 2.5 and does not work for LMBench 3.0+. The
application is tested on Ubuntu 16.04, with both normal Linux and SGX platforms.

# Building LMBench and generating the manifest

This repository does not contain the source code of LMBench. Using the following
building commands will automatically download the source code and unpack it into
a subdirectory of the current directory.

## Building for Linux

Run `make` (non-debug) or `make DEBUG=1` (debug) in the directory.

## Building for SGX

Run `make SGX=1` (non-debug) or `make SGX=1 DEBUG=1` (debug) in the directory.

# Running LMBench

## Running natively

To run the whole test suite natively, use the following command:
```
make run-native

```

To run individual tests, you may run the programs in `lmbench-2.5/bin/linux`.
Here are a few examples:
```
./lat_syscall null
./lat_syscall read
./lat_syscall write
```

## Running with Graphene

To run the whole test suite under Graphene, use the following command:
```
make run-graphene
```

To run individual tests, you may run the programs in `lmbench-2.5/bin/linux`,
using `pal_loader`. Here are a few examples:
```
./pal_loader lat_syscall null
./pal_loader lat_syscall read
./pal_loader lat_syscall write
```

## Running with Graphene-SGX

To run the whole test suite, use the following command:
```
make run-graphene SGX=1
```

To run individual tests, you may run the programs in `lmbench-2.5/bin/linux`,
using `pal_loader`. Here are a few examples:
```
SGX=1 ./pal_loader lat_syscall null
SGX=1 ./pal_loader lat_syscall read
SGX=1 ./pal_loader lat_syscall write
```
