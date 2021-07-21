# R example

This directory contains an example for running R in Graphene, including the
Makefile and a template for generating the manifest.

# Generating the manifest

## Building for Linux

Run `make` (non-debug) or `make DEBUG=1` (debug) in the directory.

## Building for SGX

Run `make SGX=1` (non-debug) or `make SGX=1 DEBUG=1` (debug) in the directory.

## Building with a local R installation

By default, the `make` command creates the manifest for the system R binary
(`/usr/lib/R/bin/exec/R`). If you have a local R installation, you may create
the manifest with the `R_HOME` variable set accordingly. For example:

```
make R_HOME=<install path>/lib/R SGX=1
```

# Run R with Graphene

When running R with Graphene, please use the `--vanilla` or `--no-save` option.

Here's an example of running an R script under Graphene:

Without SGX:
```
graphene-direct ./R --slave --vanilla -f scripts/sample.r
graphene-direct ./R --slave --vanilla -f scripts/R-benchmark-25.R
```

With SGX:
```
graphene-sgx ./R --slave --vanilla -f scripts/sample.r
graphene-sgx ./R --slave --vanilla -f scripts/R-benchmark-25.R
```
