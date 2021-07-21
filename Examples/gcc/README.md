# Introduction

***TODO: this example should be reworked to use a standalone gcc version, not
the one from the system***

This directory contains a Makefile and template manifests to run gcc and its
related tools on Graphene. This example uses the package version of gcc and
related tools (as, cc1, collect2, ld) installed on the system instead of
compiling them from source as some of the other examples do.

# Quick Start

To run the regression tests execute ```make check```. To do the same for SGX,
execute ```SGX=1 make check```. The regression tests build three sample programs
- helloworld.c, bzip2.c and gzip.c - and test their functionality.
