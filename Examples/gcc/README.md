# Introduction

This directory contains a Makefile and template manifests to run gcc and its related tools on
Graphene. We tested with gcc version 5.5.0 and binutils (as, ld) version 2.26.1 on Ubuntu 16.04. We
also tested on Ubuntu 18.04 with gcc version 7.4.0 and binutils version 2.30. This example uses the
package version of gcc and related tools (as, cc1, collect2, ld) installed on the system instead of
compiling them from source as some of the other examples do.

The Makefile and the template manifest contain comments to hopefully make them easier to understand.

**This example is temporarily broken until we rewrite Graphene loader**

# Quick Start

To run the regression tests execute ```make check```. To do the same for SGX, execute ```SGX=1 make
check```. The regression tests build three sample programs - helloworld.c, bzip2.c and gzip.c - and
test their functionality.

By looking at the Makefile "check" target you can see how gcc is invoked to compile individual
source files under the hood. If you want to compile different and/or more complex applications, you
would likely need to tweak the manifest files to whitelist additional files.
