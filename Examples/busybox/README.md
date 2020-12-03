# Busybox

This directory contains the Makefile and the template manifest for the most
recent version of Busybox (as of this writing, commit ac78f2ac96). This was
tested on a machine with SGX v1 and Ubuntu 16.04.

The Makefile and the template manifest contain extensive comments and are made
self-explanatory. Please review them to gain understanding in Graphene-SGX
and requirements for applications running under Graphene-SGX.

# Quick Start

```sh
# build Busybox and the final manifest
make SGX=1

# run Busybox shell in non-SGX Graphene
./pal_loader busybox sh

# run Busybox shell in Graphene-SGX
SGX=1 ./pal_loader busybox sh

# now a shell session should be running e.g. typing:
ls
# should run program `ls` which lists current working directory
```
