# Node.js

This directory contains a Makefile and template manifest to run Node.js on Graphene. We tested it
with Node.js 8.10.0 on Ubuntu 18.04. This example uses Node.js installed on the system instead of
compiling from source as some of the other examples do.

The Makefile and the template manifest contain comments to hopefully make them easier to understand.

# Quick Start

To run the regression test execute ```make check```. To do the same for SGX, execute ```make SGX=1
check```.
