# Curl

This directory contains a Makefile and template manifest to run curl on
Graphene. This example uses curl installed on the system instead of compiling
from source as some of the other examples do.

# Quick Start

To run the regression test execute ```make check```. To do the same for SGX,
execute ```make SGX=1 check```. The regression test downloads the index page of
`example.com`, thus it requires Internet connection.
