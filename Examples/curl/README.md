# Curl

This directory contains a Makefile and template manifest to run curl on Graphene. We tested it with
curl 7.47.0 on Ubuntu 16.04 and with curl 7.58.0 on Ubuntu 18.04. This example uses curl installed
on the system instead of compiling from source as some of the other examples do. On Ubuntu 16.04,
please make sure that `libnss-mdns` is installed and if not, run the following command:

```sh
sudo apt-get install libnss-mdns
```

The Makefile and the template manifest contain comments to hopefully make them easier to understand.

# Quick Start

To run the regression test execute ```make check```. To do the same for SGX, execute ```make SGX=1
check```. The regression test downloads the index page of `example.com`, thus it requires Internet
connection.
