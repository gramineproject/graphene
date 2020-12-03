# Nginx

This directory contains the Makefile and the template manifest for the most
recent version of Nginx web server (as of this writing, version 1.16.1). This
was tested on a machine with SGX v1 and Ubuntu 16.04.

The Makefile and the template manifest contain extensive comments. Please review
them to understand the requirements for Nginx running under Graphene-SGX.

We build Nginx from the source code instead of using an existing installation.
On Ubuntu 16.04, please make sure that the following packages are installed:
```sh
sudo apt-get install -y build-essential apache2-utils
```

# Quick Start

```sh
# build Nginx and the final manifest
make SGX=1

# run original Nginx against a benchmark (benchmark-http.sh, uses ab)
./install/sbin/nginx -c conf/nginx-graphene.conf &
./benchmark-http.sh 127.0.0.1:8002
kill -SIGINT %%

# run Nginx in non-SGX Graphene against a benchmark
./pal_loader ./nginx -c conf/nginx-graphene.conf &
./benchmark-http.sh 127.0.0.1:8002
kill -SIGINT %%

# run Nginx in Graphene-SGX against a benchmark
SGX=1 ./pal_loader ./nginx -c conf/nginx-graphene.conf &
./benchmark-http.sh 127.0.0.1:8002
kill -SIGINT %%

# you can also test the server using other utilities like wget
wget http://127.0.0.1:8002/random/10K.1.html
```

Alternatively, to run the Nginx server, use one of the following commands:

```
make start-native-server
make start-graphene-server
make SGX=1 start-graphene-server
```
