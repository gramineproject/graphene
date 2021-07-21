# Apache

This directory contains the Makefile and the template manifest for the most
recent version of Apache web server (as of this writing, version 2.4.41).

We build Apache from the source code instead of using an existing installation.
On Ubuntu 18.04, please make sure that the following packages are installed:
```sh
sudo apt-get install -y build-essential flex libapr1-dev libaprutil1-dev libpcre2-dev \
                        apache2-utils libssl-dev
```

# Quick Start

```sh
# build Apache and the final manifest
make SGX=1

# run original Apache against HTTP and HTTPS benchmarks (benchmark-http.sh, uses ab)
make start-native-server &
../common_tools/benchmark-http.sh 127.0.0.1:8001
../common_tools/benchmark-http.sh https://127.0.0.1:8443
kill -SIGINT %%

# run Apache in non-SGX Graphene against HTTP and HTTPS benchmarks
make start-graphene-server &
../common_tools/benchmark-http.sh 127.0.0.1:8001
../common_tools/benchmark-http.sh https://127.0.0.1:8443
kill -SIGINT %%

# run Apache in Graphene-SGX against HTTP and HTTPS benchmarks
SGX=1 make start-graphene-server &
../common_tools/benchmark-http.sh 127.0.0.1:8001
../common_tools/benchmark-http.sh https://127.0.0.1:8443
kill -SIGINT %%

# you can also test the server using other utilities like wget
wget http://127.0.0.1:8001/random/10K.1.html
wget https://127.0.0.1:8443/random/10K.1.html
```

# Running Apache with Different MPMs

The Apache server can run with several different multi-processing modules
(MPMs). The two popular ones are *Prefork* and *Worker* MPMs. The Prefork
MPM uses multiple child processes with one thread each, and each process
handles one connection at a time. The Worker MPM uses multiple child processes
with many threads each, and each thread handles one connection at a time.

The supplied Makefile allows to run Apache in both configurations:
```sh
make start-native-server                  # run with Prefork MPM
make start-graphene-server                # run with Prefork MPM

make start-native-multithreaded-server    # run with Worker MPM
make start-graphene-multithreaded-server  # run with Worker MPM
```
