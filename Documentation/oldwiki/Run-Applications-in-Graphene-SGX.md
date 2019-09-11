We prepared and tested several applications to demonstrate Graphene-SGX usability. These applications
can be directly built and run from the Graphene source:

* [[LMBench (v2.5) | Run Applications in Graphene SGX#running lmbench in graphene]]
* [[Python | Run Applications in Graphene SGX#running python in graphene]]
* [[R | Run Applications in Graphene SGX#running r in graphene]]
* [[Lighttpd | Run Applications in Graphene SGX#running lighttpd in graphene]]
* [[Apache | Run Applications in Graphene SGX#running apache in graphene]]
* [[Busybox | Run Applications in Graphene SGX#running busybox in graphene]]
* [[Bash | Run Applications in Graphene SGX#running bash in graphene]]


## Running LMBench in Graphene-SGX

The LMBench source and scripts are stored in the directory `LibOS/shim/test/apps/lmbench`. Many
convenient commands are written in the Makefile inside the directory. The following steps compile
and run LMBench in a native environment and under Graphene-SGX.

    cd LibOS/shim/test/apps/lmbench
    make SGX=1      # compile source of lmbench and generate manifest and signature
    make SGX_RUN=1  $ get enclave token
    make test-graphene       # run the whole package in Graphene-SGX

The result of native runs can be found in `lmbench-2.5/results/linux`. The result of Graphene-SGX
runs can be found in `lmbench-2.5/results/graphene`. The file with the largest number as suffix
will be the latest output. For debugging purposes, you may want to test each LMBench test
individually. To do that, run the following commands:

    cd LibOS/shim/test/apps/lmbench
    cd lmbench-2.5/bin/linux/
    SGX=1 ./pal_loader lat_syscall null    # run lat_syscall in Graphene-SGX

To run the tcp and udp latency tests:

    SGX=1 ./pal_loader lat_udp -s &        # starts a server
    SGX=1 ./pal_loader lat_udp 127.0.0.1   # starts a client
    SGX=1 ./pal_loader lat_udp -127.0.0.1  # kills the server

## Running Python in Graphene-SGX

To run Python, first generate the manifest and the signature, and retrieve the token:

    cd LibOS/shim/test/apps/python
    make SGX=1
    make SGX_RUN=1

You can run `python.manifest.sgx` as an executable to load any script. The manifest file is
actually a script with a shebang that can be automatically loaded in PAL. Use the following
commands:

    ./python.manifest.sgx scripts/helloworld.py
    ./python.manifest.sgx scripts/fibonacci.py

## Running R in Graphene-SGX

To run R, first prepare the manifest:

    cd LibOS/shim/test/apps/r
    make SGX=1
    make SGX_RUN=1

You can run `R.manifest.sgx` as an executable to load any script. The manifest file is actually
a script with a shebang that can be automatically loaded in PAL. Use the following commands:

    ./R.manifest.sgx -f scripts/sample.r

## Running Lighttpd in Graphene-SGX

Lighttpd can be used to test the TCP latency and throughput of Graphene-SGX, in either single-
threaded or multi-threaded environment. The scripts and the source code for Lighttpd can be found
in `LibOS/shim/test/apps/lighttpd`. To build Lighttpd, run the following commands:

    cd LibOS/shim/test/apps/lighttpd
    make SGX=1
    make SGX_RUN=1

The commands above will compile the source code, build the manifest file for Graphene-SGX, generate
the configuration file for Lighttpd, and generate the HTML sample files. We prepared the following file
samples:

* `html/random/*.html`: random files (non-html) created with different sizes

The server should be started manually and tested by running the ApacheBench (ab) benchmark from a
remote client. To start the HTTP server, run one of the following commands:

    make start-native-server  or  make start-graphene-server

To start the server in a multi-threaded environment, run on of the following commands:

    make start-multithreaded-native-server  or  make start-multithreaded-graphene-server

For testing, use ApacheBench (ab). There is a script `run-apachebench.sh` that takes two arguments:
the IP and the port. It runs 100,000 requests (`-n 100000`) with 25 to 200 maximum outstanding
requests (`-c 25` to `-c 200`). The results are saved into the same directory, and all previous
output files are overwritten.

    make start-graphene-server
    ./run-apachebench.sh <ip> <port>
    # which internally calls:
    #   ab -k -n 100000 -c [25:200] -t 10 http://ip:port/random/100.1.html

## Running Apache in Graphene-SGX

Apache is a commercial-class web server that can be used to test the TCP latency and throughput of
Graphene. The scripts and the source code can be found in `LibOS/shim/test/apps/apache`. To build
Apache, run the following commands:

    cd LibOS/shim/test/apps/apache
    make SGX=1
    make SGX_RUN=1

The commands above will compile the source code, build the manifest file for Graphene, generate
the configuration file for Apache, and generate the HTML sample files (same as described in the
[[lighttpd section|Run applications in Graphene#Running Lighttpd in Graphene]]).

The server can be started manually via one the following commands:

    make start-native-server  or  make start-graphene-server

By default, the Apache web server is configured to run with 4 preforked worker processes and has
PHP support enabled. To test Apache server with ab, run:

    make start-graphene-server
    ./run-apachebench.sh <ip> <port>
    # which internally calls:
    #   ab -k -n 100000 -c [25:200] -t 10 http://ip:port/random/100.1.html

## Running Busybox in Graphene-SGX

Busybox is a standalone shell including general-purpose system utilities. The scripts and the
source code for Busybox is stored in `LibOS/shim/apps/busybox`. To build the source code with
the proper manifest, run the following commands:

    cd LibOS/shim/test/apps/busybox
    make SGX=1
    make SGX_RUN=1

To run Busybox, you may directly run busybox.manifest built in the directory as a script.
For example:

    ./busybox.manifest.sgx sh (to run a shell)

or

    ./busybox.manifest.sgx ls -l (to list local directory)

## Running Bash in Graphene-SGX

Bash is the most commonly used shell utility in Linux. The scripts and the source code for Bash
is stored in `LibOS/shim/apps/bash`. To build the source code with the proper manifest, simply run
the following commands:

    cd LibOS/shim/test/apps/bash
    make SGX=1
    make SGX_RUN=1

To test Bash, use the benchmark suites we prepared: `bash_test.sh` and `unixbench`. Run one of the
following commands to test Bash:

    ./bash.manifest.sgx bash_test.sh [times]
    ./bash.manifest.sgx unixbench.sh [times]

