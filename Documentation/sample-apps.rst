Running Sample Applications
===========================

.. highlight:: sh

We prepared and tested several applications to demonstrate Graphene and
Graphene-SGX usability. These applications can be directly built and run from
the Graphene source.

.. _sample-lmbench:

LMBench
-------

The LMBench source and scripts are stored in the directory
:file:`LibOS/shim/test/apps/lmbench`. Many convenient commands are written in
the Makefile inside the directory. The following steps compile and run LMBench
in a |~| native environment and under Graphene::

   cd LibOS/shim/test/apps/lmbench
   make                  # compile lmbench and set up manifests as target of Graphene tests
   make test-native      # run the whole package in native environment
   make test-graphene    # run the whole package in Graphene

   # or under SGX:
   make SGX=1                 # compile lmbench and generate manifest and signature
   make SGX=1 sgx-tokens      # get enclave token
   make SGX=1 test-graphene   # run the whole package in Graphene-SGX

The result of native runs can be found in :file:`lmbench-2.5/results/linux`. The
result of Graphene runs can be found in :file:`lmbench-2.5/results/graphene`.
The file with the largest number as suffix will be the latest output. For
debugging purposes, you may want to test each LMBench test individually. To do
that, run the following commands::

   cd LibOS/shim/test/apps/lmbench
   cd lmbench-2.5/bin/linux/
   ./lat_syscall null        # run the specific test, for example, lat_syscall
   ./pal lat_syscall null    # run lat_syscall in Graphene
   SGX=1 ./pal_loader lat_syscall null    # run lat_syscall in Graphene-SGX

To run the tcp and udp latency tests::

   ./pal_loader lat_udp -s &        # starts a server
   ./pal_loader lat_udp 127.0.0.1   # starts a client
   ./pal_loader lat_udp -127.0.0.1  # kills the server

   # under SGX:
   SGX=1 ./pal_loader lat_udp -s &        # starts a server
   SGX=1 ./pal_loader lat_udp 127.0.0.1   # starts a client
   SGX=1 ./pal_loader lat_udp -127.0.0.1  # kills the server

Python
------

To run Python, first prepare the manifest::

   cd LibOS/shim/test/apps/python
   make

   # or under SGX
   make SGX=1
   make SGX=1 sgx-tokens

You can run :command:`python.manifest` as an executable to load any script. The
manifest file is actually a |~| script with a |~| shebang that can be
automatically loaded in PAL. Use the following commands::

   ./python.manifest scripts/helloworld.py
   ./python.manifest scripts/fibonacci.py

   # or under SGX:
   ./python.manifest.sgx scripts/helloworld.py
   ./python.manifest.sgx scripts/fibonacci.py


R
-

To run R, first prepare the manifest::

   cd LibOS/shim/test/apps/r
   make

   # or under SGX:
   make SGX=1
   make SGX=1 sgx-tokens

You can run :command:`R.manifest` or :command:`R.manifest.sgx` as an executable
to load any script. The manifest file is actually a |~| script with a shebang
that can be automatically loaded in PAL. Use the following command::

   ./R.manifest -f scripts/sample.r
   # under SGX:
   ./R.manifest.sgx -f scripts/sample.r

GCC
---

We prepared several C/C++ source files to test the performance of file I/O. The
scripts and the tested source files can be found in
:file:`LibOS/shim/test/apps/gcc/test_files`. The source files include:

* :file:`helloworld.c`: an extremely small source file
* :file:`gzip.c`: a |~| larger real-world application
* :file:`oggenc.m.c`: even larger, linked with libm.so
* :file:`single-gcc.c`: all of the gcc source in one source file, used as
  a |~| stress test

To test compilation of these source files, first prepare the GCC manifest to
compile the program::

   cd LibOS/shim/test/apps/gcc
   make

To test GCC, run :command:`gcc.manifest` as an executable. The manifest file is
actually a |~| script with a |~| shebang that can be automatically loaded in
PAL. Use the following commands::

   ./gcc.manifest -o test_files/hello test_files/helloworld.c
   ./gcc.manifest -o test_files/single-gcc test_files/single-gcc.c

.. todo:: SGX

.. _sample-lighttpd:

Lighttpd
--------

Lighttpd can be used to test the TCP latency and throughput of Graphene and/or
Graphene-SGX, in either single-threaded or multi-threaded environment. The
scripts and the source code for Lighttpd can be found in
:file:`LibOS/shim/test/apps/lighttpd`. To build Lighttpd, run the following
command::

   cd LibOS/shim/test/apps/lighttpd
   make
   # or under SGX:
   make SGX=1
   make SGX=1 sgx-tokens

The commands above will compile the source code, build the manifest file for
Graphene, generate the configuration file for Lighttpd, and generate the HTML
sample files. We prepared the following file samples:

* :file:`html/random/{*}.html`: random files (non-html) created with different
  sizes

The server should be started manually and tested by running the ApacheBench
(:command:`ab`) benchmark from a |~| remote client. To start the HTTP server,
run one of the following commands::

   make start-native-server
   # or
   make start-graphene-server
   # or under SGX
   make SGX=1 start-graphene-server

To start the server in a |~| multi-threaded environment, run one of the
following commands::

   make start-multithreaded-native-server
   # or
   make start-multithreaded-graphene-server
   # or under SGX
   make SGX=1 start-multithreaded-graphene-server

For testing, use ApacheBench (:command:`ab`). There is a script
:command:`run-apachebench.sh` that takes two arguments: the IP and the port. It
runs 100,000 requests (``-n 100000``) with 25 to 200 maximum outstanding
requests (``-c 25`` to ``-c 200``). The results are saved into the same
directory, and all previous output files are overwritten.

::

   make start-graphene-server  # or make SGX=1 start-graphene-server
   ./run-apachebench.sh <ip> <port>
   # which internally calls:
   #   ab -k -n 100000 -c [25:200] -t 10 http://ip:port/random/100.1.html

Apache
------

Apache is a |~| commercial-class web server that can be used to test the TCP
latency and throughput of Graphene. The scripts and the source code can be found
in :file:`LibOS/shim/test/apps/apache`. To build Apache, run the following
command::

   cd LibOS/shim/test/apps/apache
   make
   # or under SGX:
   make SGX=1
   make SGX=1 sgx-tokens

The commands above will compile the source code, build the manifest file for
Graphene, generate the configuration file for Apache, and generate the HTML
sample files (same as described in the :ref:`lighttpd section
<sample-lighttpd>`).

The server can be started manually via one of the following commands::

   make start-native-server
   # or
   make start-graphene-server
   # or under SGX
   make SGX=1 start-graphene-server

By default, the Apache web server is configured to run with 4 preforked worker
processes and has PHP support enabled. To test Apache server with :command:`ab`,
run::

   make start-graphene-server  # or make SGX=1 start-graphene-server
   ./run-apachebench.sh <ip> <port>
   # which internally calls:
   #   ab -k -n 100000 -c [25:200] -t 10 http://ip:port/random/100.1.html

Busybox
-------

Busybox is a standalone shell including general-purpose system utilities. The
scripts and the source code for Busybox is stored in
:file:`LibOS/shim/apps/busybox`. To build the source code with the proper
manifest, run the following commands::

   cd LibOS/shim/test/apps/busybox
   make
   # or under SGX:
   make SGX=1
   make SGX=1 sgx-tokens

To run Busybox, you may directly run :command:`busybox.manifest` built in the
directory as a |~| script. For example::

   ./busybox.manifest sh         # to run a shell
   ./busybox.manifest ls -l      # to list local directory

   # or under SGX:
   ./busybox.manifest.sgx sh     # to run a shell
   ./busybox.manifest.sgx ls -l  # to list local directory

Bash
----

Bash is the most commonly used shell utility in Linux. The scripts and the
source code for Bash are stored in :file:`LibOS/shim/apps/bash`. To build the
source code with the proper manifest, simply run the following commands::

   cd LibOS/shim/test/apps/bash
   make
   # or under SGX:
   make SGX=1
   make SGX=1 sgx-tokens

To test Bash, use the benchmark suites we prepared: :command:`bash_test.sh` and
:command:`unixbench`. Run one of the following commands to test Bash::

   ./bash.manifest bash_test.sh [times]
   ./bash.manifest unixbench.sh [times]

   # or under SGX:
   ./bash.manifest.sgx bash_test.sh [times]
   ./bash.manifest.sgx unixbench.sh [times]
