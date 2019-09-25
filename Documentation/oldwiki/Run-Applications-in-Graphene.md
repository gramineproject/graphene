# Run Applications in Graphene
We prepared and tested the following applications in Graphene library OS. These applications can be directly built and run from the Graphene library OS source.

* [[LMBench (v2.5) | Run Applications in Graphene#running lmbench in graphene]]
* [[Python | Run Applications in Graphene#running python in graphene]]
* [[R | Run Applications in Graphene#running r in graphene]]
* [[GCC | Run Applications in Graphene#running gcc in graphene ]]
* [[Lighttpd | Run Applications in Graphene#running lighttpd in graphene]]
* [[Apache | Run Applications in Graphene#running apache in graphene]]
* [[Busybox | Run Applications in Graphene#running busybox in graphene]]
* [[Bash | Run Applications in Graphene#running bash in graphene]]
* [[GNU Make | Run Applications in Graphene#running gnu make in graphene]]
* [[OpenJDK 1.7 | Run Applications in Graphene#running openjdk in graphene]]

## Running LMBench in Graphene

The LMBench source and scripts are stored in directory `LibOS/shim/test/apps/lmbench` inside the source tree. Many convenient commands are written in the Makefile inside the directory. The following steps will compile and run LMBench in native environment and Graphene Library OS.

    cd LibOS/shim/test/apps/lmbench
    make        # compile source of lmbench and set up manifests as target of graphene tests
    make test-native         # run the whole package in native environment
    make test-graphene       # run the whole package in graphene library OS

The result of native runs can be found in `lmbench-2.5/results/linux`. The result of graphene runs can be found in `lmbench-2.5/results/graphene`. The file with the largest number as suffix will be the latest output. Sometimes, for debugging purpose, you may want to test each LMBench test individually. For doing that, you may run the following commands:

    cd LibOS/shim/test/apps/lmbench
    cd lmbench-2.5/bin/linux/
    ./lat_syscall null        # run the specific test, for example, lat_syscall
    ./pal lat_syscall null    # run lat_syscall in Graphene

To run the tcp and udp latency tests:

     ./pal lat_udp -s &        # starts a server
     ./pal lat_udp 127.0.0.1   # starts a client
     ./pal lat_udp -127.0.0.1  # kills the server

## Running Python in Graphene

To run Python, first prepare the manifest:

    cd LibOS/shim/test/apps/python
    make

You can run `python.manifest` as an executable to load any script. The manifest file is actually a script with a shebang that can be automatically loaded in PAL. Use the following commands:

    ./python.manifest scripts/helloworld.py
    ./python.manifest scripts/fibonacci.py

In the case that you want to test a locally built python than the native python in the system, run the following command and replace the manifests:

    make python-local
    make

## Running R in Graphene

To run R, first prepare the manifest:

    cd LibOS/shim/test/apps/r
    make

You can run `R.manifest` as an executable to load any script. The manifest file is actually a script with a shebang that can be automatically loaded in PAL. Use the following commands:

    ./R.manifest -f scripts/sample.r

In the case that you want to test a locally built R than the native R in the system, run the following command and replace the manifests:

    make R-local
    make

## Running GCC in Graphene

In graphene we prepare several C/C++ source file to test the performance of file IO. Usually the native GCC and LD (linker) is used to compile the source code. The scripts and tested source files can be found in `LibOS/shim/test/apps/gcc`. The source files includes:

* `helloworld.c`: an extremely small source file
* `gzip.c`: an larger real-world application
* `oggenc.m.c`: even larger, linked with libm.so
* `single-gcc.c`: merge all gcc codes into a extremely huge source file. used as stress test.

To test compiling those source file, first prepare gcc manifest to compile the program:

    cd LibOS/shim/test/apps/gcc
    make

To run GCC for a single source code, you can run `gcc.manifest` as an executable. The manifest file is actually a script with a shebang that can be automatically loaded in PAL. Use the following commands:

    ./gcc.manifest -o helloworld helloworld.c
    ./gcc-huge.manifest -o single-gcc single-gcc.c (For some source code, GCC need a HUGE stack size to compile the source code)

In the case that you want to test a locally built gcc than the native gcc in the system, run the following command and replace the manifests:

    make gcc-local
    make

Building gcc requires a few libraries:

* `gmp`: GNU Multiple Precision Arithmetic Library
* `mpfr`: GNU Multiple-precision floating-point rounding library
* `mpc`: the GNU Multiple-precision C library

## Running Lighttpd in Graphene

Lighttpd can be used to test tcp latency and throughput of Graphene Library OS, in either single-threaded or multi-threaded environment. The scripts and source codes for Lighttpd can be found in `LibOS/shim/test/apps/lighttpd`. To compile the code base of Lighttpd that can be potentially used, run the following command:

    cd LibOS/shim/test/apps/lighttpd
    make

The building command will not only compile the source code, but build up manifests for Graphene, config file for Lighttpd, and test html files. We prepare the following test html files so far:

* html/oscar-web: a snapshot of [OSCAR website](http://www.oscar.cs.stonybrook.edu) with php support
* html/oscar-web-static: a snapshot of [OSCAR website](http://www.oscar.cs.stonybrook.edu) without php support
* html/random/*.html: random file (non-html) created into different sizes

The server should be started manually, and tested by running apache bench from a remote client. To start the http server either in native runs or graphene runs, run the following commands:

`make start-native-server` or `make start-graphene-server`.

To start the server in multi-threaded environment, run the following commands:

`make start-multithreaded-native-serve` and `make start-multithreaded-graphene-server`.

To actually test, you should use _ApacheBench_. _ApacheBench(ab)_ is an http client which can sit/run from any machine. When we benchmark lighttpd on Graphene, provided web server on Graphene is visible outside the host, one must be able to use ab from any of the lab machines. ab provides multiple options like the number of http requests, number of concurrent requests, silent mode, time delay between requests. The Ubuntu/Debian package is `apache2-utils`.

To test Lighttpd server with _ApacheBench_, first we need to start to Lighttpd server as above. There is a script run-apachebench.sh that takes two arguments: ip and port. It runs 10,000 requests (-n 10000) with 1, 2, 3, 4, and 5 maximum outstanding requests (-n 1...5). The results are saved into the same directory, and all previous output files are overwritten.

    make start-graphene-server
    ./run-apachebench.sh <ip> <port>
    # which internally calls:
    #   ab -k -n 100000 -c [25:200] -t 10 http://ip:port/random/100.1.html

## Running Apache in Graphene

Apache is a commercial-class web server that can be used to test tcp latency and throughput of Graphene Library OS. The scripts and source codes for Lighttpd can be found in `LibOS/shim/test/apps/apache`. To compile the code base of Apache and PHP module that can be potentially used, run the following command:

    cd LibOS/shim/test/apps/apache
    make

The building command will not only compile the source code, but build up manifests for Graphene, config file for Apache, and test html files (as described in the [[lighttpd section|Run applications in Graphene#Running Lighttpd in Graphene]]).

The server could be started manually by using the following commands:

`make start-native-server` or `make start-graphene-server`.

By default, the Apache web server is configured to run with 4 preforked worker processes, and has PHP support enabled.

To test Apache server with _ApacheBench_, first we need to start to Apache server as above. Run the same script to test with ApacheBench:

    make start-graphene-server
    ./run-apachebench.sh <ip> <port>
    # which internally calls:
    #   ab -k -n 100000 -c [25:200] -t 10 http://ip:port/random/100.1.html

## Running Busybox in Graphene

Busybox is a standalone shell including general-purpose system utilities. Running Busybox is a lot easier than running real shells such as Bash, because: first, Busybox can use _vfork_ instead of _fork_ to create new processes. second, Busybox can call itself as any of the utilities it includes, no need for calling some other binaries. The scripts and source code for Busybox is store in `LibOS/shim/apps/busybox`. To build the source code with proper manifest, simple run the following commands:

    cd Shim/shim/test/apps/busybox
    make

To run busybox, either to run a shell or a utility, you may directly run busybox.manifest built in the directory as a script. For example:

    ./busybox.manifest sh (to run a shell)

or

    ./busybox.manifest ls -l (to list local directory)

## Running Bash in Graphene

Bash is the most commonly used shell utilities in Linux. Bash can be run as a interactive standalone shell, or execute scripts or binaries immediately. Besides a few built-in commands, Bash mostly relies on other standalone utilities to execute commands given in the shell, such as `ls`, `cat` or `grep`. Therefore, supporting Bash will require supporting all the utility programs that can be potentially used. The scripts and source code for Bash is store in `LibOS/shim/apps/bash`. To build the source code with proper manifest, simple run the following commands:

    cd Shim/shim/test/apps/bash
    make

To test Bash, you may use the benchmark suites we prepared: one is `bash_test.sh`, and the other is `unixbench`. Run one of the following commands to test Bash:

    ./bash.manifest bash_test.sh [times]
    ./bash.manifest unixbench.sh [times]

In the case that you want to test a locally built Bash than the native Bash in the system, run the following command and replace the manifests:

    make bash-local
    make

## Running GNU Make in Graphene

GNU Make is the most commonly used building tool in Linux. GNU Make is one of the most hard-to-implement applications in Graphene because it requires full multi-processing support, Bash support and other potentially used utility programs. The scripts and source code for GNU Make is store in `LibOS/shim/apps/make`. To build the source code with proper manifest, simple run the following commands:

    cd Shim/shim/test/apps/make
    make

Currently we can only support GNU Make with very specific Makefile scripts, and not able to support other building tools such as _libtool_, _autoconf_ and _automake_. We have prepared some Makefile scripts that are proven working in Graphene:

* `helloworld`: a Makefile script that only compile one source file `helloworld.c`
* `Graphene LibOS`: eating our own dog food. Compile Graphene Library OS with Graphene Library OS.
* `bzip2` and `oggenc` 

To test one of those Makefile script in Graphene, run the following commands:

    make clean -C graphene
    ./make.manifest -C graphene NPROC=<num of processes>

In the case that you want to test a locally built GNU Make than the native GNU Make in the system, run the following command and replace the manifests:

    make make-local
    make

## Running OpenJDK in Graphene

We have tested OpenJDK 1.6 and 1.7 in Graphene library OS. Newer versions of OpenJDK can potentially work, but there is no guarantee. 

Make sure you install the build dependencies for OpenJDK first.  Sadly, openjdk itself seems like a prerequisite to build openjdk.

On Ubuntu 14.04:

    sudo apt-get build-dep openjdk-7
    sudo apt-get install openjdk-7-jdk

To build OpenJDK 1.7 and generate the manifest, run the following commands:

    cd LibOS/shim/test/apps/openjdk
    make

For SGX support, do this:

    make SGX=1; make SGX=1 sgx-tokens

The building will take several minutes and require network connection to download packages. After building OpenJDK, use the following script to run a Java program:

    <path to pal> java.manifest -cp classes HelloWorld

For SGX, use the java.manifest.sgx instead of java.manifest.

We can only confirm that openjdk works on 14.04.

In `run-compact-java` we specify the OpenJDK options to limit the resource used by the OpenJDK VM. We do not suggest running OpenJDK without these options, because the assumptions made by OpenJDK may cause Graphene library OS to crash.