We prepared and tested the following applications in Graphene library OS. These applications can be directly built and run from the Graphene library OS source.

* [[LMBench (v2.5) | Run Applications in Graphene#running lmbench in graphene]]
* [[Python | Run Applications in Graphene#running python in graphene]]
* [[R | Run Applications in Graphene#running r in graphene]]
* [[GCC | Run Applications in Graphene#running gcc in graphene ]]
* [[Lighttpd | Run Applications in Graphene#running lighttpd in graphene]]
* [[Apache | Run Applications in Graphene#running apache in graphene]]
* [[Busybox | Run Applications in Graphene#running busybox in graphene]]
* [[Bash | Run Applications in Graphene#running bash in graphene]]

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

     ./pal_loader lat_udp -s &        # starts a server
     ./pal_loader lat_udp 127.0.0.1   # starts a client
     ./pal_loader lat_udp -127.0.0.1  # kills the server

## Running Python in Graphene

To run Python, first prepare the manifest:

    cd LibOS/shim/test/apps/python
    make

You can run `python.manifest` as an executable to load any script. The manifest file is actually a script with a shebang that can be automatically loaded in PAL. Use the following commands:

    ./python.manifest scripts/helloworld.py
    ./python.manifest scripts/fibonacci.py



## Running R in Graphene

To run R, first prepare the manifest:

    cd LibOS/shim/test/apps/r
    make

You can run `R.manifest` as an executable to load any script. The manifest file is actually a script with a shebang that can be automatically loaded in PAL. Use the following commands:

    ./R.manifest -f scripts/sample.r


## Running GCC in Graphene

In Graphene, we prepare several C/C++ source files to test the performance of file IO. Usually, the native GCC and LD (linker) are used to compile the source code. The scripts and tested source files can be found in `LibOS/shim/test/apps/gcc/test_files`. The source files include:

* `helloworld.c`: an extremely small source file
* `gzip.c`: a larger real-world application
* `oggenc.m.c`: even larger, linked with libm.so
* `single-gcc.c`: merge all gcc codes into an extremely huge source file. used as a stress test.

To test compiling those source file, first prepare the GCC manifest to compile the program:

    cd LibOS/shim/test/apps/gcc
    make

To run GCC, you can run `gcc.manifest` as an executable. The manifest file is actually a script with a shebang that can be automatically loaded in PAL. Use the following commands:

    ./gcc.manifest -o test_files/hello test_files/helloworld.c
    ./gcc.manifest -o test_files/single-gcc test_files/single-gcc.c


## Running Lighttpd in Graphene

Lighttpd can be used to test tcp latency and throughput of Graphene Library OS, in either single-threaded or multi-threaded environment. The scripts and source codes for Lighttpd can be found in `LibOS/shim/test/apps/lighttpd`. To compile the code base of Lighttpd that can be potentially used, run the following command:

    cd LibOS/shim/test/apps/lighttpd
    make

The commands above will compile the source code, build the manifest file for Graphene, generate the configuration file for Apache, and generate the HTML sample files. We prepare the following file samples:

* html/random/*.html: random file (non-html) created into different sizes

The server should be started manually, and tested by running apache bench from a remote client. To start the http server either in native runs or graphene runs, run the following commands:

`make start-native-server` or `make start-graphene-server`.

To start the server in multi-threaded environment, run the following commands:

`make start-multithreaded-native-serve` and `make start-multithreaded-graphene-server`.

To actually test, you should use _ApacheBench_. _ApacheBench(ab)_ is an HTTP client which can sit/run from any machine. When we benchmark lighttpd on Graphene, provided web server on Graphene is visible outside the host, one must be able to use ab from any of the lab machines. ab provides multiple options like the number of HTTP requests, number of concurrent requests, silent mode, the time delay between requests. The Ubuntu/Debian package is `apache2-utils`.

To test Lighttpd server with _ApacheBench_, first, we need to start to Lighttpd server as above. There is a script run-apachebench.sh that takes two arguments: the IP and port. It runs 100,000 requests (-n 100000) with 25 to 200 maximum outstanding requests (-n 25 to 200). The results are saved into the same directory, and all previous output files are overwritten.

    make start-graphene-server
    ./run-apachebench.sh <ip> <port>
    # which internally calls:
    #   ab -k -n 100000 -c [25:200] -t 10 http://ip:port/random/100.1.html

## Running Apache in Graphene

Apache is a commercial-class web server that can be used to test tcp latency and throughput of Graphene Library OS. The scripts and source codes for Lighttpd can be found in `LibOS/shim/test/apps/apache`. To compile the code base of Apache and PHP module that can be potentially used, run the following command:

    cd LibOS/shim/test/apps/apache
    make

The commands above will compile the source code, build the manifest file for Graphene, generate the configuration file for Apache, and generate the HTML sample files (same as described in the [[lighttpd section|Run applications in Graphene#Running Lighttpd in Graphene]]).

The server could be started manually by using the following commands:

`make start-native-server` or `make start-graphene-server`.

By default, the Apache web server is configured to run with 4 preforked worker processes, and has PHP support enabled.

To test Apache server with _ApacheBench_, first we need to start to Apache server as above. Run the same script to test with ApacheBench:

    make start-graphene-server
    ./run-apachebench.sh <ip> <port>
    # which internally calls:
    #   ab -k -n 100000 -c [25:200] -t 10 http://ip:port/random/100.1.html

## Running Busybox in Graphene

Busybox is a standalone shell including general-purpose system utilities. Running Busybox is a lot easier than running real shells such as Bash, because: first, Busybox can use _vfork_ instead of _fork_ to create new processes. second, Busybox can call itself as any of the utilities it includes, no need for calling some other binaries. The scripts and source code for Busybox is store in `LibOS/shim/apps/busybox`. To build the source code with the proper manifest, simply run the following commands:

    cd Shim/shim/test/apps/busybox
    make

To run busybox, either to run a shell or a utility, you may directly run busybox.manifest built in the directory as a script. For example:

    ./busybox.manifest sh (to run a shell)

or

    ./busybox.manifest ls -l (to list local directory)

## Running Bash in Graphene

Bash is the most commonly used shell utilities in Linux. Bash can be run as an interactive standalone shell, or execute scripts or binaries immediately. Besides a few built-in commands, Bash mostly relies on other standalone utilities to execute commands given in the shell, such as `ls`, `cat` or `grep`. Therefore, supporting Bash will require supporting all the utility programs that can be potentially used. The scripts and source code for Bash is store in `LibOS/shim/apps/bash`. To build the source code with the proper manifest, simply run the following commands:

    cd Shim/shim/test/apps/bash
    make

To test Bash, you may use the benchmark suites we prepared: one is `bash_test.sh`, and the other is `unixbench`. Run one of the following commands to test Bash:

    ./bash.manifest bash_test.sh [times]
    ./bash.manifest unixbench.sh [times]
