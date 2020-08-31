# Java Block Chain Demo

This directory contains the Makefile and the template manifest for the most
popular version of Java (as of this writing, version 11). This was tested
on a machine with SGX v1 and Ubuntu 18.04.

The Makefile and the template manifest contain extensive comments and are made
self-explanatory. Please review them to gain understanding of Graphene-SGX
and requirements for applications running under Graphene-SGX.

# Additional Prerequisites:
    1) An OpenJDK installed in folder /opt (default: /opt/jdk)
    2) Gradle installed on system
    3) Gradle proxy configured in ~/.gradle/gradle.properties if behind firewall

# Quick Start

```sh
# build Java blockchain demo and the final manifest
make # without SGX support (default: /opt/jdk)
make SGX=1 # with SGX support (default: /opt/jdk)
make SGX=1 JDK_HOME=<JDK home folder under /opt>

# run Java blockchain demo natively (default JDK_HOME: /opt/jdk)
make run-native

# run Java blockchain demo in non-SGX Graphene
make run-gr

# run Java blockchain demo in Graphene-SGX
make SGX=1 run-gr
```

# Tuning up

Notice that by default, we run Java blockchain demo configured with 8G enclave size, 2G Java maximum
heap size and 256 SGX enclave maximum thread number, you can adjust these parameters to fit into
your system configuration and needs.

```sh
# Specify the Java maximum heap size in Gigabytes
make G_JAVA_XMX = <Java maximum heap size> # default: 2G

# Specify the Graphene SGX enclave capacity in Gigabytes, subject to 2^n
make G_SGX_SIZE = <GSGX enclave capacity> # default: 8G

# Specify the Graphene SGX maximum number of thread
make G_SGX_THREAD_NUM = <GSGX maximum number of thread> # default: 256
```

# Cleaning up

```sh
# clean Graphene generated files
make clean

# clean all generated files
make distclean
```
