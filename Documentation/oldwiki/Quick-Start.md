# Quick Start
## Quick Start without Reference Monitor

If you simply want to run Graphene without rebuilding the host kernel, try the following steps:

__** Note: Please use GCC version 4 or 5 **__

### 1. build PAL

    cd Pal/src
    make

### 2. build and install Bulk Copy kernel module

    cd Pal/ipc/linux
    make
    sudo ./load.sh

### 3. build the library OS

    cd LibOS
    make SGX=1

### 4. Run a helloworld program

    cd LibOS/shim/test/native
    make
    ./pal_loader helloworld

### 5. Run LMBench

    cd LibOS/shim/test/apps/lmbench
    make
    cd lmbench-2.5/bin/linux
    ./pal_loader lat_syscall null
    ./pal_loader lat_syscall open
    ./pal_loader lat_syscall read
    ./pal_loader lat_proc fork