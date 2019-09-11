(The following quick start instruction does not include the steps for running Graphene with
sandboxing because sandboxing is an experimental feature.)

### 1. Clone the Graphene Repository

    git clone https://github.com/oscarlab/graphene.git

### 2. Build Graphene

    cd graphene
    make

### 3. Build and Run `helloworld`

    cd LibOS/shim/test/native
    make
    ./pal_loader helloworld

### 4. Test LMBench Application

    cd ..
    git submodule update --init apps
    cd apps/lmbench
    make
    cd lmbench-2.5/bin/linux
    ./pal_loader lat_syscall null
    ./pal_loader lat_syscall open
    ./pal_loader lat_syscall read
    ./pal_loader lat_proc fork

