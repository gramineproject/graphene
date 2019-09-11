Before you run any applications in Graphene-SGX, please make sure that Intel SGX SDK and the SGX
driver are installed on your system. We recommend using Intel SGX SDK and the SGX driver no older
than version 2.1.

If Intel SGX SDK and the SGX driver are not installed, please follow the READMEs in
<https://github.com/01org/linux-sgx> and <https://github.com/01org/linux-sgx-driver> to download
and install them.

### 1. Ensure That Intel SGX is Enabled on Your Platform

    lsmod | grep isgx
    ps ax | grep [a]esm_service

The first command should list `isgx` and the second command should list the process status of
`aesm_service`.

### 2. Clone the Repository and Set the Home Directory of Graphene

    git clone https://github.com/oscarlab/graphene.git
    cd graphene
    git submodule update --init -- Pal/src/host/Linux-SGX/sgx-driver/
    export GRAPHENE_DIR=$PWD

### 3. Prepare a Signing Key

    cd $GRAPHENE_DIR/Pal/src/host/Linux-SGX/signer
    openssl genrsa -3 -out enclave-key.pem 3072

### 4. Build and Install Graphene SGX Driver

    cd $GRAPHENE_DIR/Pal/src/host/Linux-SGX/sgx-driver
    make
    (The console will be prompted to ask for the path of the Intel SGX driver code)
    sudo ./load.sh

### 5. Build Graphene-SGX

    cd $GRAPHENE_DIR
    make SGX=1

### 6. Set `vm.mmap_min_addr=0` in the System

    sudo sysctl vm.mmap_min_addr=0

### 7. Build and Run `helloworld`

    cd $GRAPHENE_DIR/LibOS/shim/test/native
    make SGX=1
    make SGX_RUN=1
    SGX=1 ./pal_loader helloworld

### 8. Test LMBench Application

    cd $GRAPHENE_DIR
    git submodule update --init -- LibOS/shim/test/apps
    cd $GRAPHENE_DIR/LibOS/shim/test/apps/lmbench
    make SGX=1
    cd lmbench-2.5/bin/linux
    SGX=1 ./pal_loader lat_syscall null
    SGX=1 ./pal_loader lat_syscall open
    SGX=1 ./pal_loader lat_syscall read
    SGX=1 ./pal_loader lat_proc fork

