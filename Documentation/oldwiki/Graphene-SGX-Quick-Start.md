Before you run any applications in Graphene-SGX, please make sure the Intel SGX Linux SDK and Linux
driver are installed on your system. We recommend using Intel SGX Linux SDK and Linux driver no
older than 2.1.

If Intel SGX Linux SDK and Linux driver are not installed, please follow the READMEs in
<https://github.com/01org/linux-sgx> and <https://github.com/01org/linux-sgx-driver> to download and
install them.

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

### 4. Build Graphene (Including the SGX PAL and the LibOS)

    cd $GRAPHENE_DIR
    make SGX=1

### 5. Build and Install Graphene SGX Driver

    cd $GRAPHENE_DIR/Pal/src/host/Linux-SGX/sgx-driver
    make
    sudo ./load.sh

During the installation, you will be prompted to enter the source code of the Intel SGX Linux driver. Type in the path and the driver version and continue.

### 6. Set `vm.mmap_min_addr=0` in the System

    sudo sysctl vm.mmap_min_addr=0

### 7. Run `helloworld`

    cd $GRAPHENE_DIR/LibOS/shim/test/native
    make SGX=1
    make SGX_RUN=1
    SGX=1 ./pal_loader helloworld

### 9. Run Applications in Graphene-SGX (Example: LMBench)

    cd $GRAPHENE_DIR
    git submodule update --init -- LibOS/shim/test/apps
    cd $GRAPHENE_DIR/LibOS/shim/test/apps/lmbench
    make SGX=1
    cd lmbench-2.5/bin/linux
    SGX=1 ./pal_loader lat_syscall null
    SGX=1 ./pal_loader lat_syscall open
    SGX=1 ./pal_loader lat_syscall read
    SGX=1 ./pal_loader lat_proc fork

