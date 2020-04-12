Quick Start
===========

.. highlight:: sh

#. Clone the Graphene Repository::

      git clone https://github.com/oscarlab/graphene.git

#. Build Graphene::

      sudo apt-get install -y build-essential autoconf gawk bison
      cd graphene
      make

#. Build and Run :program:`helloworld`::

      cd LibOS/shim/test/native
      make
      ./pal_loader helloworld

#. Test LMBench Application::

      cd ../../../../Examples/lmbench
      make
      cd lmbench-2.5/bin/linux
      ./pal_loader lat_syscall null
      ./pal_loader lat_syscall open
      ./pal_loader lat_syscall read
      ./pal_loader lat_proc fork

#. For more complex examples, see :file:`Examples` directory.

SGX Quick Start
---------------

Before you run any applications in Graphene-SGX, please make sure that Intel SGX
SDK and the SGX driver are installed on your system. We recommend using Intel
SGX SDK and the SGX driver no older than version 1.9 (or the DCAP SGX SDK and
the driver version 1.4/1.5).

If Intel SGX SDK and the SGX driver are not installed, please follow the READMEs
in https://github.com/01org/linux-sgx and
https://github.com/01org/linux-sgx-driver to download and install them.
If you want to use the DCAP SDK and driver, please follow the README in
https://github.com/intel/SGXDataCenterAttestationPrimitives. Please note, that
the DCAP driver requires Graphene to run as a root user to access it.

#. Ensure That Intel SGX is Enabled on Your Platform::

      lsmod | grep sgx
      ps ax | grep [a]esm_service

The first command should list :command:`isgx` (or :command:`sgx`) and the
second command should list the process status of :command:`aesm_service`.

#. Clone the Repository and Set the Home Directory of Graphene::

      git clone https://github.com/oscarlab/graphene.git
      cd graphene
      git submodule update --init -- Pal/src/host/Linux-SGX/sgx-driver/
      export GRAPHENE_DIR=$PWD

#. Prepare a Signing Key::

      cd $GRAPHENE_DIR/Pal/src/host/Linux-SGX/signer
      openssl genrsa -3 -out enclave-key.pem 3072

#. Build and Install Graphene SGX Driver::

      cd $GRAPHENE_DIR/Pal/src/host/Linux-SGX/sgx-driver
      make
      # the console will prompt you for the path of the Intel SGX driver code
      sudo insmod gsgx.ko

#. Build Graphene-SGX::

      sudo apt-get install -y \
         build-essential autoconf gawk bison \
         python3-protobuf libprotobuf-c-dev protobuf-c-compiler
      cd $GRAPHENE_DIR
      make SGX=1

#. Set ``vm.mmap_min_addr=0`` in the System::

      sudo sysctl vm.mmap_min_addr=0

#. Build and Run :program:`helloworld`::

      cd $GRAPHENE_DIR/LibOS/shim/test/native
      make SGX=1
      make SGX=1 sgx-tokens
      SGX=1 ./pal_loader helloworld

#. Test LMBench Application::

      cd $GRAPHENE_DIR/Examples/lmbench
      make SGX=1
      cd lmbench-2.5/bin/linux
      SGX=1 ./pal_loader lat_syscall null
      SGX=1 ./pal_loader lat_syscall open
      SGX=1 ./pal_loader lat_syscall read
      SGX=1 ./pal_loader lat_proc fork
