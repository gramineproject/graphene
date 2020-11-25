Quick start
===========

.. highlight:: sh

Quick start without SGX support
-------------------------------

#. Clone the Graphene repository::

      git clone https://github.com/oscarlab/graphene.git

#. Build Graphene::

      sudo apt-get install -y build-essential autoconf gawk bison
      cd graphene
      make

#. Build and run :program:`helloworld`::

      cd LibOS/shim/test/native
      make
      ./pal_loader helloworld

#. For more complex examples, see :file:`Examples` directory.

Quick start with SGX support
-------------------------------

Graphene-SGX requires that the FSGSBASE feature of recent processors is enabled
in the Linux kernel. For the ways to enable the FSGSBASE feature, please refer
to :doc:`building`.

Before you run any applications in Graphene-SGX, please make sure that Intel SGX
SDK and the SGX driver are installed on your system. We recommend using Intel
SGX SDK and the SGX driver no older than version 1.9 (or the DCAP SGX SDK and
the driver version 1.4/1.5/1.6).

If Intel SGX SDK and the SGX driver are not installed, please follow the READMEs
in https://github.com/01org/linux-sgx and
https://github.com/01org/linux-sgx-driver to download and install them.
If you want to use the DCAP SDK and driver, please follow the README in
https://github.com/intel/SGXDataCenterAttestationPrimitives. Please note, that
the DCAP driver requires Graphene to run as a root user to access it.

#. Ensure that Intel SGX is enabled on your platform::

      lsmod | grep sgx
      ps ax | grep [a]esm_service

The first command should list :command:`isgx` (or :command:`sgx`) and the
second command should list the process status of :command:`aesm_service`.

#. Clone the repository and set the home directory of Graphene::

      git clone https://github.com/oscarlab/graphene.git
      cd graphene
      export GRAPHENE_DIR=$PWD

#. Prepare a signing key::

      cd $GRAPHENE_DIR/Pal/src/host/Linux-SGX/signer
      openssl genrsa -3 -out enclave-key.pem 3072

#. Build Graphene-SGX::

      sudo apt-get install -y \
         build-essential autoconf gawk bison libcurl4-openssl-dev \
         python3-protobuf libprotobuf-c-dev protobuf-c-compiler
      cd $GRAPHENE_DIR
      make SGX=1
      # the console will prompt you for the path to the Intel SGX driver code
      # (simply press ENTER if you use the in-kernel Intel SGX driver)

#. Set ``vm.mmap_min_addr=0`` in the system (*only required for the legacy SGX
   driver and not needed for newer DCAP/in-kernel drivers*)::

      sudo sysctl vm.mmap_min_addr=0

   Note that this is an inadvisable configuration for production systems.

#. Build and run :program:`helloworld`::

      cd $GRAPHENE_DIR/LibOS/shim/test/native
      make SGX=1 sgx-tokens
      SGX=1 ./pal_loader helloworld

Running sample applications
---------------------------

We prepared and tested several applications to demonstrate Graphene and
Graphene-SGX usability. These applications can be found in the :file:`Examples`
folder in the repository, each containing a short README with instructions how
to test it. We recommend starting with simpler, thoroughly documented examples
like Memcached and Redis, to understand manifest options and features of
Graphene.
