How to build Graphene?
======================

.. highlight:: sh

.. todo::

   This page really belongs to :file:`devel/`, move it there after a |~| proper
   release. Instead, for all users, there should be documentation for installing
   without full compilation.

Graphene consists of three parts:

- An instrumented GNU C Library
- The Library OS itself (a shared library named ``libsysdb.so``, called the
  "shim" in our source code)
- The Platform Adaptation Layer, or PAL (a shared library named ``libpal.so``)

Prerequisites
-------------

Graphene currently only works on the x86_64 architecture. Graphene is currently
tested on Ubuntu 16.04 and 18.04 (both server and desktop version), along with
Linux kernel versions 3.x/4.x/5.x. We recommend building and installing Graphene
on the same host platform. If you find problems with Graphene on other Linux
distributions, please contact us with a |~| detailed `bug report
<https://github.com/oscarlab/graphene/issues/new>`__.

Run the following command on Ubuntu to install dependencies for Graphene::

    sudo apt-get install -y build-essential autoconf gawk bison

For building Graphene for SGX, run the following command in addition::

    sudo apt-get install -y libprotobuf-c-dev protobuf-c-compiler

    # For Ubuntu 18.04
    sudo apt-get install -y python3-protobuf

    # For Ubuntu 16.04
    sudo apt install -y python3-pip
    sudo /usr/bin/pip3 install protobuf

To run tests locally, you also need the python3-pytest package::

    sudo apt-get install -y python3-pytest

To build Graphene, simply run the following commands in the root of the
source tree::

    git submodule update --init -- Pal/src/host/Linux-SGX/sgx-driver/
    make

Building
--------

Each part of Graphene can be built separately in the subdirectories.

To build Graphene with debug symbols, run :command:`make DEBUG=1`
instead of :command:`make`. To specify custom mirrors for downloading the Glibc
source, use :command:`make GLIBC_MIRRORS=...`.

To build with ``-Werror``, run :command:`make WERROR=1`.

Building with Intel SGX Support
-------------------------------

Prerequisites
^^^^^^^^^^^^^

1. Generate signing keys

   A 3072-bit RSA private key (PEM format) is required for signing the manifest.
   If you don't have a private key, create it with the following command::

      openssl genrsa -3 -out enclave-key.pem 3072

   You can either place the generated enclave key in the default path,
   :file:`host/Linux-SGX/signer/enclave-key.pem`, or specify the key's location
   through the environment variable ``SGX_SIGNER_KEY``.

   After signing the application's manifest, users may ship the application and
   Graphene binaries, along with an SGX-specific manifest (``.manifest.sgx``
   extension), the signature (``.sig`` extension), and the aesmd init token
   (``.token`` extension) to execute on another SGX-enabled host.

2. Install the Intel SGX SDK and driver

   The Intel SGX Linux SDK is required to compile and run Graphene on SGX.
   Download and install it from the official Intel GitHub repositories:

   - <https://github.com/01org/linux-sgx>
   - <https://github.com/01org/linux-sgx-driver>

3. Build and install the Graphene SGX driver
   A Graphene-specific Linux driver must also be installed before running
   Graphene in an SGX environment. Simply run the following commands to build
   the driver::

      cd Pal/src/host/Linux-SGX/sgx-driver
      make
      # The console will be prompted to ask for the path of Intel SGX driver code
      sudo insmod gsgx.ko
      sudo sysctl vm.mmap_min_addr = 0

   We note that this last command is a |~| temporary work-around for some issues
   with the Intel SGX driver. This is an inadvisable configuration for
   production systems. We hope to remove this step in a |~| future version of
   Graphene, once the SGX driver is upstreamed to Linux.

Building Graphene-SGX
^^^^^^^^^^^^^^^^^^^^^

To build Graphene with Intel SGX support, in the root directory of Graphene
repo, run the following command::

   make SGX=1

To build with debug symbols, instead run the command::

   make SGX=1 DEBUG=1

Running :command:`make SGX=1` in the test or regression directory will
automatically generate the required manifest signatures (``.sig`` files).

Deprecated features
-------------------

Building with kernel-level sandboxing (optional)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This feature is marked as EXPERIMENTAL and no longer exists on the master
branch.
