Quick start
===========

.. highlight:: sh

Quick start without SGX support
-------------------------------

#. Clone the Graphene repository::

      git clone https://github.com/oscarlab/graphene.git

#. Build Graphene::

      sudo apt-get install -y build-essential autoconf gawk bison wget python3
      cd graphene
      make
      meson build -Ddirect=enabled -Dsgx=disabled
      ninja -C build
      sudo ninja -C build install

#. Build and run :program:`helloworld`::

      cd LibOS/shim/test/regression
      make
      graphene-direct helloworld

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
in https://github.com/intel/linux-sgx and
https://github.com/intel/linux-sgx-driver to download and install them.
If you want to use the DCAP SDK and driver, please follow the README in
https://github.com/intel/SGXDataCenterAttestationPrimitives. Please note, that
the DCAP driver requires Graphene to run as a root user to access it.

#. Ensure that Intel SGX is enabled on your platform::

      lsmod | grep sgx
      ps ax | grep [a]esm_service

The first command should list :command:`isgx` (or :command:`sgx`) and the
second command should list the process status of :command:`aesm_service`.

#. Clone the Graphene repository::

      git clone https://github.com/oscarlab/graphene.git
      cd graphene

#. Prepare a signing key::

      openssl genrsa -3 -out Pal/src/host/Linux-SGX/signer/enclave-key.pem 3072

#. Build Graphene and Graphene-SGX::

      sudo apt-get install -y \
         build-essential autoconf gawk bison wget python3 libcurl4-openssl-dev \
         python3-protobuf libprotobuf-c-dev protobuf-c-compiler python3-pip
      python3 -m pip install toml>=0.10
      make
      make ISGX_DRIVER_PATH=<path-to-sgx-driver-sources> SGX=1
      meson build -Ddirect=enabled -Dsgx=enabled
      ninja -C build
      sudo ninja -C build install

#. Set ``vm.mmap_min_addr=0`` in the system (*only required for the legacy SGX
   driver and not needed for newer DCAP/in-kernel drivers*)::

      sudo sysctl vm.mmap_min_addr=0

   Note that this is an inadvisable configuration for production systems.

#. Build and run :program:`helloworld`::

      cd LibOS/shim/test/regression
      make SGX=1
      make SGX=1 sgx-tokens
      graphene-sgx helloworld

Running sample applications
---------------------------

We prepared and tested several applications to demonstrate Graphene and
Graphene-SGX usability. These applications can be found in the :file:`Examples`
folder in the repository, each containing a short README with instructions how
to test it. We recommend starting with simpler, thoroughly documented examples
like Memcached and Redis, to understand manifest options and features of
Graphene.
