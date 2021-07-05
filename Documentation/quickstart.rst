Quick start
===========

.. highlight:: sh

.. note::

   When installing from sources, Graphene executables are placed under
   ``/usr/local/bin``. Some Linux distributions (notably CentOS) do not search
   for executables under this path. If your system reports that Graphene
   programs can not be found, you might need to edit your configuration files so
   that ``/usr/local/bin`` is in your path (in the ``PATH`` environment
   variable).

Quick start without SGX support
-------------------------------

#. Clone the Graphene repository::

      git clone https://github.com/oscarlab/graphene.git

#. Build Graphene::

      sudo apt-get install -y build-essential autoconf gawk bison wget python3
      cd graphene
      make
      meson build --buildtype=release -Ddirect=enabled -Dsgx=disabled
      ninja -C build
      sudo ninja -C build install

#. Build and run :program:`helloworld`::

      cd LibOS/shim/test/regression
      make
      graphene-direct helloworld

#. For more complex examples, see :file:`Examples` directory.

Quick start with SGX support
-------------------------------

Graphene requires several features from your system:

- the FSGSBASE feature of recent processors must be enabled in the Linux kernel,
- the Intel SGX driver must be built in the Linux kernel,
- Intel SGX SDK/PSW and (optionally) Intel DCAP must be installed.

If your system doesn't meet these requirements, please refer to more detailed
descriptions in :doc:`building`.

#. Ensure that Intel SGX is enabled on your platform using
   :program:`is_sgx_available`.

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
      make ISGX_DRIVER_PATH="" SGX=1                  # this assumes Linux 5.11+
      meson build --buildtype=release -Ddirect=enabled -Dsgx=enabled
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
