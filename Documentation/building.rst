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

    sudo apt-get install -y libprotobuf-c-dev protobuf-c-compiler \
       libcurl4-openssl-dev

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

1. Install the Linux kernel patched with FSGSBASE
"""""""""""""""""""""""""""""""""""""""""""""""""

FSGSBASE is a feature in recent processors which allows direct access to the FS
and GS segment base addresses. For more information about FSGSBASE and its
benefits, see `this discussion <https://lwn.net/Articles/821719>`__.

Work is being done to include FSGSBASE enabling in the upstream Linux kernel.
Currently, the FSGSBASE enabling code is out-of-tree, requiring some patches to
the kernel.

Enabling FSGSBASE support requires building and installing a custom kernel with
backported patches. The instructions to patch and compile a Linux kernel with
FSGSBASE support below are written around Ubuntu 18.04 LTS (Bionic Beaver) with
a Linux 5.4 LTS stable kernel but can be adapted for other distros as necessary.
These instructions ensure that the resulting kernel has FSGSBASE support and up
to date security mitigations.

#. Setup a build environment for kernel development following `the instructions
   in the Ubuntu wiki <https://wiki.ubuntu.com/KernelTeam/GitKernelBuild>`__.
   Clone Linux version 5.4 via::

       git clone --single-branch --branch linux-5.4.y \
           https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
       cd linux

#. Apply the provided FSGSBASE patches to the kernel source tree::

       git am <graphene-dir>/Pal/src/host/Linux-SGX/sgx-driver/fsgsbase_patches/*.patch

   The conversation regarding this patchset can be found in the kernel mailing
   list archives `here
   <https://lore.kernel.org/lkml/20200528201402.1708239-1-sashal@kernel.org>`__.

#. Build and install the kernel following `the instructions in the Ubuntu wiki
   <https://wiki.ubuntu.com/KernelTeam/GitKernelBuild>`__.

#. After rebooting, verify the patched kernel is the one that has been booted
   and is running::

       uname -r

#. Also verify that the patched kernel supports FSGSBASE (the below command
   must return that bit 2 is set)::

       LD_SHOW_AUXV=1 /bin/true | grep AT_HWCAP2

After the patched Linux kernel is installed, you may proceed with installations
of other SGX software infrastructure: the Intel SGX Linux driver, the Intel SGX
SDK/PSW, and Graphene itself (see next steps). Note that older versions of
these software packages may not work with recent Linux kernels like 5.4. We
recommend to use commit ``b7ccf6f`` of the Intel SGX Linux Driver for Intel SGX
DCAP and commit ``0e71c22`` of the Intel SGX SDK/PSW.


2. Generate signing keys
""""""""""""""""""""""""

A 3072-bit RSA private key (PEM format) is required for signing the manifest.
If you don't have a private key, create it with the following command::

   openssl genrsa -3 -out enclave-key.pem 3072

You can either place the generated enclave key in the default path,
:file:`Pal/src/host/Linux-SGX/signer/enclave-key.pem`, or specify the key's
location through the environment variable ``SGX_SIGNER_KEY``.

After signing the application's manifest, users may ship the application and
Graphene binaries, along with an SGX-specific manifest (``.manifest.sgx``
extension), the signature (``.sig`` extension), and the aesmd init token
(``.token`` extension) to execute on another SGX-enabled host.

3. Install the Intel SGX driver and SDK/PSW
"""""""""""""""""""""""""""""""""""""""""""

The Intel SGX Linux SDK and the Intel SGX driver are required to compile and
run Graphene on SGX. Download and install them from the official Intel
GitHub repositories:

- https://github.com/01org/linux-sgx
- https://github.com/01org/linux-sgx-driver

Alternatively, if you want to use the DCAP versions of the SDK and driver,
download and install it from:

- https://github.com/intel/SGXDataCenterAttestationPrimitives

4. Install the Graphene SGX driver (not for production)
"""""""""""""""""""""""""""""""""""""""""""""""""""""""

If you followed step 1 and installed the patched Linux kernel, skip this step.
Otherwise, you will need a Graphene-specific Linux driver that enables the
FSGSBASE feature available in recent processors.

To install the Graphene SGX driver, run the following commands::

   cd Pal/src/host/Linux-SGX/sgx-driver
   make
   # The console will be prompted to ask for the path of Intel SGX driver code
   sudo insmod gsgx.ko


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
