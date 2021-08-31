Building
========

.. highlight:: sh

.. todo::

   This page really belongs to :file:`devel/`, move it there after a |~| proper
   release. Instead, for all users, there should be documentation for installing
   without full compilation.

Graphene consists of several components:

- The Library OS itself (a shared library named ``libsysdb.so``, called the
  "shim" in our source code)
- The Platform Adaptation Layer, or PAL (a shared library named ``libpal.so``)
- A patched GNU C Library (a set of shared libraries ``libc.so``,
  ``libpthread.so``, ``libm.so``, etc.)

The build of Graphene implies building at least the first two components. The
build of the patched C library is optional but highly recommended for
performance reasons. The patched C library is built by default.

Graphene currently only works on the x86_64 architecture. Graphene is currently
tested on Ubuntu 18.04/20.04, along with Linux kernel version 5.x. We recommend
building and installing Graphene on Ubuntu with Linux kernel version 5.11 or
higher. If you find problems with Graphene on other Linux distributions, please
contact us with a |~| detailed `bug report
<https://github.com/oscarlab/graphene/issues/new>`__.

Installing dependencies
-----------------------

Common dependencies
^^^^^^^^^^^^^^^^^^^

Run the following command on Ubuntu to install dependencies::

    sudo apt-get install -y autoconf bison build-essential gawk meson \
        python3 python3-click python3-jinja2 wget

For GDB support and to run all tests locally you also need to install::

    sudo apt-get install -y libunwind8 python3-pyelftools python3-pytest

Dependencies for SGX
^^^^^^^^^^^^^^^^^^^^

The build of Graphene with SGX support requires the corresponding SGX software
infrastructure to be installed on the system. In particular, the FSGSBASE
functionality must be enabled in the Linux kernel, the Intel SGX driver must be
running, and Intel SGX SDK/PSW/DCAP must be installed.

.. note::

   We recommend to use Linux kernel version 5.11 or higher: starting from this
   version, Linux has the FSGSBASE functionality as well as the Intel SGX driver
   built-in. If you have Linux 5.11+, skip steps 2 and 3.

1. Required packages
""""""""""""""""""""
Run the following commands on Ubuntu to install SGX-related dependencies::

    sudo apt-get install -y libcurl4-openssl-dev libprotobuf-c-dev \
        protobuf-c-compiler python3-pip python3-protobuf
    python3 -m pip install toml>=0.10

2. Upgrade to the Linux kernel patched with FSGSBASE
""""""""""""""""""""""""""""""""""""""""""""""""""""

FSGSBASE is a feature in recent processors which allows direct access to the FS
and GS segment base addresses. For more information about FSGSBASE and its
benefits, see `this discussion <https://lwn.net/Articles/821719>`__. Note that
if your kernel version is 5.9 or higher, then the FSGSBASE feature is already
supported and you can skip this step.

If your current kernel version is lower than 5.9, then you have two options:

- Update the Linux kernel to at least 5.9 in your OS distro. If you use Ubuntu,
  you can follow e.g. `this tutorial
  <https://itsfoss.com/upgrade-linux-kernel-ubuntu/>`__.

- Use our provided patches to the Linux kernel version 5.4. See section
  :ref:`FSGSBASE` for the exact steps.

3. Install the Intel SGX driver
"""""""""""""""""""""""""""""""

This step depends on your hardware and kernel version. Note that if your kernel
version is 5.11 or higher, then the Intel SGX driver is already installed and
you can skip this step.

If you have an older CPU without :term:`FLC` support, you need to download and
install the the following Intel SGX driver:

- https://github.com/intel/linux-sgx-driver

Alternatively, if your CPU supports :term:`FLC`, you can choose to install the
DCAP version of the Intel SGX driver from:

- https://github.com/intel/SGXDataCenterAttestationPrimitives

4. Install Intel SGX SDK/PSW
""""""""""""""""""""""""""""

Follow the installation instructions from:

- https://github.com/intel/linux-sgx

5. Generate signing keys
""""""""""""""""""""""""

A 3072-bit RSA private key (PEM format) is required for signing the manifest.
If you don't have a private key, create it with the following command::

   openssl genrsa -3 -out enclave-key.pem 3072

You can either place the generated enclave key in the default path,
:file:`Pal/src/host/Linux-SGX/signer/enclave-key.pem`, or specify the key's
location through the environment variable ``SGX_SIGNER_KEY``.

After signing the application's manifest, users may ship the application and
Graphene binaries, along with an SGX-specific manifest (``.manifest.sgx``
extension), the SIGSTRUCT signature file (``.sig`` extension), and the
EINITTOKEN file (``.token`` extension) to execute on another SGX-enabled host.

Building
--------

.. note::

   We're in the middle of the migration from Make to Meson. In the meantime you
   need to run **both** buildchains, first :command:`make` then
   :command:`meson`.

To build Graphene, in the root directory of Graphene repo, run the following
commands::

   # if you build graphene-direct (note that "direct" means non-SGX version)
   make

   # if you build graphene-sgx
   make SGX=1 ISGX_DRIVER_PATH=<path-to-sgx-driver-sources>

The path to the SGX driver sources must point to the absolute path where the SGX
driver was downloaded or installed in the previous step. For example, for the
DCAP version 33 of the SGX driver, you must specify
``ISGX_DRIVER_PATH="/usr/src/sgx-1.33/"``. You can define
``ISGX_DRIVER_PATH=""`` to use the default in-kernel driver's C header.

Running :command:`make SGX=1 sgx-tokens` in the test or regression directory
will automatically generate the required SIGSTRUCT signatures (``.sig`` files)
and EINITTOKENs (``.token`` files).

Then install Graphene (recall that "direct" means non-SGX version)::

   meson setup build/ --buildtype=release -Ddirect=enabled -Dsgx=enabled
   ninja -C build/
   sudo ninja -C build/ install

Set ``-Ddirect=`` and ``-Dsgx=`` options to ``enabled`` or ``disabled``
according to whether you built the corresponding PAL (the snippet assumes you
built both).

.. note::

   When installing from sources, Graphene executables are placed under
   ``/usr/local/bin``. Some Linux distributions (notably CentOS) do not search
   for executables under this path. If your system reports that Graphene
   programs can not be found, you might need to edit your configuration files so
   that ``/usr/local/bin`` is in your path (in ``PATH`` environment variable).

Additional build options
^^^^^^^^^^^^^^^^^^^^^^^^

- To create a debug build, run :command:`make DEBUG=1` and :command:`meson
  --buildtype=debug`. This adds debug symbols in all Graphene components, builds
  them without optimizations, and enables detailed debug logs in Graphene.

  .. warning::
     Debug builds are not suitable for production.

- To create a debug build that does not disable optimizations, run
  :command:`make DEBUGOPT=1` and :command:`meson --buildtype=debugoptimized`.

  .. warning::
     Debug builds are not suitable for production.

  .. note::
     This is generally *not* recommended, because optimized builds lose some
     debugging information, and may cause GDB to display confusing tracebacks or
     garbage data. You should use ``DEBUGOPT=1`` only if you have a good reason
     (e.g. for profiling).

- To compile with undefined behavior sanitization (UBSan), run :command:`make
  UBSAN=1` and :command:`meson -Dubsan=enabled`. This causes Graphene to abort
  when undefined behavior is detected (and display information about source
  line). UBSan can be enabled for both debug and non-debug builds.

  .. warning::
     UBSan builds (even non-debug) are not suitable for production.

- To build with ``-Werror``, run :command:`make WERROR=1` and
  :command:`meson --werror`.

- To specify custom mirrors for downloading the Glibc source, use :command:`make
  GLIBC_MIRRORS=...`.

- To install into some other place than :file:`/usr/local`, use
  :command:`meson --prefix=<prefix>`. Note that you then need to include the
  :file:`<prefix>/bin` directory in ``$PATH`` and
  :file:`<prefix>/lib/python<version>/site-packages` in ``$PYTHONPATH``.


.. _FSGSBASE:

Advanced: installing Linux kernel with FSGSBASE patches
-------------------------------------------------------

FSGSBASE patchset was merged in Linux kernel version 5.9. For older kernels it
is available as `separate patches
<https://github.com/oscarlab/graphene-sgx-driver/tree/master/fsgsbase_patches>`__.

The following instructions to patch and compile a Linux kernel with FSGSBASE
support below are written around Ubuntu 18.04 LTS (Bionic Beaver) with a Linux
5.4 LTS stable kernel but can be adapted for other distros as necessary. These
instructions ensure that the resulting kernel has FSGSBASE support.

#. Clone the repository with patches::

       git clone https://github.com/oscarlab/graphene-sgx-driver

#. Setup a build environment for kernel development following `the instructions
   in the Ubuntu wiki <https://wiki.ubuntu.com/KernelTeam/GitKernelBuild>`__.
   Clone Linux version 5.4 via::

       git clone --single-branch --branch linux-5.4.y \
           https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
       cd linux

#. Apply the provided FSGSBASE patches to the kernel source tree::

       git am <graphene-sgx-driver>/fsgsbase_patches/*.patch

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
SDK/PSW, and Graphene itself.
