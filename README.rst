******************************************
Graphene Library OS with Intel SGX Support
******************************************

.. image:: https://readthedocs.org/projects/graphene/badge/?version=latest
   :target: http://graphene.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status

*A Linux-compatible Library OS for Multi-Process Applications*

.. This is not |nbsp|, because that is in rst_prolog in conf.py, which GitHub
   cannot parse. GitHub doesn't appear to use it correctly anyway...
.. |_| unicode:: 0xa0
   :trim:

What is Graphene?
=================

Graphene Library OS is a |_| project which provides lightweight guest OSes
with support for Linux multi-process applications. Graphene can run applications
in an isolated environment with virtualization benefits such as guest
customization, platform independence, and migration, which is comparable to
other virtual machines.

Graphene Library OS supports native, unmodified Linux applications on
any platform. Currently, Graphene Library OS is successfully ported to
Linux, FreeBSD and Intel SGX enclaves upon Linux platforms.

With the Intel SGX support, Graphene Library OS can secure a |_| critical
application in a |_| hardware encrypted memory region. Graphene Library OS can
protect applications against a |_| malicious system stack with minimal porting
effort.

Graphene Library OS is a |_| work published in Eurosys 2014. For more
information. see the paper: Tsai, et al, "Cooperation and Security Isolation
of Library OSes for Multi-Process Applications", Eurosys 2014.



How to build Graphene?
======================

Graphene Library OS is consist of five parts:

- Instrumented GNU C Library
- LibOS (a shared library named ``libsysdb.so``)
- PAL, a.k.a Platform Adaption Layer (a shared library named ``libpal.so``)

Graphene Library OS currently only works on x86_64 architecture.

Graphene Library OS is tested to be compiling and running on Ubuntu 14.04/16.04
(both server and desktop version), along with Linux kernel 3.5/3.14/4.4.
We recommend to build and install Graphene with the same host platform.
Other distributions of 64-bit Linux can potentially, but the result is not
guaranteed. If you find Graphene not working on other distributions, please
contact us with a detailed bug report.

Run the following command on Ubuntu to install dependencies for Graphene::

    sudo apt-get install -y build-essential autoconf gawk bison

For building Graphene for SGX, run the following command in addition::

    sudo apt-get install -y python-protobuf

To run unit tests locally, you also need the python3-pytest package::

    sudo apt-get install -y python3-pytest

To build the system, simply run the following commands in the root of the
source tree::

    git submodule update --init -- Pal/src/host/Linux-SGX/sgx-driver/
    make

Each part of Graphene can be built separately in the subdirectories.

To build Graphene library OS with debug symbols, run ``make DEBUG=1``
instead of ``make``. To specify custom mirrors for downloading the GLIBC
source, use ``make GLIBC_MIRRORS=...``.

To build with ``-Werror``, run ``make WERROR=1``.

Build with kernel-level sandboxing (optional)
---------------------------------------------

This feature is marked as EXPERIMENTAL and no longer exists in the mainstream code.

Build with Intel SGX Support
----------------------------

Prerequisites
^^^^^^^^^^^^^

1. Generating signing keys

   A 3072-bit RSA private key (PEM format) is required for signing the enclaves.
   If you don't have a private key, create it with the following command::

      openssl genrsa -3 -out enclave-key.pem 3072

   You could either put the generated enclave key to the default path,
   ``host/Linux-SGX/signer/enclave-key.pem``, or specify the key through
   environment variable ``SGX_SIGNER_KEY`` when building Graphene with SGX
   support.

   After signing the enclaves, users may ship the application files with the
   built Graphene Library OS, along with a SGX-specific manifest (.manifest.sgx
   files) and the signatures, to the SGX-enabled hosts.

2. Installing Intel SGX SDK and driver

   The Intel SGX Linux SDK is required for running Graphene Library OS. Download
   and install from the official Intel github repositories:

   - <https://github.com/01org/linux-sgx>
   - <https://github.com/01org/linux-sgx-driver>

   A Linux driver must be installed before running Graphene Library OS in
   enclaves. Simply run the following command to build the driver::

      cd Pal/src/host/Linux-SGX/sgx-driver
      make
      (The console will be prompted to ask for the path of Intel SGX driver code)
      sudo ./load.sh

Building Graphene-SGX
^^^^^^^^^^^^^^^^^^^^^

To build Graphene Library OS with Intel SGX support, in the root directory of
Graphene repo, run following command::

   make SGX=1

To build with debug symbols, run the command::

   make SGX=1 DEBUG=1

Using ``make SGX=1`` in the test or regression directory will automatically
generate the enclave signatures (.sig files).

Run Built-in Examples in Graphene-SGX
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are a few built-in examples under ``LibOS/shim/test/``. The "native"
folder includes a |_| rich set of C |_| programs and "apps" folder includes
a |_| few tested applications, such as GCC, Python, and Apache.

1. Build and run a |_| Hello World program with Graphene on SGX

   - go to LibOS/shim/test/native, build the enclaves via command::

      make SGX=1

     The command will build enclaves for all the programs in the folder

   - Generate the token from aesmd service, via command::

      make SGX_RUN=1

   - Run Hello World program with Graphene on SGX::

      SGX=1 ./pal_loader helloworld

     or::
     
      ./pal_loader SGX helloworld

2. Build and run python helloworld script in Graphene on SGX

   - go to LibOS/shim/test/apps/python, build the enclave::

      make SGX=1

   - Generate token::

      make SGX_RUN=1

   - Run python helloworld with Graphene-SGX via::

      SGX=1 ./python.manifest.sgx scripts/helloworld.py

Including Application Test Cases
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To add the application test cases, issue the following command from the root
of the source tree::

   git submodule update --init -- LibOS/shim/test/apps/

How to run an application in Graphene?
======================================

Graphene library OS uses PAL (``libpal.so``) as a loader to bootstrap an
application in the library OS. To start Graphene, PAL (``libpal.so``) will have
to be run as an executable, with the name of the program, and a |_| "manifest
file" given from the command line. Graphene provides three options for
specifying the programs and manifest files:

- option 1 (automatic manifest)::

   [PATH TO Runtime]/pal_loader [PROGRAM] [ARGUMENTS]...
   (Manifest file: "[PROGRAM].manifest" or "manifest")

- option 2 (given manifest)::

   [PATH TO Runtime]/pal_loader [MANIFEST] [ARGUMENTS]...

- option 3 (manifest as a script)::

   [PATH TO MANIFEST]/[MANIFEST] [ARGUMENTS]...
   (Manifest must have "#![PATH_TO_PAL]/libpal.so" as the first line)

Although manifest files are optional for Graphene, running an application
usually requires some minimal configuration in its manifest file. A |_| sensible
manifest file will include paths to the library OS and GNU library C,
environment variables such as LD_LIBRARY_PATH and file systems to
be mounted.

Here is an example of manifest files::

    loader.preload = file:LibOS/shim/src/libsysdb.so
    loader.env.LDL_LIBRAY_PATH = /lib
    fs.mount.glibc.type = chroot
    fs.mount.glibc.path = /lib
    fs.mount.glibc.uri = file:LibOS/build

More examples can be found in the test directories (``LibOS/shim/test``). We
have also tested several commercial applications such as GCC, Bash and Apache,
and the manifest files that bootstrap them in Graphene are provided in the
individual directories.

For more information and the detail of the manifest syntax, see the `Graphene
documentation <https://graphene.rtfd.io/>`_.

Contact
=======

For any questions or bug reports, please send an email to
<support@graphene-project.io> or post an issue on our GitHub repository:
<https://github.com/oscarlab/graphene/issues>.

Our mailing list is publicly archived `here
<https://groups.google.com/forum/#!forum/graphene-support>`_.
