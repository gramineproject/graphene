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

Graphene is a lightweight guest OS, designed to run a single application with minimal host
requirements.
Graphene can run applications
in an isolated environment with benefits comparable to running a complete OS in a virtual machine---including guest
customization, platform independence, and migration.

Graphene supports native, unmodified Linux applications on
any platform. Currently, Graphene runs on
Linux, FreeBSD and Intel SGX enclaves on Linux platforms.

With Intel SGX support, Graphene Library OS can secure a |_| critical
application in a |_| hardware-encrypted memory region. Graphene can
protect applications from a |_| malicious system stack with minimal porting
effort.

Our `EuroSys 2014 <http://www.cs.unc.edu/~porter/pubs/tsai14graphene.pdf>` and `ATC 2017 <http://www.cs.unc.edu/~porter/pubs/graphene-sgx.pdf>` papers
describe the motivation, design choices, and measured performance of Graphene.


How to build Graphene?
======================

Graphene consists of three parts:

- An Instrumented GNU C Library
- The Library OS itself (a shared library named ``libsysdb.so``, called the "shim" in our source code)
- The Platform Adaption Layer, or PAL, (a shared library named ``libpal.so``)

Graphene Library OS currently only works on the x86_64 architecture.

Graphene Library OS is currently tested on Ubuntu 16.04
(both server and desktop version), along with Linux kernel versions 3.5/3.14/4.4.
We recommend building and installing Graphene on the same host platform.
Other distributions of 64-bit Linux potentially work, but the result is not
guaranteed. If you find problems with Graphene on other Linux distributions, please
contact us with a detailed bug report.

Run the following command on Ubuntu to install dependencies for Graphene::

    sudo apt-get install -y build-essential autoconf gawk bison

For building Graphene for SGX, run the following command in addition::

    sudo apt-get install -y python-protobuf libprotobuf-c-dev protobuf-c-compiler

To run unit tests locally, you also need the python3-pytest package::

    sudo apt-get install -y python3-pytest

To build the system, simply run the following commands in the root of the
source tree::

    git submodule update --init -- Pal/src/host/Linux-SGX/sgx-driver/
    make

Each part of Graphene can be built separately in the subdirectories.

To build Graphene with debug symbols, run ``make DEBUG=1``
instead of ``make``. To specify custom mirrors for downloading the GLIBC
source, use ``make GLIBC_MIRRORS=...``.

To build with ``-Werror``, run ``make WERROR=1``.

Building with kernel-level sandboxing (optional)
------------------------------------------------

This feature is marked as EXPERIMENTAL and no longer exists in the mainstream code.

Building with Intel SGX Support
-------------------------------

Prerequisites
^^^^^^^^^^^^^

1. Generate signing keys

   A 3072-bit RSA private key (PEM format) is required for signing the enclaves.
   If you don't have a private key, create it with the following command::

      openssl genrsa -3 -out enclave-key.pem 3072

   You can either place the generated enclave key in the default path,
   ``host/Linux-SGX/signer/enclave-key.pem``, or specify the key's location through
   the environment variable ``SGX_SIGNER_KEY``.

   After signing the application, users may ship the application and Graphene binaries,
   along with a signed SGX-specific manifest (.manifest.sgx extension), to execute on
   another SGX-enabled host.

2. Install the Intel SGX SDK and driver

   The Intel SGX Linux SDK is required to compile and run Graphene on SGX. Download
   and install from the official Intel github repositories:

   - <https://github.com/01org/linux-sgx>
   - <https://github.com/01org/linux-sgx-driver>

3. Build and install the Graphene SGX driver
   A Graphene-specific Linux driver must also be installed before running Graphene Library OS in
   enclaves. Simply run the following command to build the driver::

      cd Pal/src/host/Linux-SGX/sgx-driver
      make
      (The console will be prompted to ask for the path of Intel SGX driver code)
      sudo ./load.sh

Building Graphene-SGX
^^^^^^^^^^^^^^^^^^^^^

To build Graphene Library OS with Intel SGX support, in the root directory of
Graphene repo, run following commands::

   make SGX=1
   make SGX_RUN=1

To build with debug symbols, run the command::

   make SGX=1 DEBUG=1
   make SGX_RUN=1 DEBUG=1

Running ``make SGX=1`` in the test or regression directory will automatically
generate the enclave signatures (.sig files).

Run Built-in Examples in Graphene-SGX
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are a few built-in examples under ``LibOS/shim/test/``. The "native"
folder includes a |_| rich set of C |_| programs and "apps" folder includes
a |_| few tested applications, such as GCC, Python, and Apache.

1. Build and run a |_| Hello World program with Graphene on SGX

   - go to LibOS/shim/test/native, build the enclaves via the command::

      make SGX=1

     This command will build enclaves for all the programs in the folder

   - Generate the token from aesmd service, via the command::

      make SGX_RUN=1

   - Run Hello World program with Graphene on SGX::

      SGX=1 ./pal_loader helloworld

     or::

      ./pal_loader SGX helloworld

2. Build and run a python helloworld script in Graphene on SGX

   - go to LibOS/shim/test/apps/python, and build the enclave::

      make SGX=1

   - Generate the token::

      make SGX_RUN=1

   - Run python helloworld with Graphene-SGX via::

      SGX=1 ./python.manifest.sgx scripts/helloworld.py

Including Application Test Cases
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To add the application test cases, issue the following command from the root
of the source tree::

   git submodule update --init -- LibOS/shim/test/apps/

Testing the remote attestation feature
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To enable tests for the built-in remote attestation feature for Graphene-SGX, obtain a SPID
and a subscription key (can be linkable or unlinkable) from the Intel API Portal:
https://api.portal.trustedservices.intel.com/EPID-attestation

Specify the SPID, subscription key, and the type of the SPID/key in the manifest::

    sgx.ra_client_spid = <SPID>
    sgx.ra_client_key = <KEY>
    sgx.ra_client_linkable = 1 # or 0 if the SPID/key is unlinkable (default)

If the remote attestation feature is enabled, Graphene-SGX will terminate if the platform
is not successfully verified by the Intel Attestation Service (IAS). The feature ensures that
Graphene-SGX only executes on genuine, up-to-date SGX hardware.


To enable remote attestation tests in ``Pal/regression``, specify the following variables::

    cd PAL/regression
    make SGX=1 RA_CLIENT_SPID=<SPID> RA_CLIENT_KEY=<KEY>
    make SGX_RUN=1


If you receive a "GROUP_OUT_OF_DATE" status from IAS, this status indicates that your CPU
is out of date and can be vulnerable to hardware attacks. If you wish to bypass this error,
you can specify the following option in the manifest::

    sgx.ra_accept_group_out_of_date = 1

SECURITY ADVISORIES:

"GROUP_OUT_OF_DATE" may indicate that the firmware (microcode) of you CPU is not updated
according to INTEL-SA-00233 (Load/store data sampling) and INTEL-SA-00161 (L1 terminal fault).
It is recommended that you keep the BIOS of your platform up-to-date.

If you receive status "CONFIGURATION_NEEDED" from the IAS after updating your BIOS, you may
need to disable hyperthreading in your BIOS to mitigate L1 terminal fault.

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
manifest file will include paths to the library OS and other libraries the application requires;
environment variables, such as LD_LIBRARY_PATH; and file systems to
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
