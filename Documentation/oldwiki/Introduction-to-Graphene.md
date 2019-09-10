## What is Graphene Library OS?

**Graphene library OS** is a lightweight guest OS which supports Linux multi-process applications.
Graphene runs applications in an isolated environment, with virtualization benefits, such as guest
customization, ease of porting to different OSes, and process migration, similar to a container or
a virtual machine. The work is originally published in the proceedings of
[Eurosys 2014](https://oscarlab.github.io/papers/tsai14graphene.pdf).

Graphene library OS supports running Linux applications with the latest **Intel SGX (Software
Guard Extension)**. With Intel SGX, applications are secured in hardware-encrypted memory
regions (so-called **enclaves**). SGX can protect code and data in the enclave against a malicious
software stack or attacks on the hardware off the CPU package. Graphene Library OS can support
native application to run in enclaves, without the porting efforts that developers usually have
to pay. For more information about SGX support, see [[Introduction to Graphene-SGX]].

### Which Hosts is Graphene Currently Ported To?

Graphene Library OS can run Linux applications on top of a host-specific layer which is easy to
port to different hosts. This host-specific layer is called a __Platform Adaption Layer (PAL)__.
Porting Graphene to a new host only requires porting a PAL, by implementing the [[PAL Host ABI]]
using OS features of the host. Currently, we have ported Graphene Library OS to **64-bit FreeBSD**
and **64-bit Linux with Intel SGX**. Support for more hosts is expected in the future.

#### Check out Application Test Cases

To get the application test cases, run the following command from the root of the source tree:

    git submodule update --init -- LibOS/shim/test/apps/

See [Run Applications in Graphene] for the instruction of running each application.


## Prerequisites

Graphene Library OS has been tested to build and install on Ubuntu 16.04, along with Linux
kernel 4.4+. We recommend to build and install Graphene with the same system. If you find
Graphene not working on other Linux distributions, please submit a bug report.

To install the prerequisites of Graphene on Ubuntu, run the following command:

    sudo apt-get install -y build-essential autoconf gawk bison

For building Graphene for SGX, run the following command in addition:

    sudo apt-get install -y python-protobuf

To run tests, you also need the python3-pytest package:

    sudo apt-get install -y python3-pytest

## Build and Run Graphene Library OS

See [[Graphene Quick Start]] for instructions how to quickly build and run Graphene.

### Obtain Source Code

Graphene can be obtained from _GitHub_. Use the following command to check out the code:

`git clone https://github.com/oscarlab/graphene.git`

### Build Graphene

To build Graphene library OS, simply run the following commands in the root of the source tree:

    git submodule update --init -- Pal/src/host/Linux-SGX/sgx-driver/
    make

Each part of Graphene can be built separately in the subdirectories.

To build Graphene library OS with debug symbols, run ``make DEBUG=1`` instead of ``make``. You may
have to run ``make clean`` first if you have previously compiled the source code. To specify custom
mirrors for downloading the GLIBC source, use ``GLIBC_MIRRORS=...`` when running ``make``.

To build with ``-Werror``, run ``make WERROR=1``.


Currently, Graphene has implemented [[these Linux system calls|Supported System Calls in Graphene]].
Before running any application, you must confirm if every system call required by the application
executables and libraries is supported, or at least does not affect the functionality of the
application if the system call always returns error code **ENOSYS**.



### Build with Kernel-Level Sandboxing (Optional)

This feature is marked as EXPERIMENTAL and no longer exists in the mainstream code.
See [EXPERIMENTAL/linux-reference-monitor](https://github.com/oscarlab/graphene/tree/EXPERIMENTAL/linux-reference-monitor).



### Build with Intel SGX Support

See [[Graphene-SGX Quick Start]] for instructions how to quickly build and run Graphene with
the Intel SGX support.


#### Prerequisites

(1) Generating signing keys

A 3072-bit RSA private key (PEM format) is required for signing the enclaves. If you don't have a
private key, create it with the following command:

    openssl genrsa -3 -out enclave-key.pem 3072

You can either put the generated enclave key in the default path,
`host/Linux-SGX/signer/enclave-key.pem`, or specify the key through the environment variable
`SGX_SIGNER_KEY`.

After signing the application, users may ship the application binaries, the manifest, and the
signature with the built Graphene Library OS, along with an SGX-specific manifest
(.manifest.sgx files) and the signatures, to SGX-enabled systems.

(2) Installing the Intel SGX SDK and driver

The Intel SGX Linux SDK is required for running Graphene Library OS. Download and install it
from the official Intel GitHub repositories:

   - <https://github.com/01org/linux-sgx>
   - <https://github.com/01org/linux-sgx-driver>

The Linux driver must be installed before running Graphene Library OS in enclaves. Simply run the
following commands to build the driver:

    cd Pal/src/host/Linux-SGX/sgx-driver
    make
    # You'll be prompted to provide the path to Intel SGX driver code and the version you chose.
    sudo ./load.sh

#### Build Graphene library OS for SGX

To build Graphene Library OS with Intel SGX support, in the root directory of Graphene repo, run
the following command:

    make SGX=1

To build with debug symbols, run the command:

    make SGX=1 DEBUG=1

Using `make SGX=1` in the test or regression directory will automatically generate the enclave
signatures (.sig files).

### Run Applications in Graphene

Graphene library OS uses a PAL as a loader to bootstrap applications in the library OS. To start
Graphene, the PAL runs as an executable, taking the name of the program, and a manifest file
(per-app configuration) as command line arguments. Please see [Graphene Manifest Syntax] for more
information regarding the manifest files.

We provide a loader script, `pal_loader`, for the convenience of giving run-time options to the
PAL loader. Via `pal_loader`, Graphene provides three options for specifying the program and the
manifest file:

    option 1: (automatic manifest)
    [PATH_TO_Runtime]/pal_loader [PROGRAM] [ARGUMENTS]...
    (Manifest file: "[PROGRAM].manifest" or "manifest")

    option 2: (given manifest)
    [PATH_TO_Runtime]/pal_loader [MANIFEST] [ARGUMENTS]...

    option 3: (manifest as a script)
    [PATH_TO_MANIFEST]/[MANIFEST] [ARGUMENTS]...
    (Manifest must have "#![PATH_TO_PAL]/libpal.so" as the first line)

Although manifest files are optional for Graphene, running an application usually requires some
minimal configuration in its manifest file. A sensible manifest file will include paths to the
library OS and GNU C library, environment variables such as `LD_LIBRARY_PATH`, file systems to be
mounted.

Here is an example manifest file:

    loader.preload = file:[relative path to Graphene root]/LibOS/shim/src/libsysdb.so
    loader.env.LD_LIBRAY_PATH = /lib

    fs.mount.libc.type = chroot
    fs.mount.libc.path = /lib
    fs.mount.libc.uri = file:[relative path to Graphene root]/Runtime

More examples can be found in the test directories (`LibOS/shim/test`). We have also tested several
application test cases such as GCC, Bash, and Apache. The manifest files for these applications are
provided in the individual directories in `LibOS/shim/test/apps`.

For the full documentation of the Graphene manifest syntax, please see the following pages:
[Graphene Manifest Syntax]] and [[Graphene-SGX Manifest Syntax]].

For more details about running tested/benchmarked applications in Graphene, please see this page:
[[Run Applications in Graphene]].

#### Run Built-in Examples in Graphene-SGX

(1) Build and run `helloworld` with Graphene on SGX

- Go to LibOS/shim/test/native, sign all the test programs via the command:

      make SGX=1

- Generate launch tokens from the aesmd service, via the command:

      make SGX_RUN=1

- Run `helloworld` with Graphene on SGX:

      SGX=1 ./pal_loader helloworld   or  ./pal_loader SGX helloworld

(2) Build and run the Python `helloworld.py` script with Graphene on SGX

- Go to LibOS/shim/test/apps/python and sign the application:

      make SGX=1

- Generate a launch token from the aesmd service, via the command:

      make SGX_RUN=1

- Run the `helloworld.py` with Graphene-SGX via:

      SGX=1 ./python.manifest.sgx scripts/helloworld.py


## How Do I Contribute to the Project?

Some documentation that might be helpful:

* [[PAL Host ABI]]
* [[Porting Graphene PAL to Other hosts]]

## How to Contact the Maintainers?

For any questions or bug reports, please send an email to support@graphene-project.io
or post an issue on our GitHub repository: https://github.com/oscarlab/graphene/issues

