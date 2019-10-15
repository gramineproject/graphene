## What is Graphene Library OS?

**Graphene library OS** is a lightweight guest OS that supports Linux multi-process applications.
Graphene runs applications in an isolated environment, with guest customization, ease of porting
to different OSes, and process migration (similar to a container or a virtual machine). The work
was originally published in the proceedings of
[Eurosys 2014](https://oscarlab.github.io/papers/tsai14graphene.pdf).

Graphene supports running Linux applications using the Intel SGX (Software Guard Extensions)
technology (we call this version **Graphene-SGX**). With Intel SGX, applications are secured in
hardware-encrypted memory regions (called SGX enclaves). SGX protects code and data in the
enclave against privileged software attacks and against physical attacks on the hardware off the
CPU package (e.g., cold-boot attacks on RAM). Graphene is able to run unmodified applications
inside SGX enclaves, without the toll of manually porting the application to the SGX environment.
For more information about SGX support, see [[Introduction to Graphene-SGX]].

### What Hosts Does Graphene Currently Run On?

Graphene was developed to encapsulate all host-specific code in one layer, called the Platform
Adaptation Layer, or PAL. Thus, if there is a PAL for a given host, the library OS and applications
will "just work".

Porting Graphene to a new host only requires porting a PAL, by implementing the [[PAL Host ABI]]
using OS features of the host. To date, we ported Graphene to FreeBSD and Linux (the latter also
with Intel SGX support). Support for more hosts is expected in the future.

#### Check out Application Test Cases

To get the application test cases, run the following command from the root of the source tree:

    git submodule update --init -- LibOS/shim/test/apps/

See [Run Applications in Graphene] for instructions of how to run each application.


## Prerequisites

Graphene has been tested to build and install on Ubuntu 16.04/18.04, along with the Linux
kernel 4.4+. We recommend to build and install Graphene with the same systems. If you find
Graphene not working on other Linux distributions, please submit a bug report.

To install the prerequisites of Graphene on Ubuntu, run the following command:

    sudo apt-get install -y build-essential autoconf gawk bison

To build Graphene for SGX, run the following command in addition:

    For Ubuntu 18.04:
    sudo apt-get install -y python3-protobuf

    For Ubuntu 16.04:
    sudo apt install -y python3-pip
    sudo /usr/bin/pip3 install protobuf

To run tests, you also need the python3-pytest package:

    sudo apt-get install -y python3-pytest

## Build and Run Graphene

See [[Graphene Quick Start]] for instructions how to quickly build and run Graphene.

### Obtain Source Code

The latest version of Graphene can be cloned from GitHub:

    git clone https://github.com/oscarlab/graphene.git

### Build Graphene

To build Graphene, simply run the following commands in the root of the source tree:

    git submodule update --init -- Pal/src/host/Linux-SGX/sgx-driver/
    make

Each part of Graphene can be built separately in the corresponding subdirectories.

To build Graphene with debug symbols, run `make DEBUG=1` instead of `make`. You may have to run
`make clean` first if you have previously compiled the source code. To specify custom mirrors for
downloading the Glibc sources, use `GLIBC_MIRRORS=...` when running `make`. To build with `-Werror`,
run `make WERROR=1`.

Currently, Graphene has implemented [[these Linux system calls|Supported System Calls in Graphene]].
Before running any application, you must confirm that all system calls required by the application
executables and libraries are supported (or that unsupported system calls do not affect the
functionality of the application).


### Build with Kernel-Level Sandboxing (Optional)

This feature is marked as EXPERIMENTAL and no longer exists in the master branch.
See [EXPERIMENTAL/linux-reference-monitor](https://github.com/oscarlab/graphene/tree/EXPERIMENTAL/linux-reference-monitor).


### Build with Intel SGX Support

See [[Graphene-SGX Quick Start]] for instructions on how to build and run Graphene with
Intel SGX support.


#### Prerequisites

(1) Generating signing keys

A 3072-bit RSA private key (PEM format) is required for signing the application manifest. If you
do not have a private key, create one with the following command:

    openssl genrsa -3 -out enclave-key.pem 3072

You can either put the generated key in the default path, `host/Linux-SGX/signer/enclave-key.pem`,
or specify the key through the environment variable `SGX_SIGNER_KEY`.

After signing the application manifest, users may ship the application binaries, the manifest, and
the signature together with the Graphene binaries to an SGX-enabled system.

(2) Installing Intel SGX SDK and SGX driver

The Intel SGX SDK and the SGX driver are required for running Graphene. Download and install them
from the official Intel GitHub repositories:

   - <https://github.com/01org/linux-sgx>
   - <https://github.com/01org/linux-sgx-driver>

To make Graphene aware of the SGX driver, run the following commands:

    cd Pal/src/host/Linux-SGX/sgx-driver
    make
    # the console will prompt you for the path of the Intel SGX driver code
    sudo ./load.sh

#### Build Graphene for SGX

To build Graphene with Intel SGX support, in the root directory of the Graphene repo, run
the following command:

    make SGX=1

To build with debug symbols, instead run the following command:

    make SGX=1 DEBUG=1

Using `make SGX=1` in the test or regression directory will automatically generate the required
manifest signatures (.sig files).

### Run Applications in Graphene

Graphene uses the PAL binary as a loader to bootstrap applications in the library OS. To start
Graphene, the PAL runs as an executable, taking the name of the program and/or the manifest file
as command-line arguments. Please see [Graphene Manifest Syntax] for more information regarding
the manifest files.

We provide a loader script, `pal_loader`, for the convenience of giving run-time options to the
PAL loader. Via `pal_loader`, Graphene provides three options for specifying the program and the
manifest file:

    Option 1: (automatic manifest)
    [PATH_TO_Runtime]/pal_loader [PROGRAM] [ARGUMENTS]...
    (Manifest file: "[PROGRAM].manifest" or "manifest")

    Option 2: (given manifest)
    [PATH_TO_Runtime]/pal_loader [MANIFEST] [ARGUMENTS]...

    Option 3: (manifest as a script)
    [PATH_TO_MANIFEST]/[MANIFEST] [ARGUMENTS]...
    (Manifest must have "#![PATH_TO_PAL]/libpal.so" as the first line)

Running an application requires some minimal configuration in the application's manifest file.
A sensible manifest file will include paths to the library OS and the Glibc library, environment
variables such as `LD_LIBRARY_PATH`, and file systems to be mounted.

Here is an example manifest file:

    loader.preload = file:[relative path to Graphene root]/LibOS/shim/src/libsysdb.so
    loader.env.LD_LIBRAY_PATH = /lib

    fs.mount.libc.type = chroot
    fs.mount.libc.path = /lib
    fs.mount.libc.uri = file:[relative path to Graphene root]/Runtime

More examples can be found in the test directories (`LibOS/shim/test`). We have also tested several
applications such as GCC, Bash, Redis, R, and Apache. The manifest files for these applications are
provided in the individual directories under `LibOS/shim/test/apps`.

For the full documentation of the Graphene manifest syntax, please see the following pages:
[Graphene Manifest Syntax]] and [[Graphene-SGX Manifest Syntax]].

For more details about running tested/benchmarked applications in Graphene, please see this page:
[[Run Applications in Graphene]].


#### Run Built-in Examples in Graphene-SGX

(1) Build and run `helloworld` with Graphene-SGX:

- Go to LibOS/shim/test/native, sign all the test programs:

      make SGX=1

- Generate launch tokens from the aesmd service:

      make SGX=1 sgx-tokens

- Run `helloworld` with Graphene-SGX:

      SGX=1 ./pal_loader helloworld  or  ./pal_loader SGX helloworld

(2) Build and run the Python `helloworld.py` script with Graphene-SGX:

- Go to LibOS/shim/test/apps/python and sign the application:

      make SGX=1

- Generate a launch token from the aesmd service:

      make SGX=1 sgx-tokens

- Run the `helloworld.py` script with Graphene-SGX:

      SGX=1 ./python.manifest.sgx scripts/helloworld.py


## How Do I Contribute to the Project?

Some documentation that might be helpful:

* [[PAL Host ABI]]
* [[Porting Graphene PAL to Other hosts]]

## How to Contact the Maintainers?

For any questions or bug reports, please send an email to support@graphene-project.io
or post an issue on our GitHub repository: https://github.com/oscarlab/graphene/issues.

