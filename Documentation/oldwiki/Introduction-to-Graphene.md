## What is Graphene library OS?

**Graphene library OS** is a project to provide lightweight guest OSes with support for Linux multi-process applications. Comparable to virtual machines, Graphene runs applications in an isolated environment, with virtualization benefits such as guest customization, platform independence and migration. The work is published in the proceeding of [Eurosys 2014](https://oscarlab.github.io/papers/tsai14graphene.pdf).

Graphene Library OS can support running Linux applications with the latest **Intel SGX (Software Guard Extension)** technologies. With Intel SGX, applications are secured in hardware-encrypted memory regions (so called **enclaves**), and no malicious software stack or hardware attack such as cold-boot attack can retrieve the application secret. Graphene Library OS can support native application to run in enclaves, without the porting efforts that developers usually have to pay. For more information about the SGX support, see [[Introduction to Graphene-SGX]].

### Which hosts is Graphene currently ported to?

Graphene Library OS can run Linux applications on top of any hosts that Graphene Library OS has been ported to. Porting Graphene Library OS to a new host requires implementing the [[PAL Host ABI]] using the host ABI. Currently, we have ported Graphene Library OS to **64-bit FreeBSD** and **64-bit Linux with Intel SGX**. More supported hosts are expected in the future. 

## What is the prerequisite of Graphene?

Graphene Library OS is tested to be compiling and running on Ubuntu 14.04/16.04 (both server and desktop version), along with Linux kernel 3.5/3.14/4.4. We recommend to build and install Graphene with the same host platform. Other distributions of 64-bit Linux can potentially, but the result is not guaranteed. If you find Graphene not working on other distributions, please contact us with a detailed bug report.

To install the prerequisites of Graphene on Ubuntu, run the following command:

    sudo apt-get install -y build-essential autoconf gawk bison

For building Graphene for SGX, run the following command in addition:

    sudo apt-get install -y python-protobuf

To run unit tests locally, you also need the python3-pytest package:

    sudo apt-get install -y python3-pytest

## How to build and run Graphene library OS?

Here is a [[Graphene Quick Start]] instruction for how to quickly build and run Graphene.

### Obtaining source code

Graphene can be obtained on _github_. Use the following command to check out the code:

`git clone https://github.com/oscarlab/graphene.git`

### Building Graphene

To build the system, simply run the following commands in the root of the source tree:

    git submodule update --init -- Pal/src/host/Linux-SGX/sgx-driver/
    make

Each part of Graphene can be built separately in the subdirectories.

To build Graphene library OS with debug symbols, run ``make DEBUG=1`` instead of ``make``. You may have to run ``make clean`` first if you have previously compiled the source code. To specify custom mirrors for downloading the GLIBC source, use ``GLIBC_MIRRORS=...`` when running ``make``.

To build with ``-Werror``, run ``make WERROR=1``.


Currently, Graphene has implemented [[these Linux system calls|Supported System Calls in Graphene]]. Before running any application, you must confirm if every system call required by the application executables and libraries is supported, or at least does not affect the functionality of the application if the system call is returned with error code **ENOSYS**.



### 2.1. Build with Kernel-Level Sandboxing (Optional)

This feature is marked as EXPERIMENTAL and no longer exists in the mainstream code. If you are interested, see the [EXPERIMENTAL/linux-reference-monitor](https://github.com/oscarlab/graphene/tree/EXPERIMENTAL/linux-reference-monitor) branch.



### 2.2 Build with Intel SGX Support

Here is a [[Graphene-SGX Quick Start]] instruction for how to quickly build and run Graphene with the Intel SGX support.


#### 2.1.1 Prerequisites

(1) Generating signing keys
A 3072-bit RSA private key (PEM format) is required for signing the enclaves.
If you don't have a private key, create it with the following command:

    openssl genrsa -3 -out enclave-key.pem 3072

You could either put the generated enclave key to the default path,
'host/Linux-SGX/signer/enclave-key.pem', or specify the key through environment
variable 'SGX_SIGNER_KEY' when building Graphene with SGX support.

After signing the enclaves, users may ship the application files with the
built Graphene Library OS, along with an SGX-specific manifest (.manifest.sgx
files) and the signatures, to the SGX-enabled hosts.

(2) Installing Intel SGX SDK and driver
The Intel SGX Linux SDK is required for running Graphene Library OS. Download and install
from the official Intel github repositories:

   - <https://github.com/01org/linux-sgx>
   - <https://github.com/01org/linux-sgx-driver>

A Linux driver must be installed before running Graphene Library OS in enclaves.
Simply run the following command to build the driver:

    cd Pal/src/host/Linux-SGX/sgx-driver
    make
    (The console will be prompted to ask for the path of Intel SGX driver code)
    sudo ./load.sh

#### 2.1.2 Building Graphene-SGX

To build Graphene Library OS with Intel SGX support, in the root directory of Graphene repo, run following command:

    make SGX=1

To build with debug symbols, run the command:

    make SGX=1 DEBUG=1

Using "make SGX=1" in the test or regression directory will automatically generate the enclave signatures (.sig files).

#### 2.1.3 Run Built-in Examples in Graphene-SGX

There are a few built-in examples under LibOS/shim/test/. The "native" folder includes a rich set of C programs and "apps" folder includes a few tested applications, such as GCC, Python, and Apache.

(1) Build and run a Hello World program with Graphene on SGX
- go to LibOS/shim/test/native, build the enclaves via command:

      make SGX=1

  The command will build enclaves for all the programs in the folder
- Generate the token from aesmd service, via command:

      make SGX_RUN=1

- Run Hello World program with Graphene on SGX:

      SGX=1 ./pal_loader helloworld   or  ./pal_loader SGX helloworld

(2) Build and run python helloworld script in Graphene on SGX
- go to LibOS/shim/test/apps/python, build the enclave:

      make SGX=1

- Generate token:

      make SGX_RUN=1

- Run python helloworld with Graphene-SGX via:

      SGX=1 ./python.manifest.sgx scripts/helloworld.py

#### 2.1.3 Including Application Test Cases

To add the application test cases, issue the following command from the root
of the source tree:

    git submodule update --init -- LibOS/shim/test/apps/


### Run an application in the Graphene Library OS

Graphene library OS uses PAL as a loader to bootstrap an application in the library OS. To start Graphene, PAL will have to be run as an executable, with the name of the program, and a "manifest file" given from the command line. Graphene provides three options for specifying the programs and manifest files:

    option 1: (automatic manifest)
    [PATH_TO_Runtime]/pal_loader [PROGRAM] [ARGUMENTS]...
    (Manifest file: "[PROGRAM].manifest" or "manifest")

    option 2: (given manifest)
    [PATH_TO_Runtime]/pal_loader [MANIFEST] [ARGUMENTS]...

    option 3: (manifest as a script)
    [PATH_TO_MANIFEST]/[MANIFEST] [ARGUMENTS]...
    (Manifest must have "#![PATH_TO_PAL]/libpal.so" as the first line)

Although manifest files are optional for Graphene, running an application usually requires some minimal configuration in its manifest file. A sensible manifest file will include paths to the library OS and GNU library C, environment variables such as `LD_LIBRARY_PATH`, file systems to be mounted, and isolation rules to be enforced in the reference monitor.

Here is an example of manifest files:

    loader.preload = file:LibOS/shim/src/libsysdb.so
    loader.env.LDL_LIBRAY_PATH = /lib

    fs.mount.libc.type = chroot
    fs.mount.libc.path = /lib
    fs.mount.libc.uri = file:LibOS/build

More examples can be found in the test directories (`LibOS/shim/test`). We have also tested several commercial applications such as GCC, Bash and Apache, and the manifest files that bootstrap them in Graphene are provided in the individual directories.

For the full documentation of the Graphene manifest syntax, please see this page: [[Graphene Manifest Syntax]] and [[Graphene-SGX Manifest Syntax]].

More details of running tested/benchmarked applications in Graphene, please see this page: [[Run Applications in Graphene]].

## How do I contribute to the project? 

Some documentation that might be helpful:

* [[PAL Host ABI]]
* [[Port Graphene PAL to Other hosts]]

## How to contact the maintainers?

For any questions or bug reports, please send an email to support@graphene-project.io
or post an issue on our GitHub repository: https://github.com/oscarlab/graphene/issues

