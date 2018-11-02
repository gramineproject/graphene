
# Graphene Library OS with Intel:registered: SGX Support

![Travis Logo](https://travis-ci.org/oscarlab/graphene.svg?branch=master)


*A Linux-compatible Library OS for Multi-Process Applications*

## 1. WHAT IS GRAPHENE?

Graphene Library OS is a project which provides lightweight guest OSes with
support for Linux multi-process applications. Graphene can run applications
in an isolated environment with virtualization benefits such as guest 
customization, platform independence, and migration, which is comparable
to other virtual machines.

Graphene Library OS supports native, unmodified Linux applications on
any platform. Currently, Graphene Library OS is successfully ported to 
Linux, FreeBSD and Intel SGX enclaves upon Linux platforms.

With the Intel:registered: SGX support, Graphene Library OS can secure a critical
application in a hardware encrypted memory region. Graphene Library OS can
protect applications against a malicious system stack with minimal porting
effort.

Graphene Library OS is a work published in Eurosys 2014. For more
information. see the paper: Tsai, et al, "Cooperation and Security Isolation
of Library OSes for Multi-Process Applications", Eurosys 2014.



## 2. HOW TO BUILD GRAPHENE?

Graphene Library OS is consist of five parts:
  - Instrumented GNU Library C
  - LibOS (a shared library named "libsysdb.so")
  - PAL, a.k.a Platform Adaption Layer (a shared library named "libpal.so")
  - Reference monitor (a shared library named "libpal_sec.so")
  - Minor kernel customization and kernel modules

Graphene Library OS currently only works on x86_64 architecture.

Graphene Library OS is tested to be compiling and running on Ubuntu 14.04/16.04
(both server and desktop version), along with Linux kernel 3.5/3.14/4.4.
We recommand to build and install Graphene with the same host platform.
Other distributions of 64-bit Linux can potentially, but the result is not
guaranteed. If you find Graphene not working on other distributions, please
contact us with a detailed bug report.

The following packages are required for building Graphene: (can be installed
with 'apt-get install')
   - build-essential
   - autoconf
   - gawk
   - gcc 4 or 5

The following packages are also required for building Graphene for SGX (can
be installed with 'apt-get install'):
   - python-protobuf
   - python-crypto

To build the system, simply run the following commands in the root of the
source tree:

    git submodule update --init
    make

Each part of Graphene can be built separately in the subdirectories.

To build Graphene library OS with debug symbols, run "make DEBUG=1" instead of
"make". To specify custom mirrors for downloading the GLIBC source, use
"GLIBC_MIRRORS=..." when running "make".

### 2.1. BUILD WITH KERNEL-LEVEL SANDBOXING (OPTIONAL)

__** Note: this step is optional. **__

__** Note: for building with Intel:registered: SGX support, skip this step, go to section 2.2 **__

__** Disclaimer: this feature is experimental and may contain bugs. Please do
   no use in production system before further assessment.__

To enable sandboxing, a customized Linux kernel is needed. Note that
this feature is optional and completely unnecessary for running on SGX.
To build the Graphene Linux kernel, do the following steps:

    cd Pal/linux-3.19
    make menuconfig
    make
    make install
    (Add Graphene kernel as a boot option by commands like "update-grub")
    (reboot and choose the Graphene kernel)

Please note that the building process may pause before building the Linux
kernel, because it requires you to provide a sensible configuration file
(.config). The Graphene kernel requires the following options to be enabled
in the configuration:

  - CONFIG_GRAPHENE=y
  - CONFIG_GRAPHENE_BULK_IPC=y
  - CONFIG_GRAPHENE_ISOLATE=y

For more details about the building and installation, see the Graphene github
Wiki page: <https://github.com/oscarlab/graphene/wiki>.


### 2.2 BUILD WITH INTEL:registered: SGX SUPPORT

#### 2.1.1 Prerequisites 

(1) Generating signing keys
A 3072-bit RSA private key (PEM format) is required for signing the enclaves.
If you don't have a private key, create it with the following command:

    openssl genrsa -3 -out enclave-key.pem 3072

You could either put the generated enclave key to the default path,
'host/Linux-SGX/signer/enclave-key.pem', or specify the key through environment
variable 'SGX_ENCLAVE_KEY' when building Graphene with SGX support. 

After signing the enclaves, users may ship the application files with the
built Graphene Library OS, along with a SGX-specific manifest (.manifest.sgx
files) and the signatures, to the SGX-enabled hosts.

(2) Installing Intel SGX SDK and driver
The Intel SGX Linux SDK is required for running Graphene Library OS. Download and install
from the official Intel github repositories:

   - <https://github.com/01org/linux-sgx>
   - <https://github.com/01org/linux-sgx-driver>

A Linux driver must be installed before runing Graphene Library OS in enclaves.
Simply run the following command to build the driver:

__** Please make sure the GCC version is either 4 or 5 **__

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
       

## 3. HOW TO RUN AN APPLICATION IN GRAPHENE?

Graphene library OS uses PAL (libpal.so) as a loader to bootstrap an
application in the library OS. To start Graphene, PAL (libpal.so) will have
to be run as an executable, with the name of the program, and a "manifest
file" given from the command line. Graphene provides three options for
specifying the programs and manifest files:

   - option 1: (automatic manifest)
   
    [PATH TO Runtime]/pal_loader [PROGRAM] [ARGUMENTS]...
    (Manifest file: "[PROGRAM].manifest" or "manifest")

   - option 2: (given manifest)
   
    [PATH TO Runtime]/pal_loader [MANIFEST] [ARGUMENTS]...

   - option 3: (manifest as a script)
   
    [PATH TO MANIFEST]/[MANIFEST] [ARGUMENTS]...
    (Manifest must have "#![PATH_TO_PAL]/libpal.so" as the first line)

Using "libpal.so" as loader to start Graphene will not attach the applications
to the Graphene reference monitor. Tha applications will have better
performance, but no strong security isolation. To attach the applications to
the Graphene reference monitor, Graphene must be started with the PAL
reference monitor loader (libpal_sec.so). Graphene provides three options for
specifying the programs and manifest files to the loader:

   - option 4: (automatic manifest - with reference monitor)
   
    SEC=1 [PATH TO Runtime]/pal_loader [PROGRAM] [ARGUMENTS]...
    (Manifest file: "[PROGRAM].manifest" or "manifest")

   - option 5: (given manifest - with reference monitor)
   
    SEC=1 [PATH TO Pal/src]/pal_loader [MANIFEST] [ARGUMENTS]...

   - option 6: (manifest as a script - with reference monitor)
   
    SEC=1 [PATH TO MANIFEST]/[MANIFEST] [ARGUMENTS]...
    (Manifest must have "#![PATH TO Pal/src]/pal_sec" as the first line)

Although manifest files are optional for Graphene, running an application
usually requires some minimal configuration in its manifest file. A
sensible manifest file will include paths to the library OS and GNU
library C, environment variables such as LD_LIBRARY_PATH, file systems to
be mounted, and isolation rules to be enforced in the reference monitor.

Here is an example of manifest files:

    loader.preload = file:LibOS/shim/src/libsysdb.so
    loader.env.LDL_LIBRAY_PATH = /lib
    fs.mount.glibc.type = chroot
    fs.mount.glibc.path = /lib
    fs.mount.glibc.uri = file:LibOS/build

More examples can be found in the test directories (LibOS/shim/test). We have
also tested several commercial applications such as GCC, Bash and Apache,
and the manifest files that bootstrap them in Graphene are provided in the
individual directories.

For more information and the detail of the manifest syntax, see the Graphene
github Wiki page: <https://github.com/oscarlab/graphene/wiki>.



## 4. CONTACT

For any questions or bug reports, please send an email to
        <support@graphene-project.io>
or post an issue on our github repository:
        <https://github.com/oscarlab/graphene/issues>
