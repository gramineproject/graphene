# Home
## What is Graphene library OS?

**Graphene library OS** is a project to provide lightweight guest OSes with support for Linux multi-process applications. Comparable to virtual machines, Graphene runs applications in an isolated environment, with virtualization benefits such as guest customization, platform independence and migration. The work is published in the proceeding of [Eurosys 2014](https://oscarlab.github.io/papers/tsai14graphene.pdf).

Graphene Library OS can support running Linux applications with the latest **Intel SGX (Software Guard Extension)** technologies. With Intel SGX, applications are secured in hardware-encrypted memory regions (so called **enclaves**), and no malicious software stack or hardware attack such as cold-boot attack can retrieve the application secret. Graphene Library OS can support native application to run in enclaves, without the porting efforts that developers usually have to pay. For more information, see [[Introduction to Intel SGX Support]].

## What is the prerequisite of running my applications in Graphene?

Graphene is developed on top of 64-bit Linux, to run 64-bit Linux applications. We've tested it on 64-bit Ubuntu Linux up to 15.04 (both Server and Desktop versions). Other distributions of 64-bit Linux can potentially work, but the result is not guaranteed. If you have any problem building or running Graphene on top of other Linux hosts, please contact us. 

To compile Graphene library OS, the following packages are required:
* build-essential
* autoconf
* gawk
* python-protobuf (for SGX signing tool)
* python-crypto (for SGX signing tool)

Graphene has implemented about one third of Linux system calls, to support native, unmodified Linux applications. Before running any application, you must confirm if every system call required by the application executables and libraries is supported, or at least not affecting the functionality of the application if the system call is returned with error code **ENOSYS**. Here is a list of all [[Implemented System Calls]].

### What are the other hosts that Graphene can run on top of?

Graphene Library OS can run Linux applications on top of any hosts that Graphene Library OS has been ported to. Porting Graphene Library OS to a new host requires implementing the [[PAL Host ABI]] using the host ABI. Currently we have ported Graphene Library OS to **64-bit FreeBSD** and **64-bit Linux with Intel SGX**. More supported hosts are expected in the future. 

## How to build and run Graphene library OS?

Here is a [[Quick Start]] instruction for how to build and run Graphene with minimal commands.

### Obtaining source code

Graphene can be obtained on _github_. Use the following command to check out the code:

`git clone https://github.com/oscarlab/graphene.git`

### Building Graphene

Graphene Library OS is consist of five parts:
* Instrumented GNU Library C
* LibOS (a shared library named `libsysdb.so`)
* PAL, a.k.a Platform Adaption Layer (a shared library named `libpal.so`)
* Reference monitor (a shared library named `libpal_sec.so`)
* Minor kernel customization and kernel modules

Please note that Graphene requires building a customized Linux kernel on the host, apart from the library OS itself. It may require some basic knowledge and experience of building and installing Linux kernels.

To build the system, simply run the following commands in the root of the source tree:

__** Note: Please use GCC version 4 or 5 **__

    git submodule update --init
    make

For more detail please read this page: [[How to build Graphene Kernel|Building Linux Kernel Support]].

Each part of Graphene can be built separately in the subdirectories.

To build Graphene library OS with debug symbol, run "`make DEBUG=1`" instead of "`make`". For more information about debugging Graphene library OS, please read this page: [[How to debug Graphene|Debugging Graphene]]


#### Building with Kernel-Level Sandboxing (Optional)

__** Note: this step is optional. **__

__** Note: for building with Intel SGX support, skip this step. **__

__** Disclaimer: this feature is experimental and may contain bugs. Please do no use in production system before further assessment.__

To enable sandboxing, a customized Linux kernel is needed. Note that this feature is optional and completely unnecessary for running on SGX. To build the Graphene Linux kernel, do the following steps:

    cd Pal/linux-3.19
    make menuconfig
    make
    make install
    (Add Graphene kernel as a boot option by commands like "update-grub")
    (reboot and choose the Graphene kernel)

Please note that the building process may pause before building the Linux kernel, because it requires you to provide a sensible configuration file (.config). The Graphene kernel requires the following options to be enabled
in the configuration:

  - CONFIG_GRAPHENE=y
  - CONFIG_GRAPHENE_BULK_IPC=y
  - CONFIG_GRAPHENE_ISOLATE=y

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

Using "pal" as loader to start Graphene will not attach the applications
to the Graphene reference monitor. The applications will have better
performance, but no strong security isolation. To attach the applications to
the Graphene reference monitor, Graphene must be started with the PAL
reference monitor loader (pal_sec). Graphene provides three options for
specifying the programs and manifest files to the loader:

    option 4: (automatic manifest - with reference monitor)
    SEC=1 [PATH_TO_Runtime]/pal_loader [PROGRAM] [ARGUMENTS]...
    (Manifest file: "[PROGRAM].manifest" or "manifest")

    option 5: (given manifest - with reference monitor)
    SEC=1 [PATH_TO_Runtime]/pal_laoder [MANIFEST] [ARGUMENTS]...

    option 6: (manifest as a script - with reference monitor)
    SEC=1 [PATH_TO_MANIFEST]/[MANIFEST] [ARGUMENTS]...
    (Manifest must have "#![PATH_TO_PAL]/pal_sec" as the first line)

Although manifest files are optional for Graphene, running an application usually requires some minimal configuration in its manifest file. A sensible manifest file will include paths to the library OS and GNU library C, environment variables such as `LD_LIBRARY_PATH`, file systems to be mounted, and isolation rules to be enforced in the reference monitor.

Here is an example of manifest files:

    loader.preload = file:LibOS/shim/src/libsysdb.so
    loader.env.LDL_LIBRAY_PATH = /lib

    fs.mount.libc.type = chroot
    fs.mount.libc.path = /lib
    fs.mount.libc.uri = file:LibOS/build

More examples can be found in the test directories (`LibOS/shim/test`). We have also tested several commercial applications such as GCC, Bash and Apache, and the manifest files that bootstrap them in Graphene are provided in the individual directories.

For the full documentation of the Graphene manifest syntax, please see this page: [[Manifest Syntax]].

More details of running tested/benchmarked applications in Graphene, please see this page: [[Run Applications in Graphene]].

## How do I contribute to the project? 

Some documentations that might be helpful:

* [[PAL Host ABI]]
* [[Port Graphene PAL to Other hosts]]

## How to contact the maintainers?

For any questions or bug reports, please send an email to support@graphene-project.io
or post an issue on our github repository: https://github.com/oscarlab/graphene/issues

