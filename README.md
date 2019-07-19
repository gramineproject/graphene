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

First verify if your machine is SGX compatible:
  - Restart your machine, enter BIOS and set **Intel SGX** to **enabled**.

Run the following command on Ubuntu to download Graphene:

    git clone https://github.com/oscarlab/graphene

Graphene Library OS is consist of five parts:
  - Instrumented GNU Library C
  - LibOS (a shared library named "libsysdb.so")
  - PAL, a.k.a Platform Adaption Layer (a shared library named "libpal.so")
  - Reference monitor (a shared library named "libpal_sec.so")
  - Minor kernel customization and kernel modules

Graphene Library OS currently only works on x86_64 architecture.

Graphene Library OS is tested to be compiling and running on Ubuntu 14.04/16.04
(both server and desktop version), along with Linux kernel 3.5/3.14/4.4.
We recommend to build and install Graphene with the same host platform.
Other distributions of 64-bit Linux can potentially, but the result is not
guaranteed. If you find Graphene not working on other distributions, please
contact us with a detailed bug report.

Run the following command on Ubuntu to install dependencies for Graphene:

    sudo apt-get install -y build-essential autoconf gawk


For building Graphene for SGX, run the following command in addition:

    sudo apt-get install -y python-protobuf


To build the system, simply run the following commands in the root of the
source tree:

    git submodule update --init -- Pal/src/host/Linux-SGX/sgx-driver/
    make

Each part of Graphene can be built separately in the subdirectories.

To build Graphene library OS with debug symbols, run "make DEBUG=1" instead of
"make". To specify custom mirrors for downloading the GLIBC source, use
"GLIBC_MIRRORS=..." when running "make".

To build with "-Werror", run "make WERROR=1".

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
variable 'SGX_SIGNER_KEY' when building Graphene with SGX support.

After signing the enclaves, users may ship the application files with the
built Graphene Library OS, along with a SGX-specific manifest (.manifest.sgx
files) and the signatures, to the SGX-enabled hosts.

(2) Installing Intel SGX SDK and driver
The Intel SGX Linux SDK is required for running Graphene Library OS. Download and
install from the official Intel github repositories:

   - <https://github.com/01org/linux-sgx> (Latest)
   - <https://github.com/01org/linux-sgx-driver> (Download version 2.1
     or later & remember exact version for later)

A Linux driver must be installed before running Graphene Library OS in enclaves.
Simply run the following command to build the driver:

__** Please make sure the GCC version is either 4 or 5 **__

    cd Pal/src/host/Linux-SGX/sgx-driver
    make
    (The console will be prompted to ask for the path of Intel SGX driver code)
    sudo ./load.sh

Note: if you get an error concerning "Mod probe isgx.ko not found" or "could not
 insert module isgx.ko: Invalid module format" after running the above steps, you
 need to rebuild the SGX Drivers even if you have already built them,
 otherwise you will have an issue running aesmd service (a Linux daemon which 
 communicates with Launch Enclave and other SGX-related services).

If you continue to get errors regarding "isgx.ko" or "graphene-sgx.ko"
run the following commands respectively:

```bash
    <your-directory-with-linux-sgx-driver>$ sudo insmod isgx.ko
    graphene/Pal/src/host/Linux-SGX/sgx-driver$ sudo insmod graphene-sgx.ko
```

#### 2.1.2 Building Graphene-SGX

To build Graphene Library OS with Intel SGX support, in the root directory of
Graphene repo, run following command:

    make SGX=1

To build with debug symbols, run the command:

    make SGX=1 DEBUG=1

Using "make SGX=1" in the test or regression directory will automatically generate
the enclave signatures (.sig files).

#### 2.1.3 Including Application Test Cases

To add the application test cases (recommended), issue the following command
from the root of the source tree:

    git submodule update --init -- LibOS/shim/test/apps/

Please refer here for the full list and the official instructions for all apps:
<https://github.com/oscarlab/graphene/wiki/Run-Applications-with-SGX>

#### 2.1.3 Run Built-in Examples in Graphene-SGX

There are a few built-in examples under LibOS/shim/test/. The "native" folder includes a rich set of C programs and "apps" folder includes a few tested applications, such as GCC, Python,and Apache.

(1) Build and run a Hello World program with Graphene on SGX

- Go to LibOS/shim/test/native, build the enclaves via command:

      make SGX=1

  The command will build enclaves for all the programs in the folder
- Generate the token from aesmd service, via command:

      make SGX_RUN=1

- Run Hello World program with Graphene on SGX:

      SGX=1 ./pal_loader helloworld   or  ./pal_loader SGX helloworld

(2) Build and run python helloworld script in Graphene on SGX (part of the apps)

- go to LibOS/shim/test/apps/python, build the enclave:

      make SGX=1

- Generate token:

      make SGX_RUN=1

- Run python helloworld with Graphene-SGX via:

      SGX=1 ./python.manifest.sgx scripts/helloworld.py

(3) Running your own binary in Graphene (Not a production level setup)

    - Binaries and executables are significantly more time-consuming to setup inside
      Graphene. A general outline of the steps needed is as follows:

    1. cd into `LibOS/shim/test/apps/`
    2. create a new directory for your application
    3. create a Makefile in the directory following this template
    (this can vary wildly, look at other examples in LibOS/shim/test/apps):
        ```Makefile
        PYTHON_SRC = Python-2.7.9
        PYTHON_INSTALL = $(PYTHON_SRC)/build

        manifests = your_executable.manifest

        exec_target = $(manifests)

        extra_rules = -e 's:\$$(PYTHONDIR):$(PYTHON_INSTALL)/:g'
        clean-extra += clean-tmp

        level = ../../
        include ../../Makefile

        clean-tmp:
            rm -f your_executable.manifest.sgx *.sig *.token
        ```
    4. Inside of this file leave everything the same except for the `sgx.trusted_children`
     and `sgx.trusted_files`, adding whatever dependencies and files are necessary
     for your executable.
    5. Run `make && make SGX=1 && make SGX_RUN=1`
    6. then Run ` SGX=1 ./yourfile.manifest` to execute your code.

    NOTES:
     * It is important that the directories of any libraries you wish to use are
     added under `loader.env.LD_LIBRARY_PATH`.
          * Any files that are needed by the program should have their directories
          mounted by adding the following code to the manifest:
         ```
         fs.mount.DIRNAME.type = chroot
         fs.mount.DIRNAME.path = /PATH_ON_SYSTEM
         fs.mount.DIRNAME.uri = file:PATH_IN_GRAPHENE
         ```
     * If there are memory or thread errors, increase ```sgx.enclave_size``` or
     ```sgx.thread_num``` in the manifest.
     * You can add an entire directory to trusted/allowed files by typing
     `file:directory` with no slash at the end.
     * Trusted children will need to have their own signatures and tokens. This
     requires creating a manifest for those files as well, and they will also
     need to be added to the Makefile.
     * Arguments can be passed normally after the .manifest in terminal.

## 3. HOW TO DEBUG AND HANDLE ERRORS
If you add or remove any files, symbolic links, manifests, executable, etc. you must
first restart Graphene. (For example, if you added your own custom script to test
in LibOS/shim/test/apps/python you will need to restart Graphene).

 ### How to re-build Graphene
    1) cd into Graphene root
    2) run `make SGX=1 clean`
    3) run `make SGX=1 && make SGX_RUN=1`

 ### Issues You May Encounter in building Graphene
    1) aesmd service issues (not loaded/not running).
        - Most likely your issue lies with your setup of the SGX SDK/PSW. Make
        sure you are following all of the steps for setting up the SGX SDK
        correctly and retry.
    2) Issue when running the sample code in hardware mode.
        - Most likely you did not set SGX to enabled in your BIOS. If you cannot
        find this option, your BIOS likely doesn't support SGX
    3) Error in Intel SGX driver compatibility.
        - Make sure when you run `./load.sh` you input the correct driver version
        and you downloaded and installed the Intel SGX Driver (branch sgx2). Ensure
        your path is correct as well otherwise compatibility issues will occur. You
        may need to wipe your Graphene directory and restart if you entered the wrong
        version already.
    4) "Cannot find enclave-key.pem".
        - When you created the openssl key, it created the .pem file in the Graphene
        root directory. You need to put it in the signer folder:
        `graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem`
    5) "Cannot open device /dev/isgx".
        - cd and run this command: `/graphene/Pal/src/host/Linux-SGX/sgx-driver$ ./load.sh`
    6) "isgx.ko not found".
        - run this command: `graphene/Pal/src/host/Linux-SGX/sgx-driver/linux-sgx-driver$ sudo insmod isgx.ko`
    7) "isgx.ko not loaded".
        - This is an issue with SGX driver compatibility. You will need to delete
        your Graphene directory and re-install. Don't forget to specify 2.1 as
        the driver version

## 4. HOW TO RUN AN APPLICATION IN GRAPHENE

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
to the Graphene reference monitor. The applications will have better
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

## 5. CONTACT

For any questions or bug reports, please send an email to <support@graphene-project.io> or post an
issue on our GitHub repository: <https://github.com/oscarlab/graphene/issues>.

Our mailing list is publicly archived [here](https://groups.google.com/forum/#!forum/graphene-support).
