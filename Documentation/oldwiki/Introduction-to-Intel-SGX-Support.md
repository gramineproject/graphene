# Introduction to Intel SGX Support
## What is Intel SGX?

SGX (Software Guard Extenstion) is a new feature of the latest Intel CPUs. According to <https://github.com/ayeks/SGX-hardware>, SGX is available in CPUs that are launched after October 1st, 2015.

Intel SGX is designed to protect critical applications against potentially malicious system stack, from the operating systems to hardware (CPU itself excluded). SGX creates a hardware encrypted memory region (so-called **enclaves**) from the protected applications, that neither compromised operating systems, nor hardware attack such as **cold-boot attack** can retrieve the application secrets.

## Why use Graphene Library OS for Intel SGX?

Porting applications to Intel SGX platform can be cumbersome. To secure an application with SGX, developers must recompile the application executable with the Intel SDK (Linux SDK: <https://github.com/01org/linux-sgx>). Moreover, the secured applications have _no_ access to any OS features, such as opening a file, creating a network connection, or cloning a thread. For any interaction with the host, developers must define untrusted interfaces that the secure applications can call to leave the enclaves.

Graphene Library OS provides the OS features needed by the applications, right inside the SGX enclaves. To secure any applications, developers can directly load native, unmodified binaries into enclaves, with minimal porting efforts. Graphene Library OS provides signing tool to sign all binaries that are loaded into the enclaves, just like the Intel SGX SDK.

## How to build with Intel SGX Support?

Here is a [[Quick Start | SGX Quick Start]] instruction for how to build and run Graphene with minimal commands.

### Prerequisite

To port applications into SGX enclaves with Graphene Library OS, the process is often split into two sides: the developers' side and the untrusted hosts' side (for testing purpose, both sides can be on the same host). The developers' side will build and sign Graphene library OS with the target applications. Users then ship the signed enclave images to the untrusted hosts and run in enclaves to secure the applications.

The support for SGX in Graphene library OS is currently developed on top of 64-bit Ubuntu Linux. To build with SGX support, first the prerequisite of Graphene is required (see here: [[Prerequisite of Graphene | Home#what-is-the-prerequisite-of-running-my-applications-in-graphene]]). The signer used on the developers' side requires Python 2.7+ and OpenSSL (optional).

### Developers' Side

To build Graphene Library OS with Intel SGX support, simply run `make SGX=1` instead of `make` at the root of the source tree (or in Pal directory if the rest of the source is already built). Like the regular Graphene, `DEBUG=1` can be used to build with debug symbols. After compiling the source, a PAL enclave binary (`libpal-enclave.so`) will be created, along with the untrusted loader (`pal-sgx`) to load the enclave.

Note that building Graphene Library OS and signing the applications does NOT require SGX-enabled CPUs or Intel SGX SDK on the developers' machines (except for testing purposes).

A 3072-bit RSA private key (PEM format) is required for signing the applications. The default enclave key is supposed to be placed in `Pal/src/host/Linux-SGX/signer/enclave-key.pem`, or can be specified through environment variable `SGX_ENCLAVE_KEY when building Graphene with Intel SGX support. If you don't have a private key, create it with the following command:

    openssl genrsa -3 -out enclave-key.pem 3072

To port an application into SGX enclave, developers must use the Graphene signing tool (`Pal/src/host/Linux-SGX/signer/pal-sgx-sign`) to generate valid enclave signatures (`SIGSTRUCT` as defined in the [Programming Reference](https://software.intel.com/sites/default/files/managed/48/88/329298-002.pdf)). The signing tool takes the built PAL enclave binary, application binaries, a manifest and all supporting binaries (including the library OS). It then generates the SGX-specific manifest (a `.manifest.sgx` file) and the enclave signature (a `.sig` file). 

After signing the application, users may ship the application files with the built Graphene Library OS, along with a SGX-specific manifest and the signatures, to the untrusted hosts that are enabled with Intel SGX. Please note that all supporting binaries must be shipped and placed at the same path as on the developers' host. For security reasons, Graphene library OS will not allow loading any binaries that are not signed.

For applications that are prepared in the Graphene library source, such as GCC, Apache and OpenJDK (more are listed in [[Run Applications in Graphene]]), just type 'make SGX=1' in the correspondent directories. The applications can be found in `LibOS/shim/test/apps`. The scripts are automated to build and sign the applications that are ready for shipment.

If you are simply testing the applications, you may build an run the applications on the same host (must be SGX-enabled). In real use cases, building and running the applications on the same host is mostly meaningless.

### Untrusted Hosts' Side

To run the applications in SGX enclave with Graphene library OS, the untrusted hosts must have SGX-enabled CPUs, with the Intel SGX SDK installed. Download and install the SDK from the official Intel github repositories: <https://github.com/01org/linux-sgx> and <https://github.com/01org/linux-sgx-driver>

A Graphene SGX driver also needs to be installed on the untrusted host. Simply run the following command to build the driver:

    cd Pal/src/host/Linux-SGX/sgx-driver
    make
    (The console will be prompted to ask for the path of Intel SGX driver code)
    sudo ./load.sh

If the Graphene SGX driver is successfully installed, and the Intel SDK aesmd service is up and running (see [here](https://github.com/01org/linux-sgx#start-or-stop-aesmd-service) for more information), we can acquire enclave token to launch Graphene library OS. Use the token tool `Pal/src/host/Linux-SGX/signer/pal-sgx-get-token` to connect with the aesmd service and retrieve the token.

For applications that are prepared in the Graphene library OS source, just type 'make SGX=1 sgx-tokens' in the correspondent directories. The scripts are automated to retrieve the tokens for the applications.

With the manifest (`.manifest.sgx`), the signature (`.sig`) and the token (`.token`) ready, we can now launch Graphene Library OS to run the application. Graphene provides three options for specifying the programs and manifest files:

    option 1: (automatic manifest)
    [PATH_TO_PAL]/pal [PROGRAM] [ARGUMENTS]...
    (Manifest file: "[PROGRAM].manifest.sgx")

    option 2: (given manifest)
    [PATH_TO_PAL]/pal [MANIFEST] [ARGUMENTS]...

    option 3: (manifest as a script)
    [PATH_TO_MANIFEST]/[MANIFEST] [ARGUMENTS]...
    (Manifest must have "#![PATH_TO_PAL]/pal" as the first line)