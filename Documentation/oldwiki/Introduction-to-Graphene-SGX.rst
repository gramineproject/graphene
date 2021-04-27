:orphan:

Introduction to Graphene SGX
============================

.. highlight:: text

What is Intel SGX?
------------------

SGX (Software Guard Extenstions) is a security feature of the latest Intel CPUs. According to
https://github.com/ayeks/SGX-hardware, SGX is available in Intel CPUs that were launched after
October 1st, 2015.

Intel SGX is designed to protect critical applications against a potentially malicious system stack,
from the operating systems to hardware (CPU itself excluded). SGX creates a hardware-encrypted
memory region (called SGX enclaves) for the protected application, such that neither privileged
software attacks nor hardware attacks such as cold-boot attacks can modify or retrieve the
application data from the enclave memory.

Why use Graphene for Intel SGX?
-------------------------------

Porting applications to an Intel SGX platform can be cumbersome. To secure an application with SGX,
developers must recompile the application executable with the Intel SGX SDK
(https://github.com/intel/linux-sgx). Moreover, an in-enclave application has *no* access to
OS features, such as opening a file, creating a network connection, or cloning a thread. For any
interaction with the host, developers must define untrusted interfaces that the application must
use to exit the enclave, perform the OS system call, and re-enter the enclave.

Graphene provides the OS features to in-enclave applications, by implementing them inside the SGX
enclaves. To secure their applications, developers can directly load native, unmodified binaries
into enclaves, with no/minimal porting efforts. Graphene provides a signing tool to sign all
binaries that are loaded into the enclave (technically, the application manifest, which contains
hashes and URIs of these binaries, is signed), similar to the Intel SGX SDK workflow.

How to Build Graphene with Intel SGX Support?
---------------------------------------------

Refer to the :doc:`../quickstart` page on how to build and run Graphene-SGX.

Prerequisites
^^^^^^^^^^^^^
Porting and running an application on Intel SGX with Graphene-SGX involves two parties: the
developer and the untrusted host (for testing purposes, the same host may represent both parties).
The developer builds and signs the bundle of Graphene plus the target application(s). Developers/
users then ship the signed bundle to the untrusted host and run it inside the SGX enclave(s) to
secure their workloads.

The prerequisites to build Graphene are detailed in
[Prerequisites of Graphene](Introduction-to-Graphene.html#prerequisites).

Prerequisites for Developer
^^^^^^^^^^^^^^^^^^^^^^^^^^^
To build Graphene with Intel SGX support, simply run `make SGX=1` instead of `make` at
the root of the source tree (or in the PAL directory if the rest of the source is already built).
Like regular Graphene, `DEBUG=1` can be used to build with debug symbols. After compiling the
source, a PAL enclave binary (`libpal-enclave.so`) is created, along with the untrusted loader
(`pal-sgx`) to load the enclave.

Note that building Graphene and signing the application manifests do *not* require an SGX-enabled
CPU on the developer's machine (except for testing purposes).

A 3072-bit RSA private key (PEM format) is required for signing the application manifests. The
default key is placed under `Pal/src/host/Linux-SGX/signer/enclave-key.pem`, or can be specified
through the environment variable `SGX_SIGNER_KEY` when building Graphene with Intel SGX
support. If you don't have a private key, create one with the following command:

    openssl genrsa -3 -out enclave-key.pem 3072

To port an application to SGX, one must use the signing tool (`Pal/src/host/Linux-SGX/signer/pal-sgx-sign`)
to generate a valid enclave signature (`SIGSTRUCT` as defined in the
[Programming Reference](https://software.intel.com/sites/default/files/managed/48/88/329298-002.pdf)).
The signing tool takes the PAL enclave binary, application binaries, a manifest and all
supporting binaries (including the library OS). It then generates the SGX-specific manifest
(a `.manifest.sgx` file) and the enclave signature (a `.sig` file).

After signing the manifest, users may ship the application files together with Graphene itself,
along with an SGX-specific manifest and the signatures, to the untrusted host that has Intel SGX.
Please note that all supporting binaries must be shipped and placed at the same paths as on the
developer's machine. For security reasons, Graphene will not allow loading any binaries that are
not signed/hashed.

For applications that are prepared in the Graphene Examples directory, such as GCC, Apache, and Bash
(more are listed in [Run Applications in Graphene](Run-Applications-in-Graphene.md)), just type 'make SGX=1' in the corresponding
directory. The scripts are automated to build the applications and sign their manifests in order
to ship them to the untrusted host.

If you are simply testing the applications, you may build and run the applications on the same host
(which must be SGX-enabled). In production scenarios, building and running the applications on the
same host is mostly meaningless.

Prerequisites for Untrusted Host
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
To run the applications on Intel SGX with Graphene-SGX, the host must have an SGX-enabled CPU, with
Intel SGX SDK and the SGX driver installed. Please download and install the SDK and the driver from:
https://github.com/intel/linux-sgx and https://github.com/intel/linux-sgx-driver. If you want
to use the DCAP SDK and driver, please download and install from:
https://github.com/intel/SGXDataCenterAttestationPrimitives.

A Graphene SGX driver (gsgx) also needs to be installed on the untrusted host. Simply run the
following commands to build the driver::

    cd Pal/src/host/Linux-SGX/sgx-driver
    make
    # the console will prompt you for the path of the Intel SGX driver code
    sudo insmod gsgx.ko

If the Graphene SGX driver is successfully installed, and the Intel SDK aesmd service is up and
running (see [here](https://github.com/intel/linux-sgx#start-or-stop-aesmd-service) for more
information), one can acquire an enclave token to launch Graphene with the application. Use the
token tool `Pal/src/host/Linux-SGX/signer/pal-sgx-get-token` to connect to the aesmd service
and retrieve the token.

For applications that are prepared in the Graphene Examples directory (GCC, Apache, Bash, etc.),
type `make SGX=1 sgx-tokens` in the corresponding directory. The scripts are automated to retrieve
the tokens for the applications.

With the manifest (`.manifest.sgx`), the signature (`.sig`), and the token (`.token`) ready, one
can launch Graphene-SGX to run the application. Graphene-SGX provides three options for specifying
the programs and manifest files::

    Option 1: (automatic manifest)
    SGX=1 [PATH_TO_PAL]/pal [PROGRAM] [ARGUMENTS]...
    (Manifest file: "[PROGRAM].manifest.sgx")

    Option 2: (given manifest)
    SGX=1 [PATH_TO_PAL]/pal [MANIFEST] [ARGUMENTS]...

    Option 3: (manifest as a script)
    SGX=1 [PATH_TO_MANIFEST]/[MANIFEST] [ARGUMENTS]...
    (Manifest must have "#![PATH_TO_PAL]/pal" as the first line)

