How to deploy Graphene in the cloud?
====================================

Graphene without Intel SGX can be deployed on arbitrary cloud VMs. Please see
our :doc:`quickstart` guide for the details.

To deploy Graphene with Intel SGX, the cloud VM has to support Intel SGX. Please
see the installation and usage guide for each cloud VM offering individually
below (currently only for Microsoft Azure).

Azure Confidential Computing VMs
--------------------------------

`Azure confidential computing services
<https://azure.microsoft.com/en-us/solutions/confidential-compute/>`__ are
generally available and provide access to VMs with Intel SGX enabled in `DCsv2
VM instances
<https://docs.microsoft.com/en-us/azure/virtual-machines/dcv2-series>`__. The
description below uses a VM running Ubuntu 18.04 with a the preinstalled `Intel
SGX DCAP driver
<https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/LD_1.22>`__
(version ``LD_1.22``). To use a different Intel SGX driver, please follow the
instructions to uninstall the driver.

Prerequisites
^^^^^^^^^^^^^

Update and install the required packages for Graphene:

      .. code-block:: sh

            sudo apt update
            sudo apt install -y build-essential autoconf gawk bison python3-protobuf \
                              libprotobuf-c-dev protobuf-c-compiler libcurl4 python3

Build and Test
^^^^^^^^^^^^^^

#. Clone Graphene:

      .. code-block:: sh

            git clone https://github.com/oscarlab/graphene.git
            cd graphene
            git submodule update --init -- Pal/src/host/Linux-SGX/sgx-driver/

#. Prepare the signing keys and Graphene kernel driver:

      .. code-block:: sh

            openssl genrsa -3 -out enclave-key.pem 3072
            cp enclave-key.pem Pal/src/host/Linux-SGX/signer
            cd Pal/src/host/Linux-SGX/sgx-driver
            ISGX_DRIVER_PATH=/usr/src/linux-azure-headers-`uname -r`/arch/x86/ make
            # WARNING: read "Security Implications" section before running this command
            sudo insmod gsgx.ko
            cd -

#. Build Graphene:

      .. code-block:: sh

            ISGX_DRIVER_PATH=/usr/src/linux-azure-headers-`uname -r`/arch/x86/ \
                  make SGX=1

#. Set ``vm.mmap_min_addr=0`` in the system:

      .. code-block:: sh

            # WARNING: read "Security Implications" section before running this command
            sudo sysctl vm.mmap_min_addr=0

#. Build and Run :program:`helloworld`:

      .. code-block:: sh

            cd LibOS/shim/test/native
            make SGX=1 sgx-tokens
            SGX=1 ./pal_loader helloworld


Security Implications
^^^^^^^^^^^^^^^^^^^^^

Note that this guide assumes that you deploy Graphene on an untrusted cloud VM.
The two steps in this guide significantly weaken the security of the cloud VM's
Linux kernel.

In particular, ``sudo insmod gsgx.ko`` introduces a local privilege escalation
vulnerability. This kernel module enables the FSGSBASE processor feature
without proper enabling in the host Linux kernel. Please refer to the
documentation under ``Pal/src/host/Linux-SGX/sgx-driver`` for more information.

Also, ``sudo sysctl vm.mmap_min_addr=0`` weakens the security of the Linux
kernel. This kernel tunable specifies the minimum virtual address that a
process is allowed to mmap. Setting it to zero makes it easier for attackers to
exploit "kernel NULL pointer dereference" defects.

Both these steps are temporary workarounds and will not be required in the
future. Be aware that the current guide must not be used to set up production
environments.
