How to deploy Graphene-SGX in the Cloud?
========================================

Graphene without Intel SGX can be deployed on arbitrary Cloud VMs. Please see
our :doc:`quickstart` guide for the details.

To deploy Graphene-SGX, Intel SGX has to be enabled to be used within the Cloud
VM. Please see the installation and usage guide for each Cloud VM offering
individually below.

Azure Confidential Compute VMs
------------------------------

`Azure Confidential Compute services
<https://azure.microsoft.com/en-us/solutions/confidential-compute/>`__ are
generally available and provide access to VMs with Intel SGX enabled in `DCsv2
VM instances
<https://docs.microsoft.com/en-us/azure/virtual-machines/dcv2-series>`__. We
provide the description to install Graphene-SGX based on a VM using Ubuntu 18.04
and the preinstalled `Intel SGX DCAP driver
<https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/LD_1.22>`__
(version ``LD_1.22``). To use a different driver, please follow the instructions
to uninstall the driver.

Prerequisites
^^^^^^^^^^^^^

Update and install the required packages to install Graphene-SGX::

   sudo apt update
   sudo apt install -y build-essential autoconf gawk bison python3-protobuf libprotobuf-c-dev protobuf-c-compiler libcurl4 python3

Build and Test
^^^^^^^^^^^^^^

#. Clone Graphene::

      git clone https://github.com/oscarlab/graphene.git
      cd $GRAPHENE_DIR/
      git submodule update --init -- $GRAPHENE_DIR/Pal/src/host/Linux-SGX/sgx-driver/

#. Prepare the signing keys and Graphene-SGX kernel driver::

      openssl genrsa -3 -out enclave-key.pem 3072
      cp enclave-key.pem $GRAPHENE_DIR/Pal/src/host/Linux-SGX/signer
      cd $GRAPHENE_DIR/Pal/src/host/Linux-SGX/sgx-driver
      ISGX_DRIVER_PATH=/usr/src/linux-azure-headers-`uname -r`/arch/x86/ make
      sudo insmod gsgx.ko

#. Compile Graphene-SGX::

      ISGX_DRIVER_PATH=/usr/src/linux-azure-headers-`uname -r`/arch/x86/ make SGX=1

#. Set ``vm.mmap_min_addr=0`` in the System::

      sudo sysctl vm.mmap_min_addr=0

#. Build and Run :program:`helloworld`::

      cd $GRAPHENE_DIR/LibOS/shim/test/native
      make SGX=1 sgx-tokens
      SGX=1 ./pal_loader helloworld
