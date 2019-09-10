.. _doc-dcap:

SGX DCAP Driver Support
=======================

DCAP driver can be found in https://github.com/intel/SGXDataCenterAttestationPrimitives/.

Before running `make` in ``$GRAPHENE_DIR/Pal/src/host/Linux-SGX/sgx-driver/``, ``sgx_user.h`` must be symlinked because this file does not exist.
For example, on Azure's Confidential Compute VM Deployment instance, DCAP driver is installed in ``/usr/src/sgx-1.10`` and thus the file can be symlinked as follows:

.. code-block:: bash

    cp -r /usr/src/sgx-1.10 ~/
    cd ~/sgx-1.10
    ln -s include/uapi/asm/sgx.h sgx_user.h

Also, input `~/sgx-1.10` when "Enter the Intel SGX driver directory" is prompted during `make` of ``$GRAPHENE_DIR/Pal/src/host/Linux-SGX/sgx-driver/``.
The internal script will automatically detect that the driver is DCAP.
