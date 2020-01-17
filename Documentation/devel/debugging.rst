Debugging Graphene
==================

.. highlight:: sh

Running Graphene with GDB
-------------------------

To enable GDB support, the PAL loader and Graphene implement the GDB protocol to
notify the debugger about any loading and unloading of dynamic libraries. The
PAL loader also loads a |~| GDB script to enable GDB features to make the
debugging process easier.

To build Graphene with debug symbols, the source code needs to be compiled with
``DEBUG=1``. Run the following commands in the source tree::

    make clean
    make DEBUG=1

To run Graphene with GDB, use the following command to run your application::

    GDB=1 [Graphene Directory]/Runtime/pal_loader [executable|manifest] [arguments]

Running Graphene-SGX with GDB
-----------------------------

Graphene-SGX supports debugging of enclavized applications if the enclave is
created in debug mode. Graphene provides a specialized GDB for the application
and the library OS running inside an enclave (using a normal GDB will only debug
the execution *outside* the enclave).

To build Graphene-SGX with debug symbols, the source code needs to be compiled
with ``DEBUG=1``. Run the following commands in the source tree::

    make SGX=1 clean
    make SGX=1 DEBUG=1

After rebuilding Graphene-SGX with ``DEBUG=1``, you need to re-sign the manifest
of the application. For instance, if you want to debug the ``helloworld``
program, run the following commands::

    cd LibOS/shim/test/native
    make SGX=1
    make SGX=1 sgx-tokens

To run Graphene with GDB, use the Graphene loader (``pal_loader``) and specify
``GDB=1``::

    GDB=1 SGX=1 [Graphene Directory]/Runtime/pal_loader [executable|manifest] [arguments]
