## Running Graphene with GDB

To enable GDB support, the PAL loader and Graphene library OS have implemented the GDB protocol to
notify the debugger any loading and unloading of dynamic libraries. The PAL loader will also load
a GDB script to enable GDB features to make the debugging process easier.

To build Graphene with debug symbols, the source code needs to be compiled with `DEBUG=1`. Run the
following commands in the source tree:

    make clean
    make DEBUG=1

To run Graphene with GDB, use one of the following commands to run your application:

    GDB=1 [Graphene Directory]/Runtime/pal_loader [executable|manifest] [arguments]
    gdb --args  [executable|manifest] [arguments]



## Running Graphene-SGX with GDB

Graphene-SGX also supports GDB from outside the enclave if the enclave is created in debug mode.
Graphene provides a specialized GDB for the application and the library OS running inside an
enclave. Using a normal GDB will only debug the execution OUTSIDE the enclave.

To build Graphene-SGX with debug symbols, the source code needs to be compiled with `DEBUG=1`. Run
the following commands in the source tree:

    make SGX=1 clean
    make SGX=1 DEBUG=1

After rebuilding Graphene-SGX with `DEBUG=1`, you need to sign your application again.
For instance, if you are running the Hello World program, run the following commands:

    cd LibOS/shim/test/native
    make SGX=1
    make SGX_RUN=1

To run Graphene with GDB, use the Graphene loader (`pal_loader`):

    GDB=1 SGX=1 [Graphene Directory]/Runtime/pal_loader [executable|manifest] [arguments]
