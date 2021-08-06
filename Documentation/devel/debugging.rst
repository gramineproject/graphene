Debugging Graphene with GDB
===========================

.. highlight:: sh

Debugging without SGX support
-----------------------------

To enable GDB support, the PAL loader and Graphene implement the GDB protocol to
notify the debugger about any loading and unloading of dynamic libraries. The
PAL loader also loads a |~| GDB script to enable GDB features to make the
debugging process easier.

To build Graphene with debug symbols, the source code needs to be compiled with
``DEBUG=1``. Run the following commands in the source tree::

    make clean
    make DEBUG=1
    meson setup build/ --buildtype=debug -Ddirect=enabled
    ninja -C build/
    sudo ninja -C build/ install

GDB integration also requires pyelftools Python package::

    sudo apt-get install -y python3-pyelftools

To run Graphene with GDB, use the following command to run your application::

    GDB=1 graphene-direct [application] [arguments]

Debugging with SGX support
--------------------------

Graphene supports debugging of enclavized applications if the enclave is created
in debug mode. Graphene provides a specialized GDB for the application and the
library OS running inside an enclave (using a normal GDB will only debug the
execution *outside* the enclave).

To build Graphene with debug symbols, the source code needs to be compiled with
``DEBUG=1``. Run the following commands in the source tree::

    make SGX=1 clean
    make SGX=1 DEBUG=1
    meson setup build/ --buildtype=debug -Dsgx=enabled
    ninja -C build/
    sudo ninja -C build/ install

GDB integration also requires pyelftools Python package::

    sudo apt-get install -y python3-pyelftools

After rebuilding Graphene with ``DEBUG=1``, you need to re-sign the manifest of
the application. For instance, if you want to debug the ``helloworld`` program,
run the following commands::

    cd LibOS/shim/test/regression
    make SGX=1
    make SGX=1 sgx-tokens

To run Graphene with GDB, use the Graphene loader (``graphene-sgx``) and specify
``GDB=1``::

    GDB=1 graphene-sgx [application] [arguments]

Compiling with optimizations enabled
------------------------------------

Building Graphene with ``DEBUG=1`` enables debug symbols and GDB integration,
but disables optimizations. This is usually the right thing to do: optimized
builds are harder to debug, as they may cause GDB to display confusing
tracebacks or garbage data.

However, in some cases an optimized debug build might be desirable: for example,
``_FORTIFY_SOURCE`` runtime checks work only when optimizations are enabled, and
profiling optimized code will give you more accurate results.

To build Graphene with debug symbols, and with optimizations still enabled, run
``make DEBUGOPT=1``.
