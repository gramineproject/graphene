# Debugging Graphene
## Running Graphene with GDB

To enable GDB support, the PAL loader and Graphene library OS has implemented the GDB protocol to notify any loading and unloading of dynamic libraries. The PAL loader will also load a GDB script to enable proper GDB features to make the debugging process easier. To start Graphene with GDB, use the following command to run your application:

    gdb --args <path to PAL>/pal [executable|manifest file] [arguments] ...

To build Graphene with debug symbols, the source code needs to be compiled with `make debug`. Run the following commands in the source tree:

    make clean
    make DEBUG=1

## Debugging Graphene Kernel

If you find any buggy behavior of Graphene kernel or fast memory bulk copy module, we suggest you to enable Graphene debug options in the kernel configuration. If the Graphene kernel is still failing without obvious reason, you may use any kernel debugging techniques, such as _printk_, _KDB_ or _KGDB_ to debug the kernel.