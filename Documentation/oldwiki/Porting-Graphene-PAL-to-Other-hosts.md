## Platform Compatibility of Graphene Library OS

Graphene Library OS has adapted the design of PAL (Platform Adaption Layer) from _Drawbridge Library OS_, which is a library OS designed for maximizing its platform compatibility. The argument made by _Drawbridge Library OS_ is that the library OS can be ported to a new host as long as PAL is implemented on the said host. The same property is also available in Graphene library OS.

## How to Port Graphene

As a result of platform compatibility, to port Graphene library OS to a new host platform, the only effort required will be reimplementing the PAL on the desired host platform. Most of the implementation should be just as simple as translating PAL API into the native system interface of the host. The implemented PAL must support [[PAL Host ABI]].

In fact, even in the PAL source code, we expect part of the code to be host-generic. To make porting Graphene easier, we deliberately separate the source code of PAL into three parts:

* `Pal/lib`: All the library APIs used internally by PAL.
* `Pal/src`: Host-generic implementation.
* `Pal/src/host/<host name>`: Host-specific implementation.

To start porting Graphene to a new host, we suggest you to start with a clone of `Pal/src/host/Skeleton`. This directory contains the skeleton of all functions that need to be implemented as part of a fully compatible PAL. However, although we have tried our best to isolate any host-specific code in each host directories, we do not guarantee that the necessary changes are only limited to those directories. It means that you may have to modify other part of the source code, especially Makefile scripts to complete your implementation. 

## Steps of Porting PAL
* Step 1: Fix compilation issue

For the first step to port PAL, you want to be able to build PAL as an executable on the target host. After cloning a host-specific directory, first modify `Makefile.am` to adjust compilation rules such as `CC`, `CFLAGS`, `LDFLAGS`, `AS` and `ASFLAGS`. You will also have to define the name of loader, and the reference monitor loader, if there is going to one, as target `pal` and `pal_sec` in `Makefile.am.`

* Step 2: Build a loader

PAL needs to run on the target host like a regular executable. To run Graphene Library OS, PAL must initialize the proper environments and load the applications as well as library OS in the form of Linux ELF binaries. To start the implemention of PAL loader, we suggest you begin with the following APIs in your host-specific directory:

1. `db_main.c`: this files need to contain the entry function of your loader (the 'main' function) and APIs to retrieve host-specific information. The definition of the APIs are as follows:

+ `_DkGetPagesize`(Required): Return the architecture page size of the target platform.
+ `_DkGetAllocationAlignment`(Required): Return the allocation alignment (granularity) of the target platform. Some platforms will have to different allocation alignment than page size.
+ `_DkGetAvailableUserAddressRange`(Required): PAL needs to provide a user address range which can be flexibly used by applications. None of these addresses should be used by PAL internally.
+ `_DkGetProcessId`(Required): Return an unique process ID for each process.
+ `_DkGetHostId`(Optional): Return an unique host ID for each host.
+ `_DkGetCPUInfo`(Optional): Retireve CPU information such as vendor ID, model name, etc.

The entry function in `db_main.c` must eventually call the generic entry point `pal_main`. The definition of `pal_main` is:

    /* Main initialization function */
    void pal_main (
        PAL_NUM    instance_id,      /* current instance id */
        PAL_HANDLE manifest_handle,  /* manifest handle if opened */
        PAL_HANDLE exec_handle,      /* executable handle if opened */
        PAL_PTR    exec_loaded_addr, /* executable addr if loaded */
        PAL_HANDLE parent_process,   /* parent process if it's a child */
        PAL_HANDLE first_thread,     /* first thread handle */
        PAL_STR *  arguments,        /* application arguments */
        PAL_STR *  environments      /* environment variables */
    );

2. `pal_host.h`: this file needs to define the member of `PAL_HANDLE` for handles of files, devices, pipes, sockets, threads, processes, etc.

3. `db_files.c`: To implement a basic loader, you have to specify how to open, read, and map an executable file. At least `file_open`, `file_read`, `file_map` , `file_attrquery`, `file_attrquerybyhdl` must be implemented to load a basic HelloWorld program.

4. `db_memory.c`: the same as `db_files.c`, this file also contain APIs essential to PAL loader. At least `_DkCheckMemoryMappable`, `_DkVirtualMemoryAlloc`, `_DkVirtualMemoryFree`, `_DkVirtualMemoryProtect` must be implemented.

5. `db_rtld.c`: This file must handle how symbols are resolved against PAL loader itself, to discover the entry address of host ABI. If the PAL loader is a Linux ELF binary, you may simply add a `link_map` to the `loaded_maps` list. Otherwise, you need to implement `resolve_rtld` function to return addresses of host ABI by names.

(Optional) You may implement `_DkDebugAddMap` and `_DkDebugDelMap` if you want to use host-specific debugger such as GDB to debug applications in Graphene.

* Step 3: Test a HelloWorld program without loading library OS

In `Pal/test`, we provide test program which can run without library OS, and directly use PAL Host ABI. If you can successfully run a HelloWorld program, Congratulations! You already have a working PAL loader.

* Step 4: Implementing the whole PAL Host ABI

Now it is time to complete the whole implementation of PAL Host ABI. Once you have finished implementation, use the **regression test** to confirm whether your implementation is compatible to PAL Host ABI. To run the regression test, do the following steps:

    Graphene % cd Pal/regression
    Graphene/Pal/regression % make regression


    Basic Bootstrapping:
    [Success] Basic Bootstrapping
    [Success] Control Block: Executable Name
    ...

* Step 5: Running Application with Graphene Library OS

With a completely implemented PAL, you should be able to run any applications that are currently running on Graphene library OS upon other platform. Please be aware you should not try to build any application binaries on your target host. On the contrary, you should build them on a Linux host and ship them to your target host.
We have packed most of Linux binaries in directories named `.packed` which can be found everywhere in the Graphene source code. Simplt type `make`, and these binaries will be unpacked if an non-Linux host is detected.
