## Platform Compatibility of Graphene

Graphene adopts a similar architecture to the Drawbridge Library OS, which runs a generic library
OS on top of a Platform Adaptation Layer (PAL) to maximize platform compatibility. In this
architecture, the library OS can be easily ported to a new host by implementing only the PAL
for this new host.

## How to Port Graphene

To port Graphene to a new host platform, the only effort required is reimplementing the PAL on the
desired host platform. Most of the implementation should be as simple as translating the PAL API
to the native system interface of the host. The implemented PAL must support [[PAL Host ABI]].

In fact, even in the PAL source code, we expect part of the code to be host-generic. To make porting
Graphene easier, we deliberately separate the source code of PAL into three parts:

* `Pal/lib`: All the library APIs used internally by PAL.
* `Pal/src`: Host-generic implementation.
* `Pal/src/host/<host name>`: Host-specific implementation.

To port Graphene to a new host, we suggest starting with a clone of `Pal/src/host/Skeleton`. This
directory contains the skeleton code of all functions that need to be implemented as part of a
fully compatible PAL. Although we have tried our best to isolate any host-specific code in each
host directory, we do not guarantee that the necessary changes are only limited to these
directories. That is, you may have to modify other parts of the source code (especially the Makefile
scripts) to complete your implementation.

## Steps of Porting PAL

* Step 1: Fix compilation issues

For the first step to port PAL, you want to be able to build PAL as an executable on the target
host. After cloning a host-specific directory, first modify `Makefile.am` to adjust compilation
rules such as `CC`, `CFLAGS`, `LDFLAGS`, `AS` and `ASFLAGS`. You will also have to define the name
of the loader as target `pal` in `Makefile.am.`

* Step 2: Build a loader

PAL needs to run on the target host like a regular executable. To run Graphene, PAL must initialize
the proper environments and load the applications as well as the library OS in the form of
Linux ELF binaries. To start the implemention of PAL loader, we suggest you begin with the following
APIs in your host-specific directory:

1. `db_main.c`: This file must contain the entry function of your loader (the 'main()' function)
and APIs to retrieve host-specific information. The definitions of the APIs are as follows:

+ `_DkGetPagesize`(required): Return the architecture page size of the target platform.
+ `_DkGetAllocationAlignment`(required): Return the allocation alignment (granularity) of the target
  platform. Some platforms have different allocation alignments rather than the usual page-size
  alignment.
+ `_DkGetAvailableUserAddressRange`(required): PAL must provide a user address range that
  applications can use. None of these addresses should be used by PAL internally.
+ `_DkGetProcessId`(required): Return a unique process ID for each process.
+ `_DkGetHostId`(optional): Return a unique host ID for each host.
+ `_DkGetCPUInfo`(optional): Retrieve CPU information, such as vendor ID, model name.

The entry function in `db_main.c` must eventually call the generic entry point `pal_main()`.
The definition of `pal_main()` is:

    /* Main initialization function */
    void pal_main(
        PAL_NUM    instance_id,      /* current instance id */
        PAL_HANDLE manifest_handle,  /* manifest handle if opened */
        PAL_HANDLE exec_handle,      /* executable handle if opened */
        PAL_PTR    exec_loaded_addr, /* executable addr if loaded */
        PAL_HANDLE parent_process,   /* parent process if it's a child */
        PAL_HANDLE first_thread,     /* first thread handle */
        PAL_STR*   arguments,        /* application arguments */
        PAL_STR*   environments      /* environment variables */
    );

2. `pal_host.h`: This file needs to define the member of `PAL_HANDLE` for handles of files, devices,
   pipes, sockets, threads, processes, etc.

3. `db_files.c`: To implement a basic loader, you have to specify how to open, read, and map an
   executable file. At least `file_open`, `file_read`, `file_map` , `file_attrquery`,
   `file_attrquerybyhdl` must be implemented to load a basic HelloWorld program.

4. `db_memory.c`: The same as `db_files.c`, this file also contain APIs essential to PAL loader. At
   least `_DkCheckMemoryMappable`, `_DkVirtualMemoryAlloc`, `_DkVirtualMemoryFree`,
   `_DkVirtualMemoryProtect` must be implemented.

5. `db_rtld.c`: This file must handle how symbols are resolved against the PAL loader itself, to
   discover the entry address of the host ABI. If the PAL loader is a Linux ELF binary, you may simply
   add a `link_map` to the `loaded_maps` list. Otherwise, you need to implement `resolve_rtld`
   function to return addresses of the host ABI by names.

You may implement the optional `_DkDebugAddMap` and `_DkDebugDelMap` to use a host-specific
debugger such as GDB to debug applications in Graphene.

* Step 3: Test a HelloWorld program without loading library OS

In `Pal/test`, we provide a test program that can run without the library OS and directly use the
PAL Host ABI. If you can successfully run a HelloWorld program, congratulations, you have a working
PAL loader.

* Step 4: Implementing the whole PAL Host ABI

Now it is time to complete the whole implementation of the PAL Host ABI. Once you have finished
implementation, use the regression tests to confirm whether your implementation is compatible with
the PAL Host ABI. To run the regression tests, run the following steps:

    cd Pal/regression
    make regression

* Step 5: Running Application with Library OS

With a completely implemented PAL, you should be able to run any applications that are currently
supported by Graphene on your new platform. Please be aware you should not try to build any
application binaries on your target host. On the contrary, you should build them on a Linux host
and ship them to your target host.
