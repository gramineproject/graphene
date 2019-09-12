## What is Graphene's PAL Host ABI

PAL Host ABI is the interface used by Graphene to interact with its host. It is translated into
the host's native ABI (e.g. system calls for UNIX) by a layer called the Platform Adaptation Layer
(PAL). A PAL not only exports a set of APIs (PAL APIs) that can be called by the library OS, but
also acts as the loader that bootstraps the library OS. The design of PAL Host ABI strictly follows
three primary principles, to guarantee functionality, security, and portability:

* The host ABI must be stateless.
* The host ABI must be a narrowed interface to reduce the attack surface.
* The host ABI must be generic and independent from the native ABI of any of the supported hosts.

Most of the PAL Host ABI is adapted from the Drawbridge library OS.

## PAL as Loader

Regardless of the actual implementation, we require PAL to be able to load ELF-format binaries
as executables or dynamic libraries, and perform the necessary dynamic relocation. PAL needs
to look up all unresolved symbols in loaded binaries and resolve the ones matching the names of
PAL APIs. PAL does not and will not resolve other unresolved symbols, so the loaded libraries and
executables must resolve them afterwards.

After loading the binaries, PAL needs to load and interpret the manifest files. The manifest syntax
is described in [[Graphene Manifest Syntax]].

### Manifest and Executable Loading Rules

The PAL loader supports multiple ways of locating the manifest and executable. To run a program
in Graphene properly, the PAL loader generally requires both a manifest and an executable,
although it is possible to load with only one of them. The user shall specify either the manifest
or the executable to load in the command line, and the PAL loader will try to locate the other
based on the file name or content.

Precisely, the loading rules for the manifest and executable are as follows:

1. The first argument given to the PAL loader (e.g., `pal-Linux`, `pal-Linux-SGX`, `pal-FreeBSD`,
or the cross-platform wrapper, `pal-loader`) can be either a manifest file or an executable.
2. If an executable is given to the command line, the loader will search for the manifest in the
following order: the same file name as the executable with a `.manifest` or `.manifest.sgx` extension,
a `manifest` file without any extension, or no manifest at all.
3. If a manifest is given to the command line, and the manifest contains a `loader.exec` rule,
then the rule is used to determine the executable. The loader should exit if the executable file
doesn't exist.
4. If a manifest is given to the command line, and the manifest does *not* contain a `loader.exec rule`,
then the manifest *may* be used to infer the executable. The potential executable file has the same
file name as the manifest file except it doesn't have the `.manifest` or `.manifest.sgx` extension.
5. If a manifest is given to the command line, and no executable file can be found either based on
any `loader.exec` rule or inferring from the manifest file, then no executable is used for the
execution.


## Data Types and Variables

### Data Types

#### PAL handles

The PAL handles are identifiers that are returned by PAL when opening or creating resources. The
basic data structure of a PAL handle is defined as follows:

    typedef union pal_handle {
        struct {
            PAL_IDX type;
            PAL_REF ref;
            PAL_FLG flags;
        } __in;
        /* other resource-specific definitions */
    } PAL_HANDLE;

As shown above, a PAL handle is usually defined as a `union` data type that contains different
subtypes that represent each resource such as files, directories, pipes or sockets. The actual
memory allocated for the PAL handles may be variable-sized.

#### Numbers and Flags

`PAL_NUM` and `PAL_FLG` types represent integers and flags. On x86-64, they are defined as follows:

    typedef uint64_t      PAL_NUM;
    typedef uint32_t      PAL_FLG;

#### Pointers, Buffers and Strings

`PAL_PTR` and `PAL_STR` types represent pointers that point to memory, buffers, and strings.
On x86-64, they are defined as follows:

    typedef const char*   PAL_STR;
    typedef void*         PAL_PTR;

#### Boolean Values

`PAL_BOL` type represents boolean values (either `PAL_TRUE` or `PAL_FALSE`). This data type is
commonly used as the return value of a PAL API to determine whether the call succeeded. On x86-64,
it is defined as follows:

    typedef bool          PAL_BOL;

### Graphene Control Block

The control block in Graphene is a structure that provides static information about the current
process and its host. It is also a dynamic symbol that will be linked by the library OS and resolved
at runtime. Sometimes, for the flexibility or the convenience of the dynamic resolution, the
address of the control block may be resolved by a function (`pal_control_addr()`).

The fields of the Graphene control block are defined as follows:

    typedef struct {
        /* An identifier of current picoprocess */
        PAL_NUM process_id;
        PAL_NUM host_id;

        /***** Handles and executables *****/
        /* program manifest */
        PAL_HANDLE manifest_handle;
        /* executable name */
        PAL_STR executable;
        /* handle of parent process */
        PAL_HANDLE parent_process;
        /* handle of first thread */
        PAL_HANDLE first_thread;
        /* debug stream */
        PAL_HANDLE debug_stream;
        /* broadcast RPC stream */
        PAL_HANDLE broadcast_stream;

        /***** Memory layout ******/
        /* The range of user address */
        PAL_PTR_RANGE user_address;
        /* address where executable is loaded */
        PAL_PTR_RANGE executable_range;
        /* manifest preloaded here */
        PAL_PTR_RANGE manifest_preload;

        /***** Host information *****/
        /* host page size / allocation alignment */
        PAL_NUM pagesize, alloc_align;
        /* CPU information */
        PAL_CPU_INFO cpu_info;
        /* Memory information */
        PAL_MEM_INFO mem_info;
    } PAL_CONTROL;

## PAL APIs

The PAL APIs contain 44 functions that can be called from the library OS.

### Memory Allocation

#### DkVirtualMemoryAlloc

    PAL_PTR DkVirtualMemoryAlloc(PAL_PTR addr, PAL_NUM size, PAL_FLG alloc_type, PAL_FLG prot);

This API allocates virtual memory for the library OS. `addr` can be either `NULL` or any valid
address aligned at the allocation alignment. When `addr` is non-NULL, the API will try
to allocate the memory at the given address and potentially rewrite any memory previously allocated
at the same address. Overwriting any part of PAL and host kernel is forbidden. `size` must be a
positive number, aligned at the allocation alignment.

`alloc_type` can be a combination of any of the following flags:

    /* Memory Allocation Flags */
    #define PAL_ALLOC_32BIT       0x0001   /* Only give out 32-bit addresses */
    #define PAL_ALLOC_RESERVE     0x0002   /* Only reserve the memory */

`prot` can be a combination of the following flags:

    /* Memory Protection Flags */
    #define PAL_PROT_NONE       0x0     /* 0x0 Page can not be accessed. */
    #define PAL_PROT_READ       0x1     /* 0x1 Page can be read. */
    #define PAL_PROT_WRITE      0x2     /* 0x2 Page can be written. */
    #define PAL_PROT_EXEC       0x4     /* 0x4 Page can be executed. */
    #define PAL_PROT_WRITECOPY  0x8     /* 0x8 Copy on write */

#### DkVirtualMemoryFree

    void DkVirtualMemoryFree(PAL_PTR addr, PAL_NUM size);

This API deallocates a previously allocated memory mapping. Both `addr` and `size` must be non-zero
and aligned at the allocation alignment.

#### DkVirtualMemoryProtect

    PAL_BOL DkVirtualMemoryProtect(PAL_PTR addr, PAL_NUM size, PAL_FLG prot);

This API modifies the permissions of a previously allocated memory mapping. Both `addr` and
`size` must be non-zero and aligned at the allocation alignment. `prot` is defined as
[[DkVirtualMemoryAlloc|PAL Host ABI#DkVirtualMemoryAlloc]].

### Process Creation

#### DkProcessCreate

    PAL_HANDLE DkProcessCreate(PAL_STR uri, PAL_FLG flags, PAL_STR* args);

This API creates a new process to run a separate executable. `uri` is the URI of the manifest file
or the executable to be loaded in the new process. `flags` is currently unused. `args` is an array
of strings -- the arguments to be passed to the new process.

#### DkProcessExit

    void DkProcessExit(PAL_NUM exitCode);

This API terminates all threads in the process immediately. `exitCode` is the exit value returned
to the host.

### Stream Creation/Connection/Open

#### DkStreamOpen

    PAL_HANDLE DkStreamOpen(PAL_STR uri, PAL_FLG access, PAL_FLG share_flags, PAL_FLG create,
                            PAL_FLG options);

This API opens/creates a stream resource specified by `uri`. If the resource is successfully opened
or created, a PAL handle will be returned for further access such as reading or writing. `uri` is
the URI of the stream to be opened/created. The following is a list of URIs that are supported:

* `file:...`, `dir:...`: Files or directories on the host file system. If `PAL_CREAT_TRY` is given
   in `create` flags, the file/directory will be created.
* `dev:...`: Open a device as a stream. For example, `dev:tty` represents the standard I/O.
* `pipe.srv:<ID>`, `pipe:<ID>`, `pipe:`: Open a byte stream that can be used for RPC between
   processes. Pipes are located by numeric IDs. The server side of a pipe can accept any number
   of connections. If `pipe:` is given as the URI, it will open an anonymous bidirectional pipe.
* `tcp.srv:<ADDR>:<PORT>`, `tcp:<ADDR>:<PORT>`: Open a TCP socket to listen or connect to
   a remote TCP socket.
* `udp.srv:<ADDR>:<PORT>`, `udp:<ADDR>:<PORT>`: Open a UDP socket to listen or connect to
   a remote UDP socket.

`access` can be a combination of the following flags:

    /* Stream Access Flags */
    #define PAL_ACCESS_RDONLY   00
    #define PAL_ACCESS_WRONLY   01
    #define PAL_ACCESS_RDWR     02

`share_flags` can be a combination of the following flags:

    /* Stream Sharing Flags */
    #define PAL_SHARE_GLOBAL_X    01
    #define PAL_SHARE_GLOBAL_W    02
    #define PAL_SHARE_GLOBAL_R    04
    #define PAL_SHARE_GROUP_X    010
    #define PAL_SHARE_GROUP_W    020
    #define PAL_SHARE_GROUP_R    040
    #define PAL_SHARE_OWNER_X   0100
    #define PAL_SHARE_OWNER_W   0200
    #define PAL_SHARE_OWNER_R   0400

`create` can be a combination of the following flags:

    /* Stream Create Flags */
    #define PAL_CREAT_TRY        0100       /* 0100 Create file if file not
                                               exist (O_CREAT) */
    #define PAL_CREAT_ALWAYS     0200       /* 0300 Create file and fail if file
                                               already exist (O_CREAT|O_EXCL) */

`options` can be a combination of the following flags:

    /* Stream Option Flags */
    #define PAL_OPTION_NONBLOCK     04000

#### DkStreamWaitForClient

    PAL_HANDLE DkStreamWaitForClient(PAL_HANDLE handle);

This API is only available for handles that are opened with `pipe.srv:...`, `tcp.srv:...`, and
`udp.srv:...`. It blocks until a new connection is accepted and returns the PAL handle for the
connection.

#### DkStreamRead

    PAL_NUM DkStreamRead(PAL_HANDLE handle, PAL_NUM offset, PAL_NUM count, PAL_PTR buffer,
                         PAL_PTR source, PAL_NUM size);

This API reads data from an opened stream. If the handle is a file, `offset` must be specified
at each call of DkStreamRead. `source` and `size` can be used to return the remote socket
address if the handle is a UDP socket. If the handle is a directory, DkStreamRead fills the buffer
with the names (NULL-ended) of the files or subdirectories inside of this directory.

#### DkStreamWrite

    PAL_NUM DkStreamWrite(PAL_HANDLE handle, PAL_NUM offset, PAL_NUM count,
                          PAL_PTR buffer, PAL_STR dest);

This API writes data to an opened stream. If the handle is a file, `offset` must be specified
at each call of DkStreamWrite. `dest` can be used to specify the remote socket address if the
handle is a UDP socket.

#### DkStreamDelete

    #define PAL_DELETE_RD       01
    #define PAL_DELETE_WR       02
    void DkStreamDelete(PAL_HANDLE handle, PAL_FLG access);

This API deletes files or directories on the host or shuts down the connection of TCP/UDP sockets.
`access` specifies the method of shutting down the connection and can be either read-side only,
write-side only, or both if 0 is given.

#### DkStreamMap

    PAL_PTR DkStreamMap(PAL_HANDLE handle, PAL_PTR address, PAL_FLG prot,
                        PAL_NUM offset, PAL_NUM size);

This API maps a file to a virtual memory address in the current process. `address` can be NULL or
a valid address that is aligned at the allocation alignment. `offset` and `size` have to be non-zero
and aligned at the allocation alignment. `prot` is defined as
[[DkVirtualMemoryAlloc|PAL Host ABI#DkVirtualMemoryAlloc]].

#### DkStreamUnmap

    void DkStreamUnmap(PAL_PTR addr, PAL_NUM size);

This API unmaps virtual memory that is backed by a file stream. `addr` and `size` must be aligned
at the allocation alignment.

#### DkStreamSetLength

    PAL_NUM DkStreamSetLength(PAL_HANDLE handle, PAL_NUM length);

This API truncates or extends a file stream to the given length.

#### DkStreamFlush

    PAL_BOL DkStreamFlush(PAL_HANDLE handle);

This API flushes the buffer of a file stream.

#### DkSendHandle

    PAL_BOL DkSendHandle(PAL_HANDLE handle, PAL_HANDLE cargo);

This API sends a PAL handle `cargo` over another handle. Currently, the handle that is used
to send cargo must be a process handle, thus handles can only be sent between parent and child
processes.

#### DkReceiveHandle

    PAL_HANDLE DkReceiveHandle(PAL_HANDLE handle);

This API receives a handle over another handle.

#### DkStreamAttributeQuery

    PAL_BOL DkStreamAttributesQuery(PAL_STR uri, PAL_STREAM_ATTR* attr);

This API queries the attributes of a named stream. This API only applies for URIs such as
`file:...`, `dir:...`, and `dev:...`.

The data type `PAL_STREAM_ATTR` is defined as follows:

    /* stream attribute structure */
    typedef struct {
        PAL_IDX type;
        PAL_NUM file_id;
        PAL_NUM size;
        PAL_NUM access_time;
        PAL_NUM change_time;
        PAL_NUM create_time;
        PAL_BOL disconnected;
        PAL_BOL readable;
        PAL_BOL writeable;
        PAL_BOL runnable;
        PAL_FLG share_flags;
        PAL_BOL nonblocking;
        PAL_BOL reuseaddr;
        PAL_NUM linger;
        PAL_NUM receivebuf;
        PAL_NUM sendbuf;
        PAL_NUM receivetimeout;
        PAL_NUM sendtimeout;
        PAL_BOL tcp_cork;
        PAL_BOL tcp_keepalive;
        PAL_BOL tcp_nodelay;
    } PAL_STREAM_ATTR;

#### DkStreamAttributesQuerybyHandle

    PAL_BOL DkStreamAttributesQuerybyHandle(PAL_HANDLE handle, PAL_STREAM_ATTR* attr);

This API queries the attributes of an opened stream. This API applies to any stream handle.

#### DkStreamAttributesSetbyHandle

    PAL_BOL DkStreamAttributesSetbyHandle(PAL_HANDLE handle, PAL_STREAM_ATTR* attr);

This API sets the attributes of an opened stream.

#### DkStreamGetName

    PAL_NUM DkStreamGetName(PAL_HANDLE handle, PAL_PTR buffer, PAL_NUM size);

This API queries the name of an opened stream.

#### DkStreamChangeName

    PAL_BOL DkStreamChangeName(PAL_HANDLE handle, PAL_STR uri);

This API changes the name of an opened stream.

### Thread Creation

#### DkThreadCreate

    PAL_HANDLE DkThreadCreate(PAL_PTR addr, PAL_PTR param, PAL_FLG flags);

This API creates a thread in the current process. `addr` is the address of an entry point of
execution for the new thread. `param` is the parameter that is passed to the new thread as the
only argument. `flags` is currently unused.

#### DkThreadPrivate

    PAL_PTR DkThreadPrivate(PAL_PTR addr);

This API retrieves or sets the Thread-Local Storage (TLS) address of the current thread.

#### DkThreadDelayExecution

    PAL_NUM DkThreadDelayExecution(PAL_NUM duration);

This API suspends the current thread for a certain duration (in microseconds).

#### DkThreadYieldExecution

    void DkThreadYieldExecution(void);

This API yields the current thread such that the host scheduler can reschedule it.

#### DkThreadExit

    void DkThreadExit(void);

This API terminates the current thread.

#### DkThreadResume

    PAL_BOL DkThreadResume(PAL_HANDLE thread);

This API resumes a thread. 

### Exception Handling

#### DkSetExceptionHandler

    PAL_BOL DkSetExceptionHandler(void (*handler) (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT* context),
                                  PAL_NUM event, PAL_FLG flags);

This API sets the handler for the specific exception event.

`event` can be one of the following values:

    /* Exception Handling */
    /* Div-by-zero */
    #define PAL_EVENT_DIVZERO       1
    /* segmentation fault, protection fault, bus fault */
    #define PAL_EVENT_MEMFAULT      2
    /* illegal instructions */
    #define PAL_EVENT_ILLEGAL       3
    /* terminated by external program */
    #define PAL_EVENT_QUIT          4
    /* suspended by external program */
    #define PAL_EVENT_SUSPEND       5
    /* continued by external program */
    #define PAL_EVENT_RESUME        6
    /* failure within PAL calls */
    #define PAL_EVENT_FAILURE       7

`flags` can be a combination of the following flags:

    #define PAL_EVENT_PRIVATE      0x0001       /* upcall specific to thread */
    #define PAL_EVENT_RESET        0x0002       /* reset the event upcall */

#### DkExceptionReturn

    void DkExceptionReturn(PAL_PTR event);

This API exits an exception handler and restores the context.

### Synchronization

#### DkMutexCreate

    PAL_HANDLE DkMutexCreate(PAL_NUM initialCount);

This API creates a mutex with the given `initialCount`.

#### DkMutexUnlock

    void DkMutexUnlock(PAL_HANDLE mutexHandle);

This API unlocks the given mutex.

##### DkNotificationEventCreate/DkSynchronizationEventCreate

    PAL_HANDLE DkNotificationEventCreate(PAL_BOL initialState);
    PAL_HANDLE DkSynchronizationEventCreate(PAL_BOL initialState);

This API creates an event with the given `initialState`. The definition of notification events
and synchronization events is the same as the WIN32 API. When a notification event is set to the
Signaled state it remains in that state until it is explicitly cleared. When a synchronization
event is set to the Signaled state, a single thread of execution that was waiting for the event is
released, and the event is automatically reset to the Not-signaled state.

#### DkEventSet

    void DkEventSet(PAL_HANDLE eventHandle);

This API sets (signals) a notification event or a synchronization event.

#### DkEventClear

    void DkEventClear(PAL_HANDLE eventHandle);

This API clears a notification event or a synchronization event.

### Objects

#### DkObjectsWaitAny

    #define NO_TIMEOUT ((PAL_NUM) -1)
    PAL_HANDLE DkObjectsWaitAny(PAL_NUM count, PAL_HANDLE* handleArray, PAL_NUM timeout);

This API polls an array of handles and returns one handle with recent activity. `timeout` is the
maximum time that the API should wait (in microseconds), or `NO_TIMEOUT` to indicate it is to be
blocked until at least one handle is ready.

#### DkObjectClose

    void DkObjectClose(PAL_HANDLE objectHandle);

This API closes (deallocates) a PAL handle.

### Miscellaneous

#### DkSystemTimeQuery

    PAL_NUM DkSystemTimeQuery(void);

This API returns the current time (in microseconds).

#### DkRandomBitsRead

    PAL_NUM DkRandomBitsRead(PAL_PTR buffer, PAL_NUM size);

This API fills the buffer with cryptographically-secure random values.

### Memory Bulk Copy (Optional)

#### DkCreatePhysicalMemoryChannel

    PAL_HANDLE DkCreatePhysicalMemoryChannel(PAL_NUM* key);

This API creates a physical memory channel for the process to copy virtual memory as copy-on-write.
Once a channel is created, other processes can connect to the physical memory channel by using
[[DkStreamOpen|PAL Host ABI#DkStreamOpen]] with a URI `gipc:<key>`.

#### DkPhysicalMemoryCommit

    PAL_NUM DkPhysicalMemoryCommit(PAL_HANDLE channel, PAL_NUM entries, PAL_PTR* addrs,
                                   PAL_NUM* sizes, PAL_FLG flags);

This API commits (sends) an array of the virtual memory area over the physical memory channel.

#### DkPhysicalMemoryMap

    PAL_NUM DkPhysicalMemoryMap(PAL_HANDLE channel, PAL_NUM entries, PAL_PTR* addrs,
                                PAL_NUM* sizes, PAL_FLG* prots);

This API maps an array of virtual memory area from the physical memory channel.
