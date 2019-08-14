# PAL Host ABI
## What is Graphene's PAL Host ABI

PAL Host ABI is the interface used by Graphene library OS to interact with its hosts. It is translated into the hosts' native ABI (e.g. system calls for UNIX), by a layer called PAL (platform adaption layer). A PAL not only exports a set of APIs (PAL APIs) that can be called by the library OS, but also act as the loader that bootstraps the library OS. The design of PAL Host ABI strictly follows three primary principles, to guarantee functionality, security, and platform compatibility:  

* The host ABI must be stateless.
* The host ABI must be a narrowed interface to reduce the attack surface.
* The host ABI must be generic and independent from the native ABI on the hosts.

Most of the PAL Host ABI are adapted from _Drawbridge_ library OS.

## PAL as Loader

Regardless of the actual implementation, we require PAL to be able to load ELF-format binaries as executables or dynamic libraries, and perform the necessary dynamic relocation. PAL will need to look up all unresolved symbols in loaded binaries, and resolve the ones matching the name of PAL APIs (_Important!!!_). PAL does not and will not resolve other unresolved symbols, so the loaded libraries and executables must resolve them afterwards. 

After loading the binaries, PAL needs to load and interpret the manifest files. The manifest syntax will be described in [[Manifest Syntax]].

After PAL fully initialized the process, it will jump to the entry points of libraries and/or executables to start the execution. When jumping to the entry points, arguments, environment variables and auxiliary vectors must be pushed to the stack as the UNIX calling convention.

### Manifest and Executable Loading Rules 

The PAL loader supports multiple ways of locating the manifest and executable. To run a program in Graphene properly, the PAL loader generally requires both a manifest and an executable, although it is possible to load with only one of them. The user shall specify either the manifest and the executable to load in the command line, and the PAL loader will try to locate the other based on the file name or content.

Precisely, the loading rules for the manifest and executable are as follows:

1. The first argument given to the PAL loader (e.g., `pal-Linux`, `pal-Linux-SGX`, `pal-FreeBSD`, or the cross-platform wrapper, `pal-loader`) can be either a manifest or an executable.
2. If an executable is given to the command line, the loader will search for the manifest in the following order: the same file name as the executable with a `.manifest` or `.manifest.sgx` extenstion, a `manifest` file without any extension, or no manifest at all.
3. If a manifest is given to the command line, and the manifest contains a `loader.exec` rule, then the rule is used to determine the executable. The loader should exit if the executable file doesn't exist.
4. If a manifest is given to the command line, and the manifest DOES NOT contain a `loader.exec rule`, then the manifest MAY be used to infer the executable. The potential executable file has the same file name as the manifest file except it doesn't have the `.manifest` or `.manifest.sgx` extension.
5. If a manifest is given to the command line, and no executable file can be found either based on any `loader.exec` rule or inferring from the manifest file, then no executable is used for the execution.   


## Data Types and Variables

### Data Types

#### PAL handles

The PAL handles are identifiers that are returned by PAL when opening or creating resources. The basic data structure of a PAL handle is defined as follows:

    typedef union pal_handle {
        struct {
            PAL_IDX type;
            PAL_REF ref;
            PAL_FLG flags;
        } __in;
        (Other resource-specific definitions)
    } PAL_HANDLE;

As shown above, a PAL handle is usually defined as a _union_ data type that contain different subtypes that represent each resources such as files, directories, pipes or sockets. The actual memory allocated for the PAL handles may be variable-sized. 

#### Numbers and Flags

_PAL_NUM_ and _PAL_FLG_ represent the integers used for numbers and flags. On x86-64, they are defined as follows:

    typedef unsigned long PAL_NUM;
    typedef unsigned int  PAL_FLG;
  
#### Pointers, Buffers and Strings

_PAL_PTR_ and _PAL_STR_ represent the pointers that point to memory, buffers and strings.  On x86_64, they are defined as follows:

    typedef const char *  PAL_STR;
    typedef void *        PAL_PTR;

#### Boolean Values

_PAL_BOL_ represents the boolean values that will solely contain either _True_ or _False_. This data type is commonly used as the return values of many PAL APIs to determine whether the call has succeeded. The value of _PAL_BOL_ could be either _PAL_TRUE_ or _PAL_FALSE_. On x86_64, they are defined as follows:

    typedef bool          PAL_BOL;
 
### Graphene Control Block

The control block in Graphene is a structure that provides static information of the current process and its host. It is also a dynamic symbol that will be linked by library OSes and resolved at runtime. Sometimes, for the flexibility or the convenience of dynamic resolution, the address of the control block may be resolved by a function (_pal_control_addr()_).

The members of Graphene control block are defined as follows:

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

The PAL APIs contain _44_ functions that can be called from the library OSes.

### Memory allocation

#### DkVirtualMemoryAlloc

    PAL_PTR
    DkVirtualMemoryAlloc (PAL_PTR addr, PAL_NUM size, PAL_FLG alloc_type,
                          PAL_FLG prot);

This API allocates virtual memory for the library OSes. _addr_ can be either _NULL_ or any valid addresses that are aligned by the allocation alignment. When _addr_ is non-NULL, the API will try to allocate the memory at the given address, potentially rewrite any memory previously allocated at the same address. Overwriting any part of PAL and host kernel is forbidden. _size_ must be a positive number, aligned by the allocation alignment. 

_alloc_type_ can be a combination of any of the following flags:

    /* Memory Allocation Flags */
    #define PAL_ALLOC_32BIT       0x0001   /* Only give out 32-bit addresses */
    #define PAL_ALLOC_RESERVE     0x0002   /* Only reserve the memory */

_prot_ can be a combination of the following flags:

    /* Memory Protection Flags */
    #define PAL_PROT_NONE       0x0     /* 0x0 Page can not be accessed. */
    #define PAL_PROT_READ       0x1     /* 0x1 Page can be read. */
    #define PAL_PROT_WRITE      0x2     /* 0x2 Page can be written. */
    #define PAL_PROT_EXEC       0x4     /* 0x4 Page can be executed. */
    #define PAL_PROT_WRITECOPY  0x8     /* 0x8 Copy on write */

#### DkVirtualMemoryFree

    void
    DkVirtualMemoryFree (PAL_PTR addr, PAL_NUM size);

This API deallocates a previously allocated memory mapping. Both _addr_ and _size_ must be non-zero and aligned by the allocation alignment.

#### DkVirtualMemoryProtect

    PAL_BOL
    DkVirtualMemoryProtect (PAL_PTR addr, PAL_NUM size, PAL_FLG prot);

This API modified the hardware protection of a previously allocated memory mapping. Both _addr_ and _size_ must be non-zero and aligned by the allocation alignment. _prot_ is defined as [[DkVirtualMemoryAlloc|PAL Host ABI#DkVirtualMemoryAlloc]].

### Process Creation

#### DkProcessCreate

    PAL_HANDLE
    DkProcessCreate (PAL_STR uri, PAL_FLG flags, PAL_STR * args);

This API creates a new process to run a separated executable. _uri_ is the URI of the manifest file or the executable to be loaded in the new process. _flags_ is currently unused. _args_ is an array of strings as the arguments to be passed to the new process.

#### DkProcessExit

    void
    DkProcessExit (PAL_NUM exitCode);

This API terminates all threads in the process immediately. _exitCode_ with be exit value returned to the host.

#### DkProcessSandboxCreate

    #define PAL_SANDBOX_PIPE         0x1
    PAL_BOL
    DkProcessSandboxCreate (PAL_STR manifest, PAL_FLG flags);

This API loads a new manifest file and inform the reference monitor to create a new sandbox. _manifest_ will be the URI of the manifest file to be loaded. If _PAL_SANDBOX_PIPE_ is given in _flags_, reference monitor will isolate the RPC streams from other processes.

### Stream Creation/Connection/Open

#### DkStreamOpen

    PAL_HANDLE
    DkStreamOpen (PAL_STR uri, PAL_FLG access, PAL_FLG share_flags,
                  PAL_FLG create, PAL_FLG options);

This APIs open/create stream resources specified by _uri_. If the resource is successfully opened/created, a PAL handle will be returned for further access such as reading or writing. _uri_ is the URI of the stream to be opened/created. The following is a list of URIs that are supported in PAL:

* `file:...`, `dir:...`: Files or directories on the host file systems. If _PAL_CREAT_TRY_ is given in _create_, the file or directory will be created. 
* `dev:...`: Opening devices as streams. For example, `dev:tty` represents the standard input/output.
* `pipe.srv:<ID>`, `pipe:<ID>`, `pipe:`: Open a byte stream that can be used as RPC (remote procedure call) between processes. Pipes are located by numeric IDs. The server side of pipes can accept any number of connection. If `pipe:` is given as the URI, it will open a anonymous bidirectional pipe. 
* `tcp.srv:<ADDR>:<port>`, `tcp:<ADDR>:<PORT>`: Opening a TCP socket to listen or connecting to remote TCP socket.
* `udp.srv:<ADDR>:<PORT>`, `udp:<ADDR>:<PORT>`: Opening a UDP socket to listen or connecting to remote UDP socket.

_access_ can be a combination of the following flags:

    /* Stream Access Flags */
    #define PAL_ACCESS_RDONLY   00
    #define PAL_ACCESS_WRONLY   01
    #define PAL_ACCESS_RDWR     02

_share_flags_ can be a combination of the following flags:

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

_create_ can be a combination of the following flags:

    /* Stream Create Flags */
    #define PAL_CREAT_TRY        0100       /* 0100 Create file if file not
                                               exist (O_CREAT) */
    #define PAL_CREAT_ALWAYS     0200       /* 0300 Create file and fail if file
                                               already exist (O_CREAT|O_EXCL) */

_options_ can be a combination of the following flags:

    /* Stream Option Flags */
    #define PAL_OPTION_NONBLOCK     04000

#### DkStreamWaitForClient

    PAL_HANDLE
    DkStreamWaitForClient (PAL_HANDLE handle);

This API is only available for handles that are opened with `pipe.srv:...`, `tcp.srv:...` and `udp.srv:...`. It will block until a new connection is accepted and return the PAL handle for the connection.

#### DkStreamRead

    PAL_NUM
    DkStreamRead (PAL_HANDLE handle, PAL_NUM offset, PAL_NUM count,
                  PAL_PTR buffer, PAL_PTR source, PAL_NUM size);

This API receives or reads data from an opened stream. If the handles are files, _offset_ must be specified at each call of DkStreamRead. _source_ and _size_ can be used to return the remote socket addresses if the handles are UDP sockets.  

If the handles are directories, calling DkStreamRead will fill the buffer with the names (NULL-ended) of the files or subdirectories inside.

#### DkStreamWrite

    PAL_NUM
    DkStreamWrite (PAL_HANDLE handle, PAL_NUM offset, PAL_NUM count,
                   PAL_PTR buffer, PAL_STR dest);

This API sends or writes data to an opened stream. If the handles are files, _offset_ must be specified at each call of DkStreamWrite. _dest_ can be used to specify the remote socket addresses if the handles are UDP sockets.

#### DkStreamDelete

    #define PAL_DELETE_RD       01
    #define PAL_DELETE_WR       02
    void
    DkStreamDelete (PAL_HANDLE handle, PAL_FLG access);

This API deletes files or directories on the host, or shut down connection of TCP or UDP sockets. _access_ specifies the method of shutting down the connection. _access_ can be either read-side only, write-side only, or both if 0 is given in _access_.

#### DkStreamMap

    PAL_PTR
    DkStreamMap (PAL_HANDLE handle, PAL_PTR address, PAL_FLG prot,
                 PAL_NUM offset, PAL_NUM size);

This API maps files to virtual memory of the current process. _address_ can be NULL or a valid address that are aligned by the allocation alignment. _offset_ and _size_ have to be non-zero and aligned by the allocation alignment. _prot_ is defined as [[DkVirtualMemoryAlloc|PAL Host ABI#DkVirtualMemoryAlloc]].

#### DkStreamUnmap

    void
    DkStreamUnmap (PAL_PTR addr, PAL_NUM size);

This API unmaps virtual memory that are backed with file streams. _addr_ and _size_ must be aligned by the allocation alignment.

#### DkStreamSetLength

    PAL_NUM
    DkStreamSetLength (PAL_HANDLE handle, PAL_NUM length);

This API truncates or extends a file stream to the length given.

#### DkStreamFlush

    PAL_BOL
    DkStreamFlush (PAL_HANDLE handle);

This API flushes the buffer of a file stream.

#### DkSendHandle

    PAL_BOL
    DkSendHandle (PAL_HANDLE handle, PAL_HANDLE cargo);

This API can be used to send a PAL handle upon other handle. Currently, the handle that are used to send handle must be a process handle, thus handles can only be sent between parent and child processes. 

#### DkReceiveHandle

    PAL_HANDLE
    DkReceiveHandle (PAL_HANDLE handle);

This API receives a handle upon other handle.

#### DkStreamAttributeQuery

    PAL_BOL
    DkStreamAttributesQuery (PAL_STR uri, PAL_STREAM_ATTR * attr);

This API queries the attributes of a named stream. This API only applies for URI such as `file:...`, `dir:...` or `dev:...`.

The data type _PAL_STREAM_ATTR_ is defined as follows:

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

    PAL_BOL
    DkStreamAttributesQuerybyHandle (PAL_HANDLE handle,
                                     PAL_STREAM_ATTR * attr);

This API queries the attributes of an opened stream. This API applies for any stream handles.

#### DkStreamAttributesSetbyHandle

    PAL_BOL
    DkStreamAttributesSetbyHandle (PAL_HANDLE handle, PAL_STREAM_ATTR * attr);

This API sets the attributes of an opened stream.

#### DkStreamGetName

    PAL_NUM
    DkStreamGetName (PAL_HANDLE handle, PAL_PTR buffer, PAL_NUM size);

This API queries the name of an opened stream.

#### DkStreamChangeName

    PAL_BOL
    DkStreamChangeName (PAL_HANDLE handle, PAL_STR uri);

This API changes the name of an opened stream.

### Thread Creation

#### DkThreadCreate

    PAL_HANDLE
    DkThreadCreate (PAL_PTR addr, PAL_PTR param, PAL_FLG flags);

This API creates a thread in the current process. _addr_ will be the address where the new thread starts. _param_ is the parameter that is passed into the new thread as the only argument. _flags_ is currently unused.

#### DkThreadPrivate

    PAL_PTR
    DkThreadPrivate (PAL_PTR addr);

This API retrieves or sets the thread-local storage address of the current thread.

#### DkThreadDelayExecution

    PAL_NUM
    DkThreadDelayExecution (PAL_NUM duration);

This API will suspend the current thread for certain duration (in microseconds).

#### DkThreadYieldExecution

    void
    DkThreadYieldExecution (void);

This API will yield the current thread and request for rescheduling in the scheduler on the host. 

#### DkThreadExit

    void
    DkThreadExit (void);

This API terminates the current thread.

#### DkThreadResume

    PAL_BOL
    DkThreadResume (PAL_HANDLE thread);

This API resumes a thread and force the thread to jump into a handler. 

### Exception Handling

#### DkSetExceptionHandler

    PAL_BOL
    DkSetExceptionHandler (void (*handler) (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context),
                           PAL_NUM event, PAL_FLG flags);

This API set the handler for the specific exception event.

_event_ can be one of the following values:

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

_flags_ can be combination of the following flags:

    #define PAL_EVENT_PRIVATE      0x0001       /* upcall specific to thread */
    #define PAL_EVENT_RESET        0x0002       /* reset the event upcall */

#### DkExceptionReturn

    void
    DkExceptionReturn (PAL_PTR event);

This API exits a exception handler and restores the context.

### Synchronization

#### DkSemaphoreCreate

    PAL_HANDLE
    DkSemaphoreCreate (PAL_NUM initialCount, PAL_NUM maxCount);

This API creates a semaphore with the given _initialCount_ and _maxCount_.

#### DkSemaphoreRelease

    void
    DkSemaphoreRelease (PAL_HANDLE semaphoreHandle, PAL_NUM count);

This API wakes up _count_ waiter on the given semaphore.

##### DkNotificationEventCreate/DkSynchronizationEventCreate

    PAL_HANDLE
    DkNotificationEventCreate (PAL_BOL initialState);
    PAL_HANDLE
    DkSynchronizationEventCreate (PAL_BOL initialState);

This API creates a event with the given _initialState_. The definition of notification events and synchronization events are the same as the WIN32 API. When a notification event is set to the Signaled state it remains in that state until it is explicitly cleared. When a synchronization event is set to the Signaled state, a single thread of execution that was waiting for the event is released, and the event is automatically reset to the Not-Signaled state.

#### DkEventSet

    void
    DkEventSet (PAL_HANDLE eventHandle);

This API sets (signals) a notification event or a synchronization event.

#### DkEventClear

    void
    DkEventClear (PAL_HANDLE eventHandle);

This API clears a notification event or a synchronization event.

### Objects

#### DkObjectsWaitAny

    #define NO_TIMEOUT      ((PAL_NUM) -1)
    PAL_HANDLE
    DkObjectsWaitAny (PAL_NUM count, PAL_HANDLE * handleArray, PAL_NUM timeout);

This API polls an array of handle and return one handle with recent activity. _timeout_ is the maximum time that the API should wait (in microsecond), or _NO_TIMEOUT_ to indicate it to be blocked as long as possible.

#### DkObjectClose

    void
    DkObjectClose (PAL_HANDLE objectHandle);

This API closes (deallocates) a PAL handle.

### Miscellaneous

#### DkSystemTimeQuery

    PAL_NUM
    DkSystemTimeQuery (void);

This API returns the timestamp of current time (in microseconds).

#### DkRandomBitsRead

    PAL_NUM
    DkRandomBitsRead (PAL_PTR buffer, PAL_NUM size);

This API fills the buffer with cryptographically random values.

#### DkInstructionCacheFlush

    PAL_BOL
    DkInstructionCacheFlush (PAL_PTR addr, PAL_NUM size);

This API flushes the instruction cache at the given _addr_ and _size_.

### Memory Bulk Copy

#### DkCreatePhysicalMemoryChannel

    PAL_HANDLE
    DkCreatePhysicalMemoryChannel (PAL_NUM * key);

This API creates a physical memory channel for the process to copy virtual memory as copy-on-write. Once a channel is created, any other processes can connect to the physical memory channel by using [[DkStreamOpen|PAL Host ABI#DkStreamOpen]] with URI as `gipc:<key>`.

#### DkPhysicalMemoryCommit

    PAL_NUM
    DkPhysicalMemoryCommit (PAL_HANDLE channel, PAL_NUM entries, PAL_PTR * addrs,
                            PAL_NUM * sizes, PAL_FLG flags);

This API commits (sends) an array of virtual memory area to the physical memory channel.

#### DkPhysicalMemoryMap

    PAL_NUM
    DkPhysicalMemoryMap (PAL_HANDLE channel, PAL_NUM entries, PAL_PTR * addrs,
                         PAL_NUM * sizes, PAL_FLG * prots);

This API maps an array of virtual memory area from the physical memory channel.
