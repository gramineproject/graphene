Graphene Manifest Syntax
========================

.. highlight:: text

Basic Syntax
------------

A |~| manifest file is an application-specific configuration text file that
specifies the environment and resources for running an application inside
Graphene. A |~| manifest file contains entries separated by line breaks. Each
configuration entry consists of a |~| key and a |~| value. Whitespaces
before/after the key and before/after the value are ignored. The value can be
written in quotes, indicating that the value should be assigned to this string
verbatim. (The quotes syntax is useful for values with leading/trailing
whitespaces, e.g. ``" SPACES! "``.) Each entry must be in the following format::

   [Key][.Key][.Key] = [Value]  or  [Key][.Key][.Key] = "[Value]"

Comments can be inlined in a |~| manifest by starting them with a |~| hash sign
(``# comment...``). Any text after a |~| hash sign will be considered part of
a |~| comment and discarded while loading the manifest file.

Loader-related (Required by PAL)
--------------------------------

Executable
^^^^^^^^^^

::

   loader.exec=[URI]

This syntax specifies the executable to be loaded into the library OS. The
executable must be an ELF binary, with an entry point defined to start its
execution (i.e., the binary needs a `main()` routine, it cannot just be
a |~| library).

Preloaded Libraries (e.g., LibOS)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

   loader.preload=[URI][,URI]...

This syntax specifies the libraries to be preloaded before loading the
executable. The URIs of the libraries must be separated by commas. The libraries
must be ELF binaries.

Executable Name
^^^^^^^^^^^^^^^

::

   loader.execname=[STRING]

This syntax specifies an arbitrary string (typically the executable name) that
will be passed as the first argument (``argv[0]``) to the executable only if it
is run via the manifest (e.g. ``./app.manifest arg1 arg2 ...``). If the string
is not specified in the manifest, the PAL will use the path to the manifest
itself (standard UNIX convention).

Environment Variables
^^^^^^^^^^^^^^^^^^^^^

::

   loader.env.[ENVIRON]=[VALUE]

By default, the environment variables on the host will be passed to the library
OS. Specifying an environment variable using this syntax adds/overwrites it and
passes to the library OS. This syntax can be used multiple times to specify more
than one environment variable. An environment variable can be deleted by giving
it an empty value.

Debug Type
^^^^^^^^^^

::

    loader.debug_type=[none|inline]
    (Default: none)

This specifies the debug option while running the library OS. If the debug type
is ``none``, no debug output will be printed to standard output. If the debug
type is ``inline``, a dmesg-like debug output will be printed inlined with
standard output.


System-related (Required by LibOS)
----------------------------------

Stack Size
^^^^^^^^^^

::

    sys.stack.size=[# of bytes (with K/M/G)]

This specifies the stack size of each thread in each Graphene process. The
default value is determined by the library OS. Units like ``K`` |~| (KiB),
``M`` |~| (MiB), and ``G`` |~| (GiB) can be appended to the values for
convenience. For example, ``sys.stack.size=1M`` indicates a 1 |~| MiB stack
size.

Program Break (Heap) Size
^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sys.brk.size=[# of bytes (with K/M/G)]

This specifies the program break (brk) size in each Graphene process. The
default value of the program break size is determined by the library OS. Units
like ``K`` (KiB), ``M`` (MiB), and ``G`` (GiB) can be appended to the values for
convenience. For example, ``sys.brk.size=1M`` indicates a 1 |~| MiB brk size.

Allowing eventfd
^^^^^^^^^^^^^^^^

::

    sys.allow_insecure_eventfd=[1|0]
    (Default: 0)

This specifies whether to allow system calls `eventfd()` and `eventfd2()`. Since
eventfd emulation currently relies on the host, these system calls are
disallowed by default due to security concerns.


FS-related (Required by LibOS)
------------------------------

Mount Points
^^^^^^^^^^^^

::

    fs.mount.[identifier].path=[PATH]
    fs.mount.[identifier].type=[chroot|...]
    fs.mount.[identifier].uri=[URI]

This syntax specifies how file systems are mounted inside the library OS. For
dynamically linked binaries, usually at least one mount point is required in the
manifest (the mount point of the Glibc library).


SGX syntax
----------

If Graphene is *not* running with SGX, the SGX-specific syntax is ignored. All
keys in the SGX-specific syntax are optional.

Enclave Size
^^^^^^^^^^^^

::

    sgx.enclave_size=[SIZE]
    (default: 256M)

This syntax specifies the size of the enclave set during enclave creation time
(recall that SGX |~| v1 requires a predetermined maximum size of the enclave).
The PAL and library OS code/data count towards this size value, as well as the
application memory itself: application's code, stack, heap, loaded application
libraries, etc. The application cannot allocate memory that exceeds this limit.

Number of Threads
^^^^^^^^^^^^^^^^^

::

    sgx.thread_num=[NUM]
    (Default: 4)

This syntax specifies the maximum number of threads that can be created inside
the enclave (recall that SGX |~| v1 requires a |~| predetermined maximum number
of thread slots). The application cannot have more threads than this limit *at
a time* (however, it is possible to create new threads after old threads are
destroyed).

Number of RPC Threads (Exitless Feature)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.rpc_thread_num=[NUM]
    (Default: 0)

This syntax specifies the number of RPC threads that are created outside of
the enclave. RPC threads are helper threads that run in untrusted mode
alongside enclave threads. RPC threads issue system calls on behalf of enclave
threads. This allows "exitless" design when application threads never leave
the enclave (except for a few syscalls where there is no benefit, e.g.,
``nanosleep()``).

If user specifies ``0`` or omits this directive, then no RPC threads are
created and all system calls perform an enclave exit ("normal" execution).

Note that the number of created RPC threads must match the maximum number of
simultaneous enclave threads. If there are more RPC threads, then CPU time is
wasted. If there are less RPC threads, some enclave threads may starve,
especially if there are many blocking system calls by other enclave threads.

The Exitless feature *may be detrimental for performance*. It trades slow
OCALLs/ECALLs for fast shared-memory communication at the cost of occupying
more CPU cores and burning more CPU cycles. For example, a single-threaded
Redis instance on Linux becomes 5-threaded on Graphene with Exitless. Thus,
Exitless may negatively impact throughput but may improve latency.

Debug/Production Enclave
^^^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.debug=[1|0]
    (Default: 1)

This syntax specifies whether the enclave can be debugged. Set it to ``1`` for
a |~| debug enclave and to ``0`` for a |~| production enclave.

Optional CPU features (AVX, AVX512, MPX)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.require_avx=[1|0]
    sgx.require_avx512=[1|0]
    sgx.require_mpx=[1|0]
    (Default: 0)

This syntax ensures that the CPU features are available and enabled for the
enclave. If the options are set in the manifest but the features are unavailable
on the platform, enclave initialization should fail. If the options are unset,
enclave initialization should succeed even if these features are unavailable on
the platform.

ISV Product ID and SVN
^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.isvprodid=[NUM]
    sgx.isnsvn=[NUM]
    (Default: 0)

This syntax specifies the ISV Product ID and SVN to be added to the enclave
signature.

Trusted Files
^^^^^^^^^^^^^

::

    sgx.trusted_files.[identifier]=[URI]

This syntax specifies the files to be cryptographically hashed, and thus allowed
to be loaded into the enclave. The signer tool will automatically generate
hashes of these files and add them into the SGX-specific manifest
(``.manifest.sgx``). This is especially useful for shared libraries:
a |~| trusted library cannot be silently replaced by a malicious host because
the hash verification will fail.

Allowed Files
^^^^^^^^^^^^^

::

    sgx.allowed_files.[identifier]=[URI]

This syntax specifies the files that are allowed to be loaded into the enclave
unconditionally. These files are not cryptographically hashed and are thus not
protected. It is insecure to allow files containing code or critical
information; developers must not allow files blindly!

Allowing File Creation
^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.allow_file_creation=[1|0]
    (Default: 0)

This syntax specifies whether file creation is allowed from within the enclave.
Set it to ``1`` to allow enclaves to create files and to ``0`` otherwise. Files
created during enclave execution do not need to be marked as ``allowed_files``
or ``trusted_files``.

Trusted Child Processes
^^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.trusted_children.[identifier]=[URI of signature (.sig)]

This syntax specifies the signatures of allowed child processes of the current
application. Upon process creation, the enclave in the current (parent) process
will attest the enclave in the child process, by comparing to the signatures of
the trusted children. If the child process is not trusted, the enclave will
refuse to communicate with it.

File Check Policy
^^^^^^^^^^^^^^^^^

::

    sgx.file_check_policy=[strict|allow_all_but_log]
    (Default: strict)

This syntax specifies the file check policy, determining the behavior of
authentication when opening files. By default, only files explicitly listed as
_trusted_files_ or _allowed_files_ declared in the manifest are allowed for
access. If the file check policy is ``allow_all_but_log``, all files other than
trusted and allowed are allowed for access, and Graphene-SGX emits a warning
message for every such file. This is a convenient way to determine the set of
files that the ported application uses.
