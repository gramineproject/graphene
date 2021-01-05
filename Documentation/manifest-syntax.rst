Manifest syntax
===============

.. highlight:: text

A |~| manifest file is an application-specific configuration text file that
specifies the environment and resources for running an application inside
Graphene. A |~| manifest file contains key-value pairs (as well as more
complicated table and array objects) in the TOML syntax. For the details of the
TOML syntax, see `the official documentation <https://toml.io>`__.

A typical string entry looks like this::

   [Key][.Key][.Key] = "[Value]"

A typical integer entry looks similar to the above but without double quotes::

   [Key][.Key][.Key] = [Value]

Comments can be inlined in a |~| manifest by starting them with a |~| hash sign
(``# comment...``).

Common syntax
-------------

Debug type
^^^^^^^^^^

::

    loader.debug_type = "[none|inline|file]"
    (Default: "none")

    loader.debug_file = "[PATH]"

This specifies the debug option while running the library OS. If the debug type
is ``none``, no debug output will be printed to standard output. If the debug
type is ``inline``, a dmesg-like debug output will be printed inline with
standard output. If the debug type is ``file``, debug output will be written to
the file specified in ``loader.debug_file``.

Preloaded libraries
^^^^^^^^^^^^^^^^^^^

::

   loader.preload = "[URI][,URI]..."

This syntax specifies the libraries to be preloaded before loading the
executable. The URIs of the libraries must be separated by commas. The libraries
must be ELF binaries. This usually contains the LibOS library ``libsysdb.so``.

Command-line arguments
^^^^^^^^^^^^^^^^^^^^^^

::

   loader.argv0_override = "[STRING]"

This syntax specifies an arbitrary string (typically the executable name) that
will be passed as the first argument (``argv[0]``) to the executable.

If the string is not specified in the manifest, the application will get
``argv[0]`` from :program:`pal_loader` invocation.

::

   loader.insecure__use_cmdline_argv = 1

or

::

   loader.argv_src_file = "file:file_with_serialized_argv"

If you want your application to use commandline arguments you need to either set
``loader.insecure__use_cmdline_argv`` (insecure in almost all cases) or point
``loader.argv_src_file`` to a file containing output of
:file:`Tools/argv_serializer`.

``loader.argv_src_file`` is intended to point to either a trusted file or a
protected file. The former allows to securely hardcode arguments (current
manifest syntax doesn't allow to include them inline), the latter allows the
arguments to be provided at runtime from an external (trusted) source. *NOTE:*
Pointing to a protected file is currently not supported, due to the fact that
PF wrap key provisioning currently happens after setting up arguments.

Environment variables
^^^^^^^^^^^^^^^^^^^^^

::

   loader.insecure__use_host_env = 1

By default, environment variables from the host will *not* be passed to the app.
This can be overridden by the option above, but most applications and runtime
libraries trust their environment variables and are completely insecure when
these are attacker-controlled. For example, an attacker can execute an
additional dynamic library by specifying ``LD_PRELOAD`` variable.

To securely set up the execution environment for an app you should use one or
both of the following options:

::

   loader.env.[ENVIRON] = "[VALUE]"
   loader.env_src_file = "file:file_with_serialized_envs"

``loader.env.[ENVIRON]`` adds/overwrites a single environment variable and can
be used multiple times to specify more than one variable.

``loader.env_src_file`` allows to specify a URI to a file containing serialized
environment, which can be generated using :file:`Tools/argv_serializer`. This
option is intended to point to either a trusted file or a protected file. The
former allows to securely hardcode environments (in a more flexible way than
``loader.env.[ENVIRON]`` option), the latter allows the environments to be
provided at runtime from an external (trusted) source. *NOTE:* Pointing to a
protected file is currently not supported, due to the fact that PF wrap key
provisioning currently happens after setting up environment variables.

If the same variable is set in both, then ``loader.env.[ENVIRON]`` takes
precedence.

Disabling ASLR
^^^^^^^^^^^^^^

::

    loader.insecure__disable_aslr = [1|0]
    (Default: 0)

This specifies whether to disable Address Space Layout Randomization (ASLR).
Since disabling ASLR worsens security of the application, ASLR is enabled by
default.

Graphene internal metadata size
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    loader.pal_internal_mem_size = "[SIZE]"
    (default: "0")

This syntax specifies how much additional memory Graphene reserves for its
internal use (e.g., metadata for trusted/protected files, internal handles,
etc.). By default, Graphene pre-allocates 64MB of internal memory for this
metadata, but for huge workloads this limit may be not enough. In this case,
Graphene loudly fails with "out of PAL memory" error. To run huge workloads,
increase this limit by setting this option to e.g. ``64M`` (this would result in
a total of 128MB used by Graphene for internal metadata). Note that this limit
is included in ``sgx.enclave_size``, so if your enclave size is e.g. 512MB and
you specify ``loader.pal_internal_mem_size = "64MB"``, then your application is
left with 384MB of usable memory.

Stack size
^^^^^^^^^^

::

    sys.stack.size = "[SIZE]"
    (default: "256K")

This specifies the stack size of each thread in each Graphene process. The
default value is determined by the library OS. Units like ``K`` |~| (KiB),
``M`` |~| (MiB), and ``G`` |~| (GiB) can be appended to the values for
convenience. For example, ``sys.stack.size = "1M"`` indicates a 1 |~| MiB stack
size.

Program break (brk) size
^^^^^^^^^^^^^^^^^^^^^^^^

::

    sys.brk.max_size = "[SIZE]"
    (default: "256K")

This specifies the maximal program break (brk) size in each Graphene process.
The default value of the program break size is determined by the library OS.
Units like ``K`` (KiB), ``M`` (MiB), and ``G`` (GiB) can be appended to the
values for convenience. For example, ``sys.brk.max_size = "1M"`` indicates
a 1 |~| MiB brk size.

Allowing eventfd
^^^^^^^^^^^^^^^^

::

    sys.insecure__allow_eventfd = [1|0]
    (Default: 0)

This specifies whether to allow system calls `eventfd()` and `eventfd2()`. Since
eventfd emulation currently relies on the host, these system calls are
disallowed by default due to security concerns.

Root FS mount point
^^^^^^^^^^^^^^^^^^^

::

    fs.root.[identifier].type = "[chroot|...]"
    fs.root.[identifier].path = "[PATH]"
    fs.root.[identifier].uri  = "[URI]"

This syntax specifies the root file system to be mounted inside the library OS.
If not specified, then Graphene mounts the current working directory as the
root. There can be only one root FS mount point specified in the manifest.

FS mount points
^^^^^^^^^^^^^^^

::

    fs.mount.[identifier].type = "[chroot|...]"
    fs.mount.[identifier].path = "[PATH]"
    fs.mount.[identifier].uri  = "[URI]"

This syntax specifies how file systems are mounted inside the library OS. For
dynamically linked binaries, usually at least one mount point is required in the
manifest (the mount point of the Glibc library).

Start (current working) directory
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    fs.start_dir = "[URI]"

This syntax specifies the start (current working) directory. If not specified,
then Graphene sets the root directory as the start directory (see ``fs.root``).


SGX syntax
----------

If Graphene is *not* running with SGX, the SGX-specific syntax is ignored. All
keys in the SGX-specific syntax are optional.

Debug/production enclave
^^^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.debug = [1|0]
    (Default: 1)

This syntax specifies whether the enclave can be debugged. Set it to ``1`` for
a |~| debug enclave and to ``0`` for a |~| production enclave.

Enclave size
^^^^^^^^^^^^

::

    sgx.enclave_size = "[SIZE]"
    (default: "256M")

This syntax specifies the size of the enclave set during enclave creation time
(recall that SGX |~| v1 requires a predetermined maximum size of the enclave).
The PAL and library OS code/data count towards this size value, as well as the
application memory itself: application's code, stack, heap, loaded application
libraries, etc. The application cannot allocate memory that exceeds this limit.

Number of threads
^^^^^^^^^^^^^^^^^

::

    sgx.thread_num = [NUM]
    (Default: 4)

This syntax specifies the maximum number of threads that can be created inside
the enclave (recall that SGX |~| v1 requires a |~| predetermined maximum number
of thread slots). The application cannot have more threads than this limit *at
a time* (however, it is possible to create new threads after old threads are
destroyed).

Number of RPC threads (Exitless feature)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.rpc_thread_num = [NUM]
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

Optional CPU features (AVX, AVX512, MPX)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.require_avx    = [1|0]
    sgx.require_avx512 = [1|0]
    sgx.require_mpx    = [1|0]
    (Default: 0)

This syntax ensures that the CPU features are available and enabled for the
enclave. If the options are set in the manifest but the features are unavailable
on the platform, enclave initialization should fail. If the options are unset,
enclave initialization should succeed even if these features are unavailable on
the platform.

ISV Product ID and SVN
^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.isvprodid = [NUM]
    sgx.isnsvn    = [NUM]
    (Default: 0)

This syntax specifies the ISV Product ID and SVN to be added to the enclave
signature.

Allowed files
^^^^^^^^^^^^^

::

    sgx.allowed_files.[identifier] = "[URI]"

This syntax specifies the files that are allowed to be loaded into the enclave
unconditionally. These files are not cryptographically hashed and are thus not
protected. It is insecure to allow files containing code or critical
information; developers must not allow files blindly! Instead, use trusted or
protected files.

Trusted files
^^^^^^^^^^^^^

::

    sgx.trusted_files.[identifier] = "[URI]"

This syntax specifies the files to be cryptographically hashed, and thus allowed
to be loaded into the enclave. The signer tool will automatically generate
hashes of these files and add them into the SGX-specific manifest
(``.manifest.sgx``). This is especially useful for shared libraries:
a |~| trusted library cannot be silently replaced by a malicious host because
the hash verification will fail.

Protected files
^^^^^^^^^^^^^^^

::

    sgx.protected_files_key = "[16-byte hex value]"
    sgx.protected_files.[identifier] = "[URI]"

This syntax specifies the files that are encrypted on disk and transparently
decrypted when accessed by Graphene or by application running inside Graphene.
Protected files guarantee data confidentiality and integrity (tamper
resistance), as well as file swap protection (a protected file can only be
accessed when in a specific path).

URIs can be files or directories. If a directory is specified, all existing
files/directories within it are registered as protected recursively (and are
expected to be encrypted in the PF format). New files created in a protected
directory are automatically treated as protected.

Note that path size of a protected file is limited to 512 bytes and filename
size is limited to 260 bytes.

``sgx.protected_files_key`` specifies the wrap (master) encryption key and must
be used only for debugging purposes. In production environments, this key must
be provisioned to the enclave using local/remote attestation.

File check policy
^^^^^^^^^^^^^^^^^

::

    sgx.file_check_policy = "[strict|allow_all_but_log]"
    (Default: "strict")

This syntax specifies the file check policy, determining the behavior of
authentication when opening files. By default, only files explicitly listed as
_trusted_files_ or _allowed_files_ declared in the manifest are allowed for
access. If the file check policy is ``allow_all_but_log``, all files other than
trusted and allowed are allowed for access, and Graphene-SGX emits a warning
message for every such file. This is a convenient way to determine the set of
files that the ported application uses.

Trusted child processes
^^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.trusted_children.[identifier] = "[URI of signature file (.sig)]"

This syntax specifies the signatures of allowed child processes of the current
application. Upon process creation, the enclave in the current (parent) process
will attest the enclave in the child process, by comparing to the signatures of
the trusted children. If the child process is not trusted, the enclave will
refuse to communicate with it.

Attestation and quotes
^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.remote_attestation = [1|0]
    (Default: 0)

    sgx.ra_client_linkable = [1|0]
    sgx.ra_client_spid     = "[HEX]"

This syntax specifies the parameters for remote attestation. To enable it,
``remote_attestation`` must be set to ``1``.

For EPID based attestation, ``ra_client_linkable`` and ``ra_client_spid`` must
be filled with your registered Intel SGX EPID Attestation Service credentials
(linkable/unlinkable mode and SPID of the client respectively).

For DCAP/ECDSA based attestation, ``ra_client_spid`` must be an empty string
(this is a hint to Graphene to use DCAP instead of EPID) and
``ra_client_linkable`` is ignored.

Enabling per-thread and process-wide SGX stats
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.enable_stats = [1|0]
    (Default: 0)

This syntax specifies whether to enable SGX enclave-specific statistics:

#. ``TCS.FLAGS.DBGOPTIN`` flag. This flag is set in all enclave threads and
   enables certain debug and profiling features with enclaves, including
   breakpoints, performance counters, Intel PT, etc.

#. Printing the stats on SGX-specific events. Currently supported stats are:
   number of EENTERs (corresponds to ECALLs plus returns from OCALLs), number
   of EEXITs (corresponds to OCALLs plus returns from ECALLs) and number of
   AEXs (corresponds to interrupts/exceptions/signals during enclave
   execution). Prints per-thread and per-process stats.

#. Printing the SGX enclave loading time at startup. The enclave loading time
   includes creating the enclave, adding enclave pages, measuring them and
   initializing the enclave.

*Note:* this option is insecure and cannot be used with production enclaves
(``sgx.debug = 0``). If the production enclave is started with this option set,
Graphene will fail initialization of the enclave.

SGX profiling
^^^^^^^^^^^^^

::

    sgx.profile.enable = ["none"|"main"|"all"]
    (Default: "none")

This syntax specifies whether to enable SGX profiling. Graphene must be compiled
with ``DEBUG=1`` for this option to work.

If this option is set to ``main``, the main process will collect IP samples and
save them as ``sgx-perf.data``. If it is set to ``all``, all processes will
collect samples and save them to ``sgx-perf-<PID>.data``.

The saved files can be viewed with the ``perf`` tool, e.g. ``perf report -i
sgx-perf.data``.

See :doc:`devel/performance` for more information.

*Note:* this option is insecure and cannot be used with production enclaves
(``sgx.debug = 0``). If the production enclave is started with this option set,
Graphene will fail initialization of the enclave.

::

    sgx.profile.with_stack = [1|0]
    (Default: 0)

This syntax specifies whether to include stack information with the profiling
data. This will enable ``perf report`` to show call chains. However, it will
make the output file much bigger, and slow down the process.

::

    sgx.profile.frequency = [INTEGER]
    (Default: 50)

This syntax specifies approximate frequency at which profiling samples are taken
(in samples per second). Lower values will mean less accurate results, but also
lower overhead.

Note that the accuracy is limited by how often the process is interrupted by
Linux scheduler: the effective maximum is 250 samples per second.
