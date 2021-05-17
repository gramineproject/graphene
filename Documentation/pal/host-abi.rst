PAL host ABI
============

PAL Host ABI is the interface used by Graphene to interact with its host. It is translated into
the host's native ABI (e.g. system calls for UNIX) by a layer called the Platform Adaptation Layer
(PAL). A PAL not only exports a set of APIs (PAL APIs) that can be called by the library OS, but
also acts as the loader that bootstraps the library OS. The design of PAL Host ABI strictly follows
three primary principles, to guarantee functionality, security, and portability:

* The host ABI must be stateless.
* The host ABI must be a narrowed interface to reduce the attack surface.
* The host ABI must be generic and independent from the native ABI of any of the supported hosts.

Most of the PAL Host ABI is adapted from the Drawbridge library OS.

PAL as loader
-------------

Regardless of the actual implementation, we require PAL to be able to load ELF-format binaries
as executables or dynamic libraries, and perform the necessary dynamic relocation. PAL needs
to look up all unresolved symbols in loaded binaries and resolve the ones matching the names of
PAL APIs. PAL does not and will not resolve other unresolved symbols, so the loaded libraries and
executables must resolve them afterwards.

After loading the binaries, PAL needs to load and interpret the manifest files. The manifest syntax
is described in :doc:`../manifest-syntax`.

Manifest and executable loading
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To run a program in Graphene the PAL loader needs a manifest, which will
describe the whole environment inside Graphene namespace. It also describes
which executable to start first (via ``libos.entrypoint``).

Data types and variables
------------------------

Data types
^^^^^^^^^^

PAL handles
"""""""""""

The PAL handles are identifiers that are returned by PAL when opening or
creating resources. The basic data structure of a PAL handle is defined as
follows::

   typedef union pal_handle {
       struct {
           PAL_IDX type;
       } hdr;
       /* other resource-specific definitions */
   }* PAL_HANDLE;

.. doxygenunion:: pal_handle
   :project: pal
.. doxygentypedef:: PAL_HANDLE
   :project: pal

As shown above, a PAL handle is usually defined as a `union` data type that
contains different subtypes that represent each resource such as files,
directories, pipes or sockets. The actual memory allocated for the PAL handles
may be variable-sized.

Basic types
"""""""""""

.. doxygentypedef:: PAL_NUM
   :project: pal
.. doxygentypedef:: PAL_FLG
   :project: pal
.. doxygentypedef:: PAL_PTR
   :project: pal
.. doxygentypedef:: PAL_STR
   :project: pal
.. doxygentypedef:: PAL_IDX
   :project: pal
.. doxygentypedef:: PAL_BOL
   :project: pal

.. doxygendefine:: PAL_TRUE
   :project: pal
.. doxygendefine:: PAL_FALSE
   :project: pal


.. doxygentypedef:: PAL_PTR_RANGE
   :project: pal
.. doxygenstruct:: PAL_PTR_RANGE_
   :project: pal
   :members:

Graphene control block
^^^^^^^^^^^^^^^^^^^^^^

The control block in Graphene is a structure that provides static immutable
information about the current process and its host. The address of the control
block is resolved via :func:`DkGetPalControl()` and can be memorized in a global
variable for ease of use.

The fields of the Graphene control block are defined as follows:

.. doxygentypedef:: PAL_CONTROL
   :project: pal
.. doxygenstruct:: PAL_CONTROL_
   :project: pal
   :members:

.. doxygentypedef:: PAL_CPU_INFO
   :project: pal
.. doxygenstruct:: PAL_CPU_INFO_
   :project: pal
   :members:

.. doxygentypedef:: PAL_TOPO_INFO
   :project: pal
.. doxygenstruct:: PAL_TOPO_INFO_
   :project: pal
   :members:

.. doxygentypedef:: PAL_MEM_INFO
   :project: pal
.. doxygenstruct:: PAL_MEM_INFO_
   :project: pal
   :members:

Pal APIs
--------

The PAL APIs contain a |~| number of functions that can be called from the
library OS.


Memory allocation
^^^^^^^^^^^^^^^^^

The ABI includes three calls to allocate, free, and modify the permission bits
on page-base virtual memory. Permissions include read, write, execute, and
guard. Memory regions can be unallocated, reserved, or backed by committed
memory.

.. doxygenfunction:: DkVirtualMemoryAlloc
   :project: pal

.. doxygenfunction:: DkVirtualMemoryFree
   :project: pal

.. doxygenenum:: PAL_ALLOC
   :project: pal
.. doxygenenum:: PAL_PROT
   :project: pal

.. doxygenfunction:: DkVirtualMemoryProtect
   :project: pal


Process creation
^^^^^^^^^^^^^^^^

The ABI includes one call to create a child process and one call to terminate
the running process. A child process does not inherit any objects or memory from
its parent process and the parent process may not modify the execution of its
children. A parent can wait for a child to exit using its handle. Parent and
child may communicate through I/O streams provided by the parent to the child at
creation.

.. doxygenfunction:: DkProcessCreate
   :project: pal
.. doxygenfunction:: DkProcessExit
   :project: pal


Stream creation/connect/open
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The stream ABI includes nine calls to open, read, write, map, unmap,
truncate, flush, delete and wait for I/O streams and three calls to
access metadata about an I/O stream. The ABI purposefully does not
provide an ioctl call. Supported URI schemes include:
``file:``,
``pipe:``,
``http:``,
``https:``,
``tcp:``,
``udp:``,
``pipe.srv:``,
``http.srv``,
``tcp.srv:`` and
``udp.srv:``.
The latter four schemes are used to open inbound I/O streams for server
applications.

.. doxygenfunction:: DkStreamOpen
   :project: pal

.. doxygenfunction:: DkStreamWaitForClient
   :project: pal

.. doxygenfunction:: DkStreamRead
   :project: pal

.. doxygenfunction:: DkStreamWrite
   :project: pal

.. doxygenfunction:: DkStreamDelete
   :project: pal

.. doxygenfunction:: DkStreamMap
   :project: pal

.. doxygenfunction:: DkStreamUnmap
   :project: pal

.. doxygenfunction:: DkStreamSetLength
   :project: pal

.. doxygenfunction:: DkStreamFlush
   :project: pal

.. doxygenfunction:: DkSendHandle
   :project: pal

.. doxygenfunction:: DkReceiveHandle
   :project: pal

.. doxygenfunction:: DkStreamAttributesQuery
   :project: pal

.. doxygentypedef:: PAL_STREAM_ATTR
   :project: pal
.. doxygenstruct:: _PAL_STREAM_ATTR
   :project: pal

.. doxygenfunction:: DkStreamAttributesQueryByHandle
   :project: pal

.. doxygenfunction:: DkStreamAttributesSetByHandle
   :project: pal

.. doxygenfunction:: DkStreamGetName
   :project: pal

.. doxygenfunction:: DkStreamChangeName
   :project: pal


Flags used for stream manipulation
""""""""""""""""""""""""""""""""""

.. doxygenenum:: PAL_ACCESS
   :project: pal

.. doxygenenum:: PAL_SHARE
   :project: pal

.. doxygenenum:: PAL_CREATE
   :project: pal

.. doxygenenum:: PAL_OPTION
   :project: pal

.. doxygenenum:: PAL_DELETE
   :project: pal


Thread creation
^^^^^^^^^^^^^^^

The ABI supports multithreading through five calls to create, sleep, yield the
scheduler quantum for, resume execution of, and terminate threads, as well as
seven calls to create, signal, and block on synchronization objects.

.. doxygenfunction:: DkThreadCreate
   :project: pal

.. doxygenfunction:: DkThreadYieldExecution
   :project: pal

.. doxygenfunction:: DkThreadExit
   :project: pal

.. doxygenfunction:: DkThreadResume
   :project: pal


Exception handling
^^^^^^^^^^^^^^^^^^

.. doxygenenum:: PAL_EVENT
   :project: pal

.. doxygentypedef:: PAL_CONTEXT
   :project: pal
.. doxygenstruct:: PAL_CONTEXT
   :project: pal
   :members:

.. doxygentypedef:: PAL_EVENT_HANDLER
   :project: pal

.. doxygenfunction:: DkSetExceptionHandler
   :project: pal


Synchronization
^^^^^^^^^^^^^^^

.. doxygendefine:: NO_TIMEOUT
   :project: pal

.. doxygenfunction:: DkEventCreate
   :project: pal

.. doxygenfunction:: DkEventSet
   :project: pal

.. doxygenfunction:: DkEventClear
   :project: pal

.. doxygenfunction:: DkEventWait
   :project: pal

Objects
^^^^^^^

.. doxygenfunction:: DkStreamsWaitEvents
   :project: pal

.. doxygenfunction:: DkObjectClose
   :project: pal

Miscellaneous
^^^^^^^^^^^^^

The ABI includes seven assorted calls to get wall clock time, generate
cryptographically-strong random bits, flush portions of instruction caches,
increment and decrement the reference counts on objects shared between threads,
and to obtain an attestation report and quote.

.. doxygenfunction:: DkDebugLog
   :project: pal

.. doxygenfunction:: DkGetPalControl
   :project: pal

.. doxygenfunction:: DkSystemTimeQuery
   :project: pal

.. doxygenfunction:: DkRandomBitsRead
   :project: pal

.. doxygenfunction:: DkSegmentRegisterGet
   :project: pal

.. doxygenfunction:: DkSegmentRegisterSet
   :project: pal

.. doxygenenum:: PAL_SEGMENT
   :project: pal

.. doxygenfunction:: DkMemoryAvailableQuota
   :project: pal

.. doxygenfunction:: DkCpuIdRetrieve
   :project: pal

.. doxygenfunction:: DkAttestationReport
   :project: pal

.. doxygenfunction:: DkAttestationQuote
   :project: pal

.. doxygenfunction:: DkSetProtectedFilesKey
   :project: pal
