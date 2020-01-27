Implementing A New System Call in Graphene
==========================================

Step 1: Define the Interface of System Call and Name the Function in :file:`LibOS/shim/src/shim_syscalls.c`
-----------------------------------------------------------------------------------------------------------

For example, assume we are implementing :manpage:`sched_setaffinity(2)`. You
must find the definition of ``sched_setaffinity`` in
:file:`shim_syscalls.c`, which will be the following code::

   SHIM_SYSCALL_PASSTHROUGH(sched_setaffinity, 3, int, pid_t, pid, size_t, len,
                           __kernel_cpu_set_t*, user_mask_ptr)

Change this line to ``DEFINE_SHIM_SYSCALL(...)`` to name the function that
implements this system call: ``shim_do_sched_setaffinity`` (this is the naming
convention, please follow it).

::

   DEFINE_SHIM_SYSCALL(sched_setaffinity, 3, shim_do_sched_setaffinity, int, pid_t, pid, size_t, len,
                       __kernel_cpu_set_t*, user_mask_ptr)


Step 2: Add Definitions to :file:`LibOS/shim/include/shim_table.h`
------------------------------------------------------------------

To implement system call ``sched_setaffinity``, three functions need to be
defined in :file:`shim_table.h`: ``__shim_sched_setaffinity``,
``shim_sched_setaffinity``, and ``shim_do_sched_setaffinity``. The first two
should already be defined. Add the third in respect to the system call you are
implementing, with the same prototype as defined in :file:`shim_syscalls.c`::

   int shim_do_sched_setaffinity(pid_t pid, size_t len, __kernel_cpu_set_t* user_mask_ptr);

Step 3: Implement the System Call under :file:`LibOS/shim/src/sys`
------------------------------------------------------------------

You can add the function body of ``shim_do_sysinfo`` (or the function name defined
earlier) in a new source file or any existing source file in
:file:`LibOS/shim/src/sys`.

For example, in :file:`LibOS/shim/src/sys/shim_sched.c`::

   int shim_do_sched_setaffinity(pid_t pid, size_t len, __kernel_cpu_set_t* user_mask_ptr) {
      /* code for implementing the semantics of sched_setaffinity */
   }

Step 4 (Optional): Add New PAL Calls if Necessary for the System Call
---------------------------------------------------------------------

The concept of Graphene library OS is to keep the PAL interface as simple as
possible. So, you should not add new PAL calls if the features can be fully
implemented inside the library OS using the existing PAL calls. However,
sometimes the OS features needed involve low-level operations inside the host OS
and cannot be emulated inside the library OS. Therefore, you may have to add
a |~| few new PAL calls to the existing interface.

To add a |~| new PAL call, first modify :file:`Pal/include/pal/pal.h`. Define
the PAL call in a |~| platform-independent way.

::

   PAL_BOL DkThreadSetCPUAffinity(PAL_NUM cpu_num, PAL_IDX* cpu_indexes);

Make sure you use the PAL-specific data types, including :type:`PAL_BOL`,
:type:`PAL_NUM`, :type:`PAL_PTR`, :type:`PAL_FLG`, :type:`PAL_IDX`, and
:type:`PAL_STR`. The naming convention of a |~| PAL call is to start functions
with the ``Dk`` prefix, followed by a comprehensive name describing the purpose
of the PAL call.

Step 5 (Optional): Export the new PAL call from the PAL binaries
----------------------------------------------------------------

For each directory in :file:`PAL/host/`, there is a :file:`pal.map` file. This
file lists all the symbols accessible to the library OS. The new PAL call needs
to be listed here in order to be used by your system call implementation.

Step 6 (Optional): Implementing the New PAL Call in :file:`PAL/src`
-------------------------------------------------------------------

.. todo::

   (Not finished...)
