Implementing new system call
============================

.. highlight:: c

1. Define interface of system call
----------------------------------

For example, assume we are implementing :manpage:`sched_setaffinity(2)`. You
must find the definition of ``sched_setaffinity`` in
:file:`shim_syscalls.c`, which will be the following code::

   SHIM_SYSCALL_RETURN_ENOSYS(sched_setaffinity, 3, long, pid_t, pid, unsigned int,
                              len, unsigned long*, user_mask_ptr)

Change this line to ``DEFINE_SHIM_SYSCALL(...)`` to name the function that
implements this system call: ``shim_do_sched_setaffinity`` (this is the naming
convention, please follow it)::

   DEFINE_SHIM_SYSCALL(sched_setaffinity, 3, shim_do_sched_setaffinity, long, pid_t, pid,
                       unsigned int, len, unsigned long*, user_mask_ptr)


2. Add definitions to system call table
---------------------------------------

To implement system call ``sched_setaffinity``, two functions need to be defined
in :file:`shim_table.h`: ``__shim_sched_setaffinity`` and
``shim_do_sched_setaffinity``. The first one should already be defined. Add the
second in respect to the system call you are implementing, with the same
prototype as defined in :file:`shim_syscalls.c`::

   long shim_do_sched_setaffinity(pid_t pid, unsigned int len, unsigned long* user_mask_ptr);

3. Implement system call
------------------------

You can add the function body of ``shim_do_sysinfo`` (or the function name defined
earlier) in a new source file or any existing source file in
:file:`LibOS/shim/src/sys`.

For example, in :file:`LibOS/shim/src/sys/shim_sched.c`::

   long shim_do_sched_setaffinity(pid_t pid, unsigned int len, unsigned long* user_mask_ptr) {
      /* code for implementing the semantics of sched_setaffinity */
   }

4. Add new PAL Calls (optional)
-------------------------------

The concept of Graphene library OS is to keep the PAL interface as simple as
possible. So, you should not add new PAL calls if the features can be fully
implemented inside the library OS using the existing PAL calls. However,
sometimes the OS features needed involve low-level operations inside the host OS
and cannot be emulated inside the library OS. Therefore, you may have to add
a |~| few new PAL calls to the existing interface.

To add a |~| new PAL call, first modify :file:`Pal/include/pal/pal.h`. Define
the PAL call in a |~| platform-independent way::

   PAL_BOL DkThreadSetCPUAffinity(PAL_NUM cpu_num, PAL_IDX* cpu_indexes);

Make sure you use the PAL-specific data types, including :type:`PAL_BOL`,
:type:`PAL_NUM`, :type:`PAL_PTR`, :type:`PAL_FLG`, :type:`PAL_IDX`, and
:type:`PAL_STR`. The naming convention of a |~| PAL call is to start functions
with the ``Dk`` prefix, followed by a comprehensive name describing the purpose
of the PAL call.

5. Export new PAL calls from PAL binaries (optional)
----------------------------------------------------

For each directory in :file:`PAL/host/`, there is a :file:`pal.map` file. This
file lists all the symbols accessible to the library OS. The new PAL call needs
to be listed here in order to be used by your system call implementation.

6. Implement new PAL calls (optional)
-------------------------------------

.. todo::

   (Not finished...)
