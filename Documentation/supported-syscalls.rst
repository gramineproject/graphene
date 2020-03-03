Supported System Calls in Graphene
==================================

.. note::

   This document is outdated. Please :doc:`send patches <devel/contributing>`
   with corrections.

The following is a list of system calls that are currently implemented.

System Calls that are Fully Implemented
---------------------------------------

System Calls that Require Multi-process Coordination
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Process creation (fork/vfork)
* execve
* Process/thread termination (exit/exit_group)
* Waiting for process/thread (wait4/waitid)
* Signaling (kill/tkill/tgkill)
* System V IPC semaphore (semget/semop/semtimedop/semctl)
* System V IPC message queue (msgget/msgsnd/msgrcv)

System calls that require no multi-process coordination
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* File open/close (open/openat/creat/close)
* File descriptor access (read/write/readv/writev/pread64/pwrite64)
* File/file descriptor attributes (stat/fstat/lstat)
* File permission (access/faccessat)
* File descriptor polling (poll/ppoll)
* File descriptor selecting (select/pselect)
* Create/change/remove memory mapping (mmap/mprotect/munmap)
* Signal handling (rt_sigaction/rt_sigprocmask/rt_sigreturn)
* Duplicating file descriptors (dup/dup2/dup3)
* Pipe/socket pair creation (pipe/pipe2/socketpair)
* Scheduler yielding (sched_yield)
* Pausing/sleeping (pause/nanosleep)
* Timer/alarm (alarm/setitimer/getitimer)
* Creation/connection of TCP/UDP socket (socket/connect/accept/accept4/listen)
* Sending/receiving network packets (sendto/recvfrom/sendmsg/recvmsg)
* Tear down socket (shutdown)
* Getting socket address (getsockname/getpeername)
* Socket options (getsockopt/setsockopt)
* System information (uname)
* Process credentials (getpid/gettid/getpgid/getpgrp)
* User credentials (getuid/setuid/getgid/setgid)
* Effective user credentials (geteuid/seteuid/getegid/setegid)
* Program break (brk)
* File flushing (fsync)
* File offset (lseek)
* File truncating (truncate/ftruncate)
* File copy (sendfile)
* Current directory (getcwd/chdir/fchdir)
* Listing directory (getdents/getdents64)
* Creating/deleting directory (mkdir/rmdir/mkdirat)
* Changing file metadata (rename/renameat/unlink/unlinkat/chmod/fchmod/fchmodat)
* Query system time (gettimeofday/time/clock_gettime)
* Asynchronous file descriptor polling (epoll_create/epoll_create1/epoll_wait/epoll_ctl/epoll_pwait)
* Changing thread metadata (chroot/umask)
* Futex and related system calls (futex/set_tid_address/set_robust_list/get_robust_list)
* Thread-state (arch_prctl)


System Calls that are Partially Implemented
-------------------------------------------

* ioctl

  Currently only FIONREAD is supported for the ioctl system call.

* fcntl
  - Supported: Duplicate FDs (F_DUPFD/F_DUPFD_CLOEXEC), Set FD flags (F_GETFD/F_SETFD), Set file flags (F_GETFL/F_SETFL)
  - Unsupported: File locking (F_SETLK/F_SETLKW/F_GETLK)

* clone

  The Linux clone system call is ubiquitously used for creation of processes and threads. However,
  in Graphene, we only use the clone system call for thread creation. Process creation is
  implemented as the fork system call. In practice, it is quite rare for applications to use
  methods that are not forking to create processes.

  The namespace options (CLONE_FS, CLONE_NEWIPC, CLONE_NEWNET, etc) are currently not supported.

* msgctl

  Only IPC_RMID is supported.

* setpgid/setsid

  These two system calls set the process credentials but do not coordinate any cross-process state.

* bind

  Binding on path (UNIX socket) is only supported locally in the process.

* readlink

  Symbolic links are not supported. Readlink will simply resolve absolute paths.

* getrlimit

  Returns the static values of RLIMIT_NOFILE, RLIMIT_RSS, RLIMIT_AS, RLIMIT_STACK.
