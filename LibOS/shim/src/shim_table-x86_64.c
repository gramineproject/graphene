/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * This file contains the system call table.
 */

#include "shim_internal.h"
#include "shim_table.h"

/* TODO: assign each function to appropriate index to avoid mistakes, like:
 * `[__NR_read] = (shim_fp)shim_do_read,` */
shim_fp shim_table[LIBOS_SYSCALL_BOUND] = {
    (shim_fp)shim_do_read,
    (shim_fp)shim_do_write,
    (shim_fp)shim_do_open,
    (shim_fp)shim_do_close,
    (shim_fp)shim_do_stat,
    (shim_fp)shim_do_fstat,
    (shim_fp)shim_do_lstat,
    (shim_fp)shim_do_poll,
    (shim_fp)shim_do_lseek,
    (shim_fp)shim_do_mmap,
    (shim_fp)shim_do_mprotect,
    (shim_fp)shim_do_munmap,
    (shim_fp)shim_do_brk,
    (shim_fp)shim_do_rt_sigaction,
    (shim_fp)shim_do_rt_sigprocmask,
    (shim_fp)shim_do_rt_sigreturn,
    (shim_fp)shim_do_ioctl,
    (shim_fp)shim_do_pread64,
    (shim_fp)shim_do_pwrite64,
    (shim_fp)shim_do_readv,
    (shim_fp)shim_do_writev,
    (shim_fp)shim_do_access,
    (shim_fp)shim_do_pipe,
    (shim_fp)shim_do_select,
    (shim_fp)shim_do_sched_yield,
    (shim_fp)0, // shim_do_mremap
    (shim_fp)0, // shim_do_msync,
    (shim_fp)shim_do_mincore,
    (shim_fp)shim_do_madvise,
    (shim_fp)0, // shim_do_shmget
    (shim_fp)0, // shim_do_shmat
    (shim_fp)0, // shim_do_shmctl
    (shim_fp)shim_do_dup,
    (shim_fp)shim_do_dup2,
    (shim_fp)shim_do_pause,
    (shim_fp)shim_do_nanosleep,
    (shim_fp)shim_do_getitimer,
    (shim_fp)shim_do_alarm,
    (shim_fp)shim_do_setitimer,
    (shim_fp)shim_do_getpid,
    (shim_fp)shim_do_sendfile,
    (shim_fp)shim_do_socket,
    (shim_fp)shim_do_connect,
    (shim_fp)shim_do_accept,
    (shim_fp)shim_do_sendto,
    (shim_fp)shim_do_recvfrom,
    (shim_fp)shim_do_sendmsg,
    (shim_fp)shim_do_recvmsg,
    (shim_fp)shim_do_shutdown,
    (shim_fp)shim_do_bind,
    (shim_fp)shim_do_listen,
    (shim_fp)shim_do_getsockname,
    (shim_fp)shim_do_getpeername,
    (shim_fp)shim_do_socketpair,
    (shim_fp)shim_do_setsockopt,
    (shim_fp)shim_do_getsockopt,
    (shim_fp)shim_do_clone,
    (shim_fp)shim_do_fork,
    (shim_fp)shim_do_vfork,
    (shim_fp)shim_do_execve,
    (shim_fp)shim_do_exit,
    (shim_fp)shim_do_wait4,
    (shim_fp)shim_do_kill,
    (shim_fp)shim_do_uname,
    (shim_fp)shim_do_semget,
    (shim_fp)shim_do_semop,
    (shim_fp)shim_do_semctl,
    (shim_fp)0, // shim_do_shmdt
    (shim_fp)shim_do_msgget,
    (shim_fp)shim_do_msgsnd,
    (shim_fp)shim_do_msgrcv,
    (shim_fp)shim_do_msgctl,
    (shim_fp)shim_do_fcntl,
    (shim_fp)0, // shim_do_flock
    (shim_fp)shim_do_fsync,
    (shim_fp)shim_do_fdatasync,
    (shim_fp)shim_do_truncate,
    (shim_fp)shim_do_ftruncate,
    (shim_fp)shim_do_getdents,
    (shim_fp)shim_do_getcwd,
    (shim_fp)shim_do_chdir,
    (shim_fp)shim_do_fchdir,
    (shim_fp)shim_do_rename,
    (shim_fp)shim_do_mkdir,
    (shim_fp)shim_do_rmdir,
    (shim_fp)shim_do_creat,
    (shim_fp)0, // shim_do_link
    (shim_fp)shim_do_unlink,
    (shim_fp)0, // shim_do_symlink
    (shim_fp)shim_do_readlink,
    (shim_fp)shim_do_chmod,
    (shim_fp)shim_do_fchmod,
    (shim_fp)shim_do_chown,
    (shim_fp)shim_do_fchown,
    (shim_fp)0, // shim_do_lchown
    (shim_fp)shim_do_umask,
    (shim_fp)shim_do_gettimeofday,
    (shim_fp)shim_do_getrlimit,
    (shim_fp)0, // shim_do_getrusage
    (shim_fp)0, // shim_do_sysinfo
    (shim_fp)0, // shim_do_times
    (shim_fp)0, // shim_do_ptrace
    (shim_fp)shim_do_getuid,
    (shim_fp)0, // shim_do_syslog
    (shim_fp)shim_do_getgid,
    (shim_fp)shim_do_setuid,
    (shim_fp)shim_do_setgid,
    (shim_fp)shim_do_geteuid,
    (shim_fp)shim_do_getegid,
    (shim_fp)shim_do_setpgid,
    (shim_fp)shim_do_getppid,
    (shim_fp)shim_do_getpgrp,
    (shim_fp)shim_do_setsid,
    (shim_fp)0, // shim_do_setreuid
    (shim_fp)0, // shim_do_setregid
    (shim_fp)shim_do_getgroups,
    (shim_fp)shim_do_setgroups,
    (shim_fp)0, // shim_do_setresuid
    (shim_fp)0, // shim_do_getresuid
    (shim_fp)0, // shim_do_setresgid
    (shim_fp)0, // shim_do_getresgid
    (shim_fp)shim_do_getpgid,
    (shim_fp)0, // shim_do_setfsuid
    (shim_fp)0, // shim_do_setfsgid
    (shim_fp)shim_do_getsid,
    (shim_fp)0, // shim_do_capget
    (shim_fp)0, // shim_do_capset
    (shim_fp)shim_do_rt_sigpending,
    (shim_fp)0, // shim_do_rt_sigtimedwait
    (shim_fp)0, // shim_do_rt_sigqueueinfo
    (shim_fp)shim_do_rt_sigsuspend,
    (shim_fp)shim_do_sigaltstack,
    (shim_fp)0, // shim_do_utime
    (shim_fp)shim_do_mknod,
    (shim_fp)0, // shim_do_uselib
    (shim_fp)0, // shim_do_personality
    (shim_fp)0, // shim_do_ustat
    (shim_fp)shim_do_statfs,
    (shim_fp)shim_do_fstatfs,
    (shim_fp)0, // shim_do_sysfs
    (shim_fp)shim_do_getpriority,
    (shim_fp)shim_do_setpriority,
    (shim_fp)shim_do_sched_setparam,
    (shim_fp)shim_do_sched_getparam,
    (shim_fp)shim_do_sched_setscheduler,
    (shim_fp)shim_do_sched_getscheduler,
    (shim_fp)shim_do_sched_get_priority_max,
    (shim_fp)shim_do_sched_get_priority_min,
    (shim_fp)shim_do_sched_rr_get_interval,
    (shim_fp)0, // shim_do_mlock
    (shim_fp)0, // shim_do_munlock
    (shim_fp)0, // shim_do_mlockall
    (shim_fp)0, // shim_do_munlockall
    (shim_fp)0, // shim_do_vhangup
    (shim_fp)0, // shim_do_modify_ldt
    (shim_fp)0, // shim_do_pivot_root
    (shim_fp)0, // shim_do__sysctl
    (shim_fp)0, // shim_do_prctl
    (shim_fp)shim_do_arch_prctl,
    (shim_fp)0, // shim_do_adjtimex
    (shim_fp)shim_do_setrlimit,
    (shim_fp)shim_do_chroot,
    (shim_fp)0, // shim_do_sync
    (shim_fp)0, // shim_do_acct
    (shim_fp)0, // shim_do_settimeofday
    (shim_fp)0, // shim_do_mount
    (shim_fp)0, // shim_do_umount2
    (shim_fp)0, // shim_do_swapon
    (shim_fp)0, // shim_do_swapoff
    (shim_fp)0, // shim_do_reboot
    (shim_fp)shim_do_sethostname,
    (shim_fp)shim_do_setdomainname,
    (shim_fp)0, // shim_do_iopl
    (shim_fp)0, // shim_do_ioperm
    (shim_fp)0, // shim_do_create_module
    (shim_fp)0, // shim_do_init_module
    (shim_fp)0, // shim_do_delete_module
    (shim_fp)0,  // shim_get_kernel_syms,
    (shim_fp)0, // shim_do_query_module
    (shim_fp)0, // shim_do_quotactl
    (shim_fp)0,  // shim_nfsservctl,
    (shim_fp)0,  // shim_getpmsg,
    (shim_fp)0,  // shim_putpmsg,
    (shim_fp)0,  // shim_afs_syscall,
    (shim_fp)0,  // shim_tuxcall,
    (shim_fp)0,  // shim_security,
    (shim_fp)shim_do_gettid,
    (shim_fp)0, // shim_do_readahead
    (shim_fp)0, // shim_do_setxattr
    (shim_fp)0, // shim_do_lsetxattr
    (shim_fp)0, // shim_do_fsetxattr
    (shim_fp)0, // shim_do_getxattr
    (shim_fp)0, // shim_do_lgetxattr
    (shim_fp)0, // shim_do_fgetxattr
    (shim_fp)0, // shim_do_listxattr
    (shim_fp)0, // shim_do_llistxattr
    (shim_fp)0, // shim_do_flistxattr
    (shim_fp)0, // shim_do_removexattr
    (shim_fp)0, // shim_do_lremovexattr
    (shim_fp)0, // shim_do_fremovexattr
    (shim_fp)shim_do_tkill,
    (shim_fp)shim_do_time,
    (shim_fp)shim_do_futex,
    (shim_fp)shim_do_sched_setaffinity,
    (shim_fp)shim_do_sched_getaffinity,
    (shim_fp)0, // shim_do_set_thread_area
    (shim_fp)0, // shim_do_io_setup
    (shim_fp)0, // shim_do_io_destroy
    (shim_fp)0, // shim_do_io_getevents
    (shim_fp)0, // shim_do_io_submit
    (shim_fp)0, // shim_do_io_cancel
    (shim_fp)0, // shim_do_get_thread_area
    (shim_fp)0, // shim_do_lookup_dcookie
    (shim_fp)shim_do_epoll_create,
    (shim_fp)0,  // shim_epoll_ctl_old,
    (shim_fp)0,  // shim_epoll_wait_old,
    (shim_fp)0, // shim_do_remap_file_pages
    (shim_fp)shim_do_getdents64,
    (shim_fp)shim_do_set_tid_address,
    (shim_fp)0, // shim_do_restart_syscall
    (shim_fp)shim_do_semtimedop,
    (shim_fp)0, // shim_do_fadvise64
    (shim_fp)0, // shim_do_timer_create
    (shim_fp)0, // shim_do_timer_settime
    (shim_fp)0, // shim_do_timer_gettime
    (shim_fp)0, // shim_do_timer_getoverrun
    (shim_fp)0, // shim_do_timer_delete
    (shim_fp)0, // shim_do_clock_settime
    (shim_fp)shim_do_clock_gettime,
    (shim_fp)shim_do_clock_getres,
    (shim_fp)shim_do_clock_nanosleep,
    (shim_fp)shim_do_exit_group,
    (shim_fp)shim_do_epoll_wait,
    (shim_fp)shim_do_epoll_ctl,
    (shim_fp)shim_do_tgkill,
    (shim_fp)0, // shim_do_utimes
    (shim_fp)0,  // shim_vserver,
    (shim_fp)shim_do_mbind,
    (shim_fp)0, // shim_do_set_mempolicy
    (shim_fp)0, // shim_do_get_mempolicy
    (shim_fp)0, // shim_do_mq_open
    (shim_fp)0, // shim_do_mq_unlink
    (shim_fp)0, // shim_do_mq_timedsend
    (shim_fp)0, // shim_do_mq_timedreceive
    (shim_fp)0, // shim_do_mq_notify
    (shim_fp)0, // shim_do_mq_getsetattr
    (shim_fp)0,  // shim_kexec_load,
    (shim_fp)shim_do_waitid,
    (shim_fp)0,  // shim_add_key,
    (shim_fp)0,  // shim_request_key,
    (shim_fp)0,  // shim_keyctl,
    (shim_fp)0, // shim_do_ioprio_set
    (shim_fp)0, // shim_do_ioprio_get
    (shim_fp)0, // shim_do_inotify_init
    (shim_fp)0, // shim_do_inotify_add_watch
    (shim_fp)0, // shim_do_inotify_rm_watch
    (shim_fp)0, // shim_do_migrate_pages
    (shim_fp)shim_do_openat,
    (shim_fp)shim_do_mkdirat,
    (shim_fp)shim_do_mknodat,
    (shim_fp)shim_do_fchownat,
    (shim_fp)0, // shim_do_futimesat
    (shim_fp)shim_do_newfstatat,
    (shim_fp)shim_do_unlinkat,
    (shim_fp)shim_do_renameat,
    (shim_fp)0, // shim_do_linkat
    (shim_fp)0, // shim_do_symlinkat
    (shim_fp)shim_do_readlinkat,
    (shim_fp)shim_do_fchmodat,
    (shim_fp)shim_do_faccessat,
    (shim_fp)shim_do_pselect6,
    (shim_fp)shim_do_ppoll,
    (shim_fp)0, // shim_do_unshare
    (shim_fp)shim_do_set_robust_list,
    (shim_fp)shim_do_get_robust_list,
    (shim_fp)0, // shim_do_splice
    (shim_fp)0, // shim_do_tee
    (shim_fp)0, // shim_do_sync_file_range
    (shim_fp)0, // shim_do_vmsplice
    (shim_fp)0, // shim_do_move_pages
    (shim_fp)0, // shim_do_utimensat
    (shim_fp)shim_do_epoll_pwait,
    (shim_fp)0, // shim_do_signalfd
    (shim_fp)0, // shim_do_timerfd_create
    (shim_fp)shim_do_eventfd,
    (shim_fp)0, // shim_do_fallocate
    (shim_fp)0, // shim_do_timerfd_settime
    (shim_fp)0, // shim_do_timerfd_gettime
    (shim_fp)shim_do_accept4,
    (shim_fp)0, // shim_do_signalfd4
    (shim_fp)shim_do_eventfd2,
    (shim_fp)shim_do_epoll_create1,
    (shim_fp)shim_do_dup3,
    (shim_fp)shim_do_pipe2,
    (shim_fp)0, // shim_do_inotify_init1
    (shim_fp)0, // shim_do_preadv
    (shim_fp)0, // shim_do_pwritev
    (shim_fp)0, // shim_do_rt_tgsigqueueinfo
    (shim_fp)0, // shim_do_perf_event_open
    (shim_fp)shim_do_recvmmsg,
    (shim_fp)0, // shim_do_fanotify_init
    (shim_fp)0, // shim_do_fanotify_mark
    (shim_fp)shim_do_prlimit64,
    (shim_fp)0, // shim_do_name_to_handle_at
    (shim_fp)0, // shim_do_open_by_handle_at
    (shim_fp)0, // shim_do_clock_adjtime
    (shim_fp)0, // shim_do_syncfs
    (shim_fp)shim_do_sendmmsg,
    (shim_fp)0, // shim_do_setns
    (shim_fp)shim_do_getcpu,
    (shim_fp)0, // shim_do_process_vm_readv
    (shim_fp)0, // shim_do_process_vm_writev
    (shim_fp)0, // shim_do_kcmp
    (shim_fp)0, // shim_do_finit_module
    (shim_fp)0, // shim_do_sched_setattr
    (shim_fp)0, // shim_do_sched_getattr
    (shim_fp)0, // shim_do_renameat2
    (shim_fp)0, // shim_do_seccomp
    (shim_fp)shim_do_getrandom,
    (shim_fp)0, // shim_do_memfd_create
    (shim_fp)0, // shim_do_kexec_file_load
    (shim_fp)0, // shim_do_bpf
    (shim_fp)0, // shim_do_execveat
    (shim_fp)0, // shim_do_userfaultfd
    (shim_fp)0, // shim_do_membarrier
    (shim_fp)0, // shim_do_mlock2
    (shim_fp)0, // shim_do_copy_file_range
    (shim_fp)0, // shim_do_preadv2
    (shim_fp)0, // shim_do_pwritev2
    (shim_fp)0, // shim_do_pkey_mprotect
    (shim_fp)0, // shim_do_pkey_alloc
    (shim_fp)0, // shim_do_pkey_free
    (shim_fp)0, // shim_do_statx
    (shim_fp)0, // shim_do_io_pgetevents
    (shim_fp)0, // shim_do_rseq
    (shim_fp)0, // shim_do_pidfd_send_signal
    (shim_fp)0, // shim_do_io_uring_setup
    (shim_fp)0, // shim_do_io_uring_enter
    (shim_fp)0, // shim_do_io_uring_register
};
