/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains code for parsing system call arguments for debug purpose.
 */

#include <asm/fcntl.h>
#include <asm/ioctls.h>
#include <asm/mman.h>
#include <asm/unistd.h>
#include <errno.h>
#include <linux/fcntl.h>
#include <linux/futex.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/sched.h>
#include <linux/un.h>
#include <linux/wait.h>

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "shim_internal.h"
#include "shim_syscalls.h"
#include "shim_table.h"
#include "shim_tcb.h"
#include "shim_thread.h"
#include "shim_utils.h"
#include "shim_vma.h"
#include "stat.h"

static void parse_open_flags(va_list*);
static void parse_open_mode(va_list*);
static void parse_access_mode(va_list*);
static void parse_clone_flags(va_list*);
static void parse_mmap_prot(va_list*);
static void parse_mmap_flags(va_list*);
static void parse_exec_args(va_list*);
static void parse_exec_envp(va_list*);
static void parse_pipe_fds(va_list*);
static void parse_signum(va_list*);
static void parse_sigmask(va_list*);
static void parse_sigprocmask_how(va_list*);
static void parse_madvise_behavior(va_list* ap);
static void parse_timespec(va_list*);
static void parse_sockaddr(va_list*);
static void parse_domain(va_list*);
static void parse_socktype(va_list*);
static void parse_futexop(va_list*);
static void parse_ioctlop(va_list*);
static void parse_fcntlop(va_list*);
static void parse_seek(va_list*);
static void parse_at_fdcwd(va_list*);
static void parse_wait_options(va_list*);
static void parse_waitid_which(va_list*);
static void parse_getrandom_flags(va_list*);

struct parser_table {
    int slow;
    int stop;
    void (*parser[6])(va_list*);
} syscall_parser_table[LIBOS_SYSCALL_BOUND] =
    {
        [__NR_read]     = {.slow = 1, .parser = {NULL}},
        [__NR_write]    = {.slow = 1, .parser = {NULL}},
        [__NR_open]     = {.slow = 1, .parser = {NULL, &parse_open_flags, &parse_open_mode}},
        [__NR_close]    = {.slow = 0, .parser = {NULL}},
        [__NR_stat]     = {.slow = 0, .parser = {NULL}},
        [__NR_fstat]    = {.slow = 0, .parser = {NULL}},
        [__NR_lstat]    = {.slow = 0, .parser = {NULL}},
        [__NR_poll]     = {.slow = 1, .parser = {NULL}},
        [__NR_lseek]    = {.slow = 0, .parser = {NULL, NULL, &parse_seek}},
        [__NR_mmap]     = {.slow = 1, .parser = {NULL, NULL, &parse_mmap_prot, &parse_mmap_flags}},
        [__NR_mprotect] = {.slow = 1, .parser = {NULL, NULL, &parse_mmap_prot}},
        [__NR_munmap]   = {.slow = 1, .parser = {NULL}},
        [__NR_brk]      = {.slow = 0, .parser = {NULL}},
        [__NR_rt_sigaction]   = {.slow = 0, .parser = {&parse_signum}},
        [__NR_rt_sigprocmask] = {.slow = 0,
                                 .parser = {&parse_sigprocmask_how, &parse_sigmask, &parse_sigmask}},
        [__NR_rt_sigreturn]   = {.slow = 0, .parser = {NULL}},
        [__NR_ioctl]          = {.slow = 1, .parser = {NULL, &parse_ioctlop}},
        [__NR_pread64]        = {.slow = 1, .parser = {NULL}},
        [__NR_pwrite64]       = {.slow = 0, .parser = {NULL}},
        [__NR_readv]          = {.slow = 1, .parser = {NULL}},
        [__NR_writev]         = {.slow = 0, .parser = {NULL}},
        [__NR_access]         = {.slow = 0, .parser = {NULL, &parse_access_mode}},
        [__NR_pipe]           = {.slow = 0, .parser = {&parse_pipe_fds}},
        [__NR_select]         = {.slow = 1, .parser = {NULL}},
        [__NR_sched_yield] = {.slow = 0, .parser = {NULL}},
        [__NR_mremap]      = {.slow = 0, .parser = {NULL}},
        [__NR_msync]       = {.slow = 0, .parser = {NULL}},
        [__NR_mincore]     = {.slow = 0, .parser = {NULL}},
        [__NR_madvise]     = {.slow = 0, .parser = {NULL, NULL, &parse_madvise_behavior}},
        [__NR_shmget]      = {.slow = 0, .parser = {NULL}},
        [__NR_shmat]       = {.slow = 0, .parser = {NULL}},
        [__NR_shmctl]      = {.slow = 0, .parser = {NULL}},
        [__NR_dup]         = {.slow = 0, .parser = {NULL}},
        [__NR_dup2]        = {.slow = 0, .parser = {NULL}},
        [__NR_pause]       = {.slow = 1, .parser = {NULL}},
        [__NR_nanosleep]   = {.slow = 1, .parser = {&parse_timespec}},
        [__NR_getitimer]   = {.slow = 0, .parser = {NULL}},
        [__NR_alarm]       = {.slow = 0, .parser = {NULL}},
        [__NR_setitimer]   = {.slow = 0, .parser = {NULL}},
        [__NR_getpid]      = {.slow = 0, .parser = {NULL}},
        [__NR_sendfile]    = {.slow = 0, .parser = {NULL}},
        [__NR_socket]      = {.slow = 0, .parser = {&parse_domain, &parse_socktype}},
        [__NR_connect]     = {.slow = 1, .parser = {NULL, &parse_sockaddr}},
        [__NR_accept]      = {.slow = 1, .parser = {NULL}},
        [__NR_sendto]      = {.slow = 0, .parser = {NULL}},
        [__NR_recvfrom]    = {.slow = 0, .parser = {NULL}},
        [__NR_sendmsg]     = {.slow = 0, .parser = {NULL}},
        [__NR_recvmsg]     = {.slow = 1, .parser = {NULL}},
        [__NR_shutdown]    = {.slow = 0, .parser = {NULL}},
        [__NR_bind]        = {.slow = 0, .parser = {NULL}},
        [__NR_listen]      = {.slow = 0, .parser = {NULL}},
        [__NR_getsockname] = {.slow = 0, .parser = {NULL}},
        [__NR_getpeername] = {.slow = 0, .parser = {NULL}},
        [__NR_socketpair]  = {.slow = 0,
                              .stop = 3,
                              .parser = {&parse_domain, &parse_socktype, NULL, &parse_pipe_fds}},
        [__NR_setsockopt]  = {.slow = 0, .parser = {NULL}},
        [__NR_getsockopt]  = {.slow = 0, .parser = {NULL}},
        [__NR_clone]    = {.slow = 1, .parser = {&parse_clone_flags}},
        [__NR_fork]     = {.slow = 1, .parser = {NULL}},
        [__NR_vfork]    = {.slow = 1, .parser = {NULL}},
        [__NR_execve]   = {.slow   = 1,
                           .parser = {NULL, &parse_exec_args, &parse_exec_envp}},
        [__NR_exit]     = {.slow = 0, .parser = {NULL}},
        [__NR_wait4]    = {.slow = 1, .parser = {NULL, NULL, &parse_wait_options, NULL}},
        [__NR_kill]     = {.slow = 0, .parser = {NULL, &parse_signum, }},
        [__NR_uname]    = {.slow = 0, .parser = {NULL}},
        [__NR_semget]   = {.slow = 0, .parser = {NULL}},
        [__NR_semop]    = {.slow = 1, .parser = {NULL}},
        [__NR_semctl]   = {.slow = 0, .parser = {NULL}},
        [__NR_shmdt]    = {.slow = 0, .parser = {NULL}},
        [__NR_msgget]   = {.slow = 1, .parser = {NULL}},
        [__NR_msgsnd]   = {.slow = 1, .parser = {NULL}},
        [__NR_msgrcv]   = {.slow = 1, .parser = {NULL}},
        [__NR_msgctl]   = {.slow = 1, .parser = {NULL}},
        [__NR_fcntl]    = {.slow = 0, .parser = {NULL, &parse_fcntlop}},
        [__NR_flock]    = {.slow = 0, .parser = {NULL}},
        [__NR_fsync]    = {.slow = 0, .parser = {NULL}},
        [__NR_fdatasync] = {.slow = 0, .parser = {NULL}},
        [__NR_truncate]  = {.slow = 0, .parser = {NULL}},
        [__NR_ftruncate] = {.slow = 0, .parser = {NULL}},
        [__NR_getdents]  = {.slow = 0, .parser = {NULL}},
        [__NR_getcwd]   = {.slow = 0, .parser = {NULL}},
        [__NR_chdir]    = {.slow = 0, .parser = {NULL}},
        [__NR_fchdir]   = {.slow = 0, .parser = {NULL}},
        [__NR_rename]   = {.slow = 0, .parser = {NULL}},
        [__NR_mkdir]    = {.slow = 0, .parser = {NULL}},
        [__NR_rmdir]    = {.slow = 0, .parser = {NULL}},
        [__NR_creat]    = {.slow = 0, .parser = {NULL, &parse_open_mode}},
        [__NR_link]     = {.slow = 0, .parser = {NULL}},
        [__NR_unlink]   = {.slow = 0, .parser = {NULL}},
        [__NR_symlink]  = {.slow = 0, .parser = {NULL}},
        [__NR_readlink] = {.slow = 0, .parser = {NULL}},
        [__NR_chmod]    = {.slow = 0, .parser = {NULL}},
        [__NR_fchmod]   = {.slow = 0, .parser = {NULL}},
        [__NR_chown]    = {.slow = 0, .parser = {NULL}},
        [__NR_fchown]   = {.slow = 0, .parser = {NULL}},
        [__NR_lchown]   = {.slow = 0, .parser = {NULL}},
        [__NR_umask]    = {.slow = 0, .parser = {NULL}},
        [__NR_gettimeofday] = {.slow = 0, .parser = {NULL}},
        [__NR_getrlimit]    = {.slow = 0, .parser = {NULL}},
        [__NR_getrusage]    = {.slow = 0, .parser = {NULL}},
        [__NR_sysinfo]   = {.slow = 0, .parser = {NULL}},
        [__NR_times]     = {.slow = 0, .parser = {NULL}},
        [__NR_ptrace]    = {.slow = 0, .parser = {NULL}},
        [__NR_getuid]    = {.slow = 0, .parser = {NULL}},
        [__NR_syslog]    = {.slow = 0, .parser = {NULL}},
        [__NR_getgid]    =  {.slow = 0, .parser = {NULL}},
        [__NR_setuid]    = {.slow = 0, .parser = {NULL}},
        [__NR_setgid]    = {.slow = 0, .parser = {NULL}},
        [__NR_geteuid]   = {.slow = 0, .parser = {NULL}},
        [__NR_getegid]   = {.slow = 0, .parser = {NULL}},
        [__NR_setpgid]   = {.slow = 0, .parser = {NULL}},
        [__NR_getppid]   = {.slow = 0, .parser = {NULL}},
        [__NR_getpgrp]   = {.slow = 0, .parser = {NULL}},
        [__NR_setsid]    = {.slow = 0, .parser = {NULL}},
        [__NR_setreuid]  = {.slow = 0, .parser = {NULL}},
        [__NR_setregid]  = {.slow = 0, .parser = {NULL}},
        [__NR_getgroups] = {.slow = 0, .parser = {NULL}},
        [__NR_setgroups] = {.slow = 0, .parser = {NULL}},
        [__NR_setresuid] = {.slow = 0, .parser = {NULL}},
        [__NR_getresuid] = {.slow = 0, .parser = {NULL}},
        [__NR_setresgid] = {.slow = 0, .parser = {NULL}},
        [__NR_getresgid] = {.slow = 0, .parser = {NULL}},
        [__NR_getpgid]   = {.slow = 0, .parser = {NULL}},
        [__NR_setfsuid]  = {.slow = 0, .parser = {NULL}},
        [__NR_setfsgid]  = {.slow = 0, .parser = {NULL}},
        [__NR_getsid]    = {.slow = 0, .parser = {NULL}},
        [__NR_capget]    = {.slow = 0, .parser = {NULL}},
        [__NR_capset]    = {.slow = 0, .parser = {NULL}},
        [__NR_rt_sigpending]   = {.slow = 0, .parser = {NULL}},
        [__NR_rt_sigtimedwait] = {.slow = 0, .parser = {NULL}},
        [__NR_rt_sigqueueinfo] = {.slow = 0, .parser = {NULL}},
        [__NR_rt_sigsuspend]   = {.slow = 1, .parser = {NULL}},
        [__NR_sigaltstack]     = {.slow = 0, .parser = {NULL}},
        [__NR_utime]       = {.slow = 0, .parser = {NULL}},
        [__NR_mknod]       = {.slow = 0, .parser = {NULL, &parse_open_mode}},
        [__NR_uselib]      = {.slow = 0, .parser = {NULL}},
        [__NR_personality] = {.slow = 0, .parser = {NULL}},
        [__NR_ustat]       = {.slow = 0, .parser = {NULL}},
        [__NR_statfs]      = {.slow = 0, .parser = {NULL}},
        [__NR_fstatfs]     = {.slow = 0, .parser = {NULL}},
        [__NR_sysfs]       = {.slow = 0, .parser = {NULL}},
        [__NR_getpriority]    = {.slow = 0, .parser = {NULL}},
        [__NR_setpriority]    = {.slow = 0, .parser = {NULL}},
        [__NR_sched_setparam] = {.slow = 0, .parser = {NULL}},
        [__NR_sched_getparam] = {.slow = 0, .parser = {NULL}},
        [__NR_sched_setscheduler]     = {.slow = 0, .parser = {NULL}},
        [__NR_sched_getscheduler]     = {.slow = 0, .parser = {NULL}},
        [__NR_sched_get_priority_max] = {.slow = 0, .parser = {NULL}},
        [__NR_sched_get_priority_min] = {.slow = 0, .parser = {NULL}},
        [__NR_sched_rr_get_interval]  = {.slow = 0, .parser = {NULL}},
        [__NR_mlock]      = {.slow = 0, .parser = {NULL}},
        [__NR_munlock]    = {.slow = 0, .parser = {NULL}},
        [__NR_mlockall]   = {.slow = 0, .parser = {NULL}},
        [__NR_munlockall] = {.slow = 0, .parser = {NULL}},
        [__NR_vhangup]    = {.slow = 0, .parser = {NULL}},
        [__NR_modify_ldt] = {.slow = 0, .parser = {NULL}},
        [__NR_pivot_root] = {.slow = 0, .parser = {NULL}},
        [__NR__sysctl]    = {.slow = 0, .parser = {NULL}},
        [__NR_prctl]      = {.slow = 0, .parser = {NULL}},
#ifdef __NR_arch_prctl
        [__NR_arch_prctl] = {.slow = 0, .parser = {NULL}},
#endif
        [__NR_adjtimex]  = {.slow = 0, .parser = {NULL}},
        [__NR_setrlimit] = {.slow = 0, .parser = {NULL}},
        [__NR_chroot]    = {.slow = 0, .parser = {NULL}},
        [__NR_sync]      = {.slow = 0, .parser = {NULL}},
        [__NR_acct]      = {.slow = 0, .parser = {NULL}},
        [__NR_settimeofday]  = {.slow = 0, .parser = {NULL}},
        [__NR_mount]         = {.slow = 0, .parser = {NULL}},
        [__NR_umount2]       = { .slow = 0, .parser = {NULL}},
        [__NR_swapon]        = {.slow = 0, .parser = {NULL}},
        [__NR_swapoff]       = {.slow = 0, .parser = {NULL}},
        [__NR_reboot]        = {.slow = 0, .parser = {NULL}},
        [__NR_sethostname]   = {.slow = 0, .parser = {NULL}},
        [__NR_setdomainname] = {.slow = 0, .parser = {NULL}},
#ifdef __NR_iopl
        [__NR_iopl]          = {.slow = 0, .parser = {NULL}},
#endif
#ifdef __NR_ioperm
        [__NR_ioperm]        = {.slow = 0, .parser = {NULL}},
#endif
        [__NR_create_module]   = {.slow = 0, .parser = {NULL}},
        [__NR_init_module]     = {.slow = 0, .parser = {NULL}},
        [__NR_delete_module]   = {.slow = 0, .parser = {NULL}},
        [__NR_get_kernel_syms] = {.slow = 0, .parser = {NULL}},
        [__NR_query_module]    = {.slow = 0, .parser = {NULL}},
        [__NR_quotactl]     = {.slow = 0, .parser = {NULL}},
        [__NR_nfsservctl]   = {.slow = 0, .parser = {NULL}},
        [__NR_getpmsg]      = {.slow = 0, .parser = {NULL}},
        [__NR_putpmsg]      = {.slow = 0, .parser = {NULL}},
        [__NR_afs_syscall]  = {.slow = 0, .parser = {NULL}},
        [__NR_tuxcall]      = {.slow = 0, .parser = {NULL}},
        [__NR_security]     = {.slow = 0, .parser = {NULL}},
        [__NR_gettid]       = {.slow = 0, .parser = {NULL}},
        [__NR_readahead]    = {.slow = 0, .parser = {NULL}},
        [__NR_setxattr]     = {.slow = 0, .parser = {NULL}},
        [__NR_lsetxattr]    = {.slow = 0, .parser = {NULL}},
        [__NR_fsetxattr]    = {.slow = 0, .parser = {NULL}},
        [__NR_getxattr]     = {.slow = 0, .parser = {NULL}},
        [__NR_lgetxattr]    = {.slow = 0, .parser = {NULL}},
        [__NR_fgetxattr]    = {.slow = 0, .parser = {NULL}},
        [__NR_listxattr]    = {.slow = 0, .parser = {NULL}},
        [__NR_llistxattr]   = {.slow = 0, .parser = {NULL}},
        [__NR_flistxattr]   = {.slow = 0, .parser = {NULL}},
        [__NR_removexattr]  = {.slow = 0, .parser = {NULL}},
        [__NR_lremovexattr] = {.slow = 0, .parser = {NULL}},
        [__NR_fremovexattr] = {.slow = 0, .parser = {NULL}},
        [__NR_tkill]        = {.slow = 0, .parser = {NULL, &parse_signum}},
        [__NR_time]         = {.slow = 0, .parser = {NULL}},
        [__NR_futex]        = {.slow = 1, .parser = {NULL, &parse_futexop}},
        [__NR_sched_setaffinity] = {.slow = 0, .parser = {NULL}},
        [__NR_sched_getaffinity] = {.slow = 0, .parser = {NULL}},
#ifdef __NR_set_thread_area
        [__NR_set_thread_area]   = {.slow = 0, .parser = {NULL}},
#endif
        [__NR_io_setup]     = {.slow = 0, .parser = {NULL}},
        [__NR_io_destroy]   = {.slow = 0, .parser = {NULL}},
        [__NR_io_getevents] = {.slow = 0, .parser = {NULL}},
        [__NR_io_submit]    = {.slow = 0, .parser = {NULL}},
        [__NR_io_cancel]    = {.slow = 0, .parser = {NULL}},
#ifdef __NR_get_thread_area
        [__NR_get_thread_area]  = {.slow = 0, .parser = {NULL}},
#endif
        [__NR_lookup_dcookie]   = {.slow = 0, .parser = {NULL}},
        [__NR_epoll_create]     = {.slow = 0, .parser = {NULL}},
        [__NR_epoll_ctl_old]    = {.slow = 0, .parser = {NULL}},
        [__NR_epoll_wait_old]   = {.slow = 0, .parser = {NULL}},
        [__NR_remap_file_pages] = {.slow = 0, .parser = {NULL}},
        [__NR_getdents64]       = {.slow = 0, .parser = {NULL}},
        [__NR_set_tid_address]  = {.slow = 0, .parser = {NULL}},
        [__NR_restart_syscall]  = {.slow = 0, .parser = {NULL}},
        [__NR_semtimedop]       = {.slow = 0, .parser = {NULL}},
        [__NR_fadvise64]        = {.slow = 0, .parser = {NULL}},
        [__NR_timer_create]     = {.slow = 0, .parser = {NULL}},
        [__NR_timer_settime]    = {.slow = 0, .parser = {NULL}},
        [__NR_timer_gettime]    = {.slow = 0, .parser = {NULL}},
        [__NR_timer_getoverrun] = {.slow = 0, .parser = {NULL}},
        [__NR_timer_delete]     = {.slow = 0, .parser = {NULL}},
        [__NR_clock_settime]    = {.slow = 0, .parser = {NULL}},
        [__NR_clock_gettime]    = {.slow = 0, .parser = {NULL}},
        [__NR_clock_getres]     = {.slow = 0, .parser = {NULL}},
        [__NR_clock_nanosleep]  = {.slow = 0, .parser = {NULL}},
        [__NR_exit_group]       = {.slow = 0, .parser = {NULL}},
        [__NR_epoll_wait]       = {.slow = 1, .parser = {NULL}},
        [__NR_epoll_ctl]        = {.slow = 0, .parser = {NULL}},
        [__NR_tgkill]           = {.slow = 0, .parser = {NULL, NULL, &parse_signum}},
        [__NR_utimes]           = {.slow = 0, .parser = {NULL}},
#ifdef __NR_vserver
        [__NR_vserver]          = {.slow = 0, .parser = {NULL}},
#endif
        [__NR_mbind]           = {.slow = 0, .parser = {NULL}},
        [__NR_set_mempolicy]   = {.slow = 0, .parser = {NULL}},
        [__NR_get_mempolicy]   = {.slow = 0, .parser = {NULL}},
        [__NR_mq_open]         = {.slow = 0, .parser = {NULL}},
        [__NR_mq_unlink]       = {.slow = 0, .parser = {NULL}},
        [__NR_mq_timedsend]    = {.slow = 0, .parser = {NULL}},
        [__NR_mq_timedreceive] = {.slow = 0, .parser = {NULL}},
        [__NR_mq_notify]       = {.slow = 0, .parser = {NULL}},
        [__NR_mq_getsetattr]   = {.slow = 0, .parser = {NULL}},
        [__NR_kexec_load]      = {.slow = 0, .parser = {NULL}},
        [__NR_waitid]      = {.slow   = 1,
                              .parser = {&parse_waitid_which, NULL, NULL, &parse_wait_options, NULL}},
        [__NR_add_key]     = {.slow = 0, .parser = {NULL}},
        [__NR_request_key] = {.slow = 0, .parser = {NULL}},
        [__NR_keyctl]      = {.slow = 0, .parser = {NULL}},
        [__NR_ioprio_set]  = {.slow = 0, .parser = {NULL}},
        [__NR_ioprio_get]  = {.slow = 0, .parser = {NULL}},
        [__NR_inotify_init]      = {.slow = 0, .parser = {NULL}},
        [__NR_inotify_add_watch] = {.slow = 0, .parser = {NULL}},
        [__NR_inotify_rm_watch]  = {.slow = 0, .parser = {NULL}},
        [__NR_migrate_pages]     = {.slow = 0, .parser = {NULL}},
        [__NR_openat]     = {.slow   = 0,
                             .parser = {&parse_at_fdcwd, NULL, &parse_open_flags, &parse_open_mode}},
        [__NR_mkdirat]    = {.slow = 0, .parser = {&parse_at_fdcwd}},
        [__NR_mknodat]    = {.slow = 0, .parser = {&parse_at_fdcwd, NULL, &parse_open_mode}},
        [__NR_fchownat]   = {.slow = 0, .parser = {&parse_at_fdcwd}},
        [__NR_futimesat]  = {.slow = 0, .parser = {&parse_at_fdcwd}},
        [__NR_newfstatat] = {.slow = 0, .parser = {&parse_at_fdcwd}},
        [__NR_unlinkat]   = {.slow = 0, .parser = {&parse_at_fdcwd}},
        [__NR_renameat]   = {.slow = 0, .parser = {&parse_at_fdcwd}},
        [__NR_linkat]     = {.slow = 0, .parser = {&parse_at_fdcwd}},
        [__NR_symlinkat]  = {.slow = 0, .parser = {&parse_at_fdcwd}},
        [__NR_readlinkat] = {.slow = 0, .parser = {&parse_at_fdcwd}},
        [__NR_fchmodat]   = {.slow = 0, .parser = {&parse_at_fdcwd}},
        [__NR_faccessat]  = {.slow = 0, .parser = {&parse_at_fdcwd}},
        [__NR_pselect6]   = {.slow = 1, .parser = {NULL}},
        [__NR_ppoll]      = {.slow = 1, .parser = {NULL}},
        [__NR_unshare]    = {.slow = 0, .parser = {NULL}},
        [__NR_set_robust_list] = {.slow = 0, .parser = {NULL}},
        [__NR_get_robust_list] = {.slow = 0, .parser = {NULL}},
        [__NR_splice]          = {.slow = 0, .parser = {NULL}},
        [__NR_tee]             = {.slow = 0, .parser = {NULL}},
        [__NR_sync_file_range] = {.slow = 0, .parser = {NULL}},
        [__NR_vmsplice]        = {.slow = 0, .parser = {NULL}},
        [__NR_move_pages]      = {.slow = 0, .parser = {NULL}},
        [__NR_utimensat]       = {.slow = 0, .parser = {NULL}},
        [__NR_epoll_pwait]     = {.slow = 1, .parser = {NULL}},
        [__NR_signalfd]        = {.slow = 0, .parser = {NULL}},
        [__NR_timerfd_create]  = {.slow = 0, .parser = {NULL}},
        [__NR_eventfd]         = {.slow = 0, .parser = {NULL}},
        [__NR_fallocate]       = {.slow = 0, .parser = {NULL}},
        [__NR_timerfd_settime] = {.slow = 0, .parser = {NULL}},
        [__NR_timerfd_gettime] = {.slow = 0, .parser = {NULL}},
        [__NR_accept4]       = {.slow = 1, .parser = {NULL}},
        [__NR_signalfd4]     = {.slow = 0, .parser = {NULL}},
        [__NR_eventfd2]      = {.slow = 0, .parser = {NULL}},
        [__NR_epoll_create1] = {.slow = 0, .parser = {NULL}},
        [__NR_dup3]          = {.slow = 0, .parser = {NULL}},
        [__NR_pipe2]         = {.slow = 0, .parser = {NULL}},
        [__NR_inotify_init1] = {.slow = 0, .parser = {NULL}},
        [__NR_preadv]        = {.slow = 0, .parser = {NULL}},
        [__NR_pwritev]       = {.slow = 0, .parser = {NULL}},
        [__NR_rt_tgsigqueueinfo] = {.slow = 0, .parser = {NULL}},
        [__NR_perf_event_open]   = {.slow = 0, .parser = {NULL}},
        [__NR_recvmmsg]          = {.slow = 0, .parser = {NULL}},
        [__NR_getcpu]        = {.slow = 0, .parser = {NULL}},
        [__NR_process_vm_readv]  = {.slow = 0, .parser = {NULL}},
        [__NR_process_vm_writev] = {.slow = 0, .parser = {NULL}},
        [__NR_kcmp]              = {.slow = 0, .parser = {NULL}},
        [__NR_finit_module]      = {.slow = 0, .parser = {NULL}},
        [__NR_sched_setattr]     = {.slow = 0, .parser = {NULL}},
        [__NR_sched_getattr]     = {.slow = 0, .parser = {NULL}},
        [__NR_renameat2]         = {.slow = 0, .parser = {NULL}},
        [__NR_seccomp]           = {.slow = 0, .parser = {NULL}},
        [__NR_getrandom]         = {.slow = 0, .parser = {NULL, NULL, parse_getrandom_flags}},
        [__NR_memfd_create]      = {.slow = 0, .parser = {NULL}},
        [__NR_kexec_file_load]   = {.slow = 0, .parser = {NULL}},
        [__NR_bpf]               = {.slow = 0, .parser = {NULL}},
        [__NR_execveat]          = {.slow = 0, .parser = {NULL}},
        [__NR_userfaultfd]       = {.slow = 0, .parser = {NULL}},
        [__NR_membarrier]        = {.slow = 0, .parser = {NULL}},
        [__NR_mlock2]            = {.slow = 0, .parser = {NULL}},
        [__NR_copy_file_range]   = {.slow = 0, .parser = {NULL}},
        [__NR_preadv2]           = {.slow = 0, .parser = {NULL}},
        [__NR_pwritev2]          = {.slow = 0, .parser = {NULL}},
        [__NR_pkey_mprotect]     = {.slow = 0, .parser = {NULL}},
        [__NR_pkey_alloc]        = {.slow = 0, .parser = {NULL}},
        [__NR_pkey_free]         = {.slow = 0, .parser = {NULL}},
        [__NR_statx]             = {.slow = 0, .parser = {NULL}},
        [__NR_io_pgetevents]     = {.slow = 0, .parser = {NULL}},
        [__NR_rseq]              = {.slow = 0, .parser = {NULL}},
        [__NR_pidfd_send_signal] = {.slow = 0, .parser = {NULL}},
        [__NR_io_uring_setup]    = {.slow = 0, .parser = {NULL}},
        [__NR_io_uring_enter]    = {.slow = 0, .parser = {NULL}},
        [__NR_io_uring_register] = {.slow = 0, .parser = {NULL}},
};

#define S(sig) #sig

const char* const siglist[SIGRTMIN] = {
    [0]         = "BAD SIGNAL",
    [SIGHUP]    = S(SIGHUP),
    [SIGINT]    = S(SIGINT),
    [SIGQUIT]   = S(SIGQUIT),
    [SIGILL]    = S(SIGILL),
    [SIGTRAP]   = S(SIGTRAP),
    [SIGABRT]   = S(SIGABRT),
    [SIGBUS]    = S(SIGBUS),
    [SIGFPE]    = S(SIGFPE),
    [SIGKILL]   = S(SIGKILL),
    [SIGUSR1]   = S(SIGUSR1),
    [SIGSEGV]   = S(SIGSEGV),
    [SIGUSR2]   = S(SIGUSR2),
    [SIGPIPE]   = S(SIGPIPE),
    [SIGALRM]   = S(SIGALRM),
    [SIGTERM]   = S(SIGTERM),
    [SIGSTKFLT] = S(SIGSTKFLT),
    [SIGCHLD]   = S(SIGCHLD),
    [SIGCONT]   = S(SIGCONT),
    [SIGSTOP]   = S(SIGSTOP),
    [SIGTSTP]   = S(SIGTSTP),
    [SIGTTIN]   = S(SIGTTIN),
    [SIGTTOU]   = S(SIGTTOU),
    [SIGURG]    = S(SIGURG),
    [SIGXCPU]   = S(SIGXCPU),
    [SIGXFSZ]   = S(SIGXFSZ),
    [SIGVTALRM] = S(SIGVTALRM),
    [SIGPROF]   = S(SIGPROF),
    [SIGWINCH]  = S(SIGWINCH),
    [SIGIO]     = S(SIGIO),
    [SIGPWR]    = S(SIGPWR),
    [SIGSYS]    = S(SIGSYS),
};

static const char* signal_name(int sig, char str[6]) {
    if (sig <= 0 || sig > NUM_SIGS) {
        return "BAD SIGNAL";
    }

    if (sig < SIGRTMIN)
        return siglist[sig];

    assert(sig <= 99);
    /* Cannot use `sizeof(buf)` here because `typeof(str)` is `char*`, thanks C! */
    snprintf(str, 6, "SIG%02d", sig);
    return str;
}

static inline int is_pointer(const char* type) {
    return type[strlen(type) - 1] == '*';
}

static inline int is_pointer_or_long(const char* type) {
    return is_pointer(type) || !strcmp(type, "long") || !strcmp(type, "unsigned long");
}

#define PRINTF(fmt, ...)                \
    do {                                \
        debug_printf(fmt, __VA_ARGS__); \
    } while (0)
#define PUTS(str)        \
    do {                 \
        debug_puts(str); \
    } while (0)
#define PUTCH(ch)        \
    do {                 \
        debug_putch(ch); \
    } while (0)

struct flag_table {
    const char *name;
    int flag;
};

static int parse_flags(int flags, const struct flag_table* all_flags, size_t count) {
    if (!flags) {
        PUTCH('0');
        return 0;
    }

    bool first = true;
    for (size_t i = 0; i < count; i++)
        if (flags & all_flags[i].flag) {
            if (first)
                first = false;
            else
                PUTCH('|');

            PUTS(all_flags[i].name);
            flags &= ~all_flags[i].flag;
        }

    return flags;
}

static inline void parse_string_arg(va_list* ap) {
    va_list ap_test_arg;
    va_copy(ap_test_arg, *ap);
    const char* test_arg = va_arg(ap_test_arg, const char*);
    if (!test_user_string(test_arg)) {
        PRINTF("\"%s\"", va_arg(*ap, const char*));
    } else {
        /* invalid memory region, print arg as ptr not string */
        PRINTF("\"(invalid-addr %p)\"", va_arg(*ap, const char*));
    }
    va_end(ap_test_arg);
}

static inline void parse_pointer_arg(va_list* ap) {
    PRINTF("%p", va_arg(*ap, void*));
}

static inline void parse_integer_arg(va_list* ap) {
    PRINTF("%d", va_arg(*ap, int));
}

static inline void parse_syscall_args(va_list* ap) {
    const char* arg_type = va_arg(*ap, const char*);

    if (!strcmp(arg_type, "const char *") || !strcmp(arg_type, "const char*"))
        parse_string_arg(ap);
    else if (is_pointer_or_long(arg_type))
        parse_pointer_arg(ap);
    else
        parse_integer_arg(ap);
}

static inline void skip_syscall_args(va_list* ap) {
    const char* arg_type = va_arg(*ap, const char*);

    if (!strcmp(arg_type, "const char *") || !strcmp(arg_type, "const char*"))
        va_arg(*ap, const char*);
    else if (is_pointer_or_long(arg_type))
        va_arg(*ap, void*);
    else
        va_arg(*ap, int);
}

void parse_syscall_before(int sysno, const char* name, int nr, ...) {
    if (!g_debug_log_enabled)
        return;

    struct parser_table* parser = &syscall_parser_table[sysno];

    if (!parser->slow && !parser->stop)
        return;

    va_list ap;
    va_start(ap, nr);

    PRINTF("---- shim_%s(", name);

    for (int i = 0; i < nr; i++) {
        if (parser->stop && parser->stop == i)
            goto dotdotdot;

        if (i)
            PUTCH(',');

        if (parser->parser[i]) {
            const char* type = va_arg(ap, const char*);
            __UNUSED(type);  // type not needed on this path
            (*parser->parser[i])(&ap);
        } else {
            parse_syscall_args(&ap);
        }
    }

    PUTCH(')');
dotdotdot:
    PRINTF(" ... %s\n", name);
    va_end(ap);
}

void parse_syscall_after(int sysno, const char* name, int nr, ...) {
    if (!g_debug_log_enabled)
        return;

    struct parser_table* parser = &syscall_parser_table[sysno];

    va_list ap;
    va_start(ap, nr);

    const char* ret_type = va_arg(ap, const char*);

    if (parser->slow || parser->stop)
        PRINTF("---- return from shim_%s(...", name);
    else
        PRINTF("---- shim_%s(", name);

    unsigned long ret_ptr = 0;
    int ret_val = 0;

    if (is_pointer(ret_type))
        ret_ptr = (unsigned long)va_arg(ap, void*);
    else
        ret_val = va_arg(ap, int);

    if (!parser->slow || parser->stop)
        for (int i = 0; i < nr; i++) {
            if (parser->stop && i < parser->stop) {
                skip_syscall_args(&ap);
                continue;
            }

            if (i)
                PUTCH(',');

            if (parser->parser[i]) {
                const char* type = va_arg(ap, const char*);
                __UNUSED(type);  // type not needed on this path
                (*parser->parser[i])(&ap);
            } else {
                parse_syscall_args(&ap);
            }
        }

    if (is_pointer(ret_type)) {
        if ((uint64_t)ret_ptr < (uint64_t)-4095L)
            PRINTF(") = 0x%08lx\n", ret_ptr);
        else
            PRINTF(") = %ld\n", (long)ret_ptr);
    } else {
        PRINTF(") = %d\n", ret_val);
    }

    va_end(ap);
}

static void parse_open_flags(va_list* ap) {
    int flags = va_arg(*ap, int);

    if (flags & O_WRONLY) {
        PUTS("O_WRONLY");
        flags &= ~O_WRONLY;
    } else if (flags & O_RDWR) {
        PUTS("O_RDWR");
        flags &= ~O_RDWR;
    } else {
        PUTS("O_RDONLY");
    }

    if (flags & O_APPEND) {
        PUTS("|O_APPEND");
        flags &= ~O_APPEND;
    }
    if (flags & O_CREAT) {
        PUTS("|O_CREAT");
        flags &= ~O_CREAT;
    }
    if (flags & O_TRUNC) {
        PUTS("|O_TRUNC");
        flags &= ~O_TRUNC;
    }
    if (flags & O_EXCL) {
        PUTS("|O_EXCL");
        flags &= ~O_EXCL;
    }

    if (flags)
        PRINTF("|%o", flags);
}

static void parse_open_mode(va_list* ap) {
    PRINTF("%04o", va_arg(*ap, mode_t));
}

static void parse_access_mode(va_list* ap) {
    int mode = va_arg(*ap, int);

    PUTS("F_OK");

    if (mode) {
        if (mode & R_OK)
            PUTS("|R_OK");
        if (mode & W_OK)
            PUTS("|W_OK");
        if (mode & X_OK)
            PUTS("|X_OK");
    }
}

static void parse_clone_flags(va_list* ap) {
    int flags = va_arg(*ap, int);

#define FLG(n) \
    { "CLONE_" #n, CLONE_##n, }
    const struct flag_table all_flags[] = {
        FLG(VM),
        FLG(FS),
        FLG(FILES),
        FLG(SIGHAND),
        FLG(PTRACE),
        FLG(VFORK),
        FLG(PARENT),
        FLG(THREAD),
        FLG(NEWNS),
        FLG(SYSVSEM),
        FLG(SETTLS),
        FLG(PARENT_SETTID),
        FLG(CHILD_CLEARTID),
        FLG(DETACHED),
        FLG(UNTRACED),
        FLG(CHILD_SETTID),
        FLG(NEWUTS),
        FLG(NEWIPC),
        FLG(NEWUSER),
        FLG(NEWPID),
        FLG(NEWNET),
        FLG(IO),
    };
#undef FLG

    flags = parse_flags(flags, all_flags, ARRAY_SIZE(all_flags));

#define CLONE_SIGNAL_MASK 0xff
    int exit_signal = flags & CLONE_SIGNAL_MASK;
    flags &= ~CLONE_SIGNAL_MASK;
    if (exit_signal) {
        char str[6];
        PRINTF("|[%s]", signal_name(exit_signal, str));
    }

    if (flags)
        PRINTF("|0x%x", flags);
}

static void parse_mmap_prot(va_list* ap) {
    int prot   = va_arg(*ap, int);
    int nflags = 0;

    if (!(prot & (PROT_READ | PROT_WRITE | PROT_EXEC))) {
        nflags++;
        PUTS("PROT_NONE");
    }

    if (prot & PROT_READ) {
        if (nflags++)
            PUTS("|");
        PUTS("PROT_READ");
    }

    if (prot & PROT_WRITE) {
        if (nflags++)
            PUTS("|");
        PUTS("PROT_WRITE");
    }

    if (prot & PROT_EXEC) {
        if (nflags++)
            PUTS("|");

        PUTS("PROT_EXEC");
    }

    if (prot & PROT_SEM) {
        PUTS("|PROT_SEM");
    }

    if (prot & PROT_GROWSDOWN) {
        PUTS("|PROT_GROWSDOWN");
    }

    if (prot & PROT_GROWSUP) {
        PUTS("|PROT_GROWSUP");
    }
}

static void parse_mmap_flags(va_list* ap) {
    int flags = va_arg(*ap, int);

    if ((flags & MAP_SHARED_VALIDATE) == MAP_SHARED_VALIDATE) {
        PUTS("MAP_SHARED_VALIDATE");
        flags &= ~MAP_SHARED_VALIDATE;
    } else if (flags & MAP_SHARED) {
        PUTS("MAP_SHARED");
        flags &= ~MAP_SHARED;
    } else {
        assert(flags & MAP_PRIVATE);
        PUTS("MAP_PRIVATE");
        flags &= ~MAP_PRIVATE;
    }

    if (flags & MAP_ANONYMOUS) {
        PUTS("|MAP_ANONYMOUS");
        flags &= ~MAP_ANONYMOUS;
    }

    if (flags & MAP_FILE) {
        PUTS("|MAP_FILE");
        flags &= ~MAP_FILE;
    }

    if (flags & MAP_FIXED) {
        PUTS("|MAP_FIXED");
        flags &= ~MAP_FIXED;
    }

#ifdef CONFIG_MMAP_ALLOW_UNINITIALIZED
    if (flags & MAP_UNINITIALIZED) {
        PUTS("|MAP_UNINITIALIZED");
        flags &= ~MAP_UNINITIALIZED;
    }
#endif

    if (flags & MAP_GROWSDOWN) {
        PUTS("|MAP_GROWSDOWN");
        flags &= ~MAP_GROWSDOWN;
    }

    if (flags & MAP_DENYWRITE) {
        PUTS("|MAP_DENYWRITE");
        flags &= ~MAP_DENYWRITE;
    }

    if (flags & MAP_EXECUTABLE) {
        PUTS("|MAP_EXECUTABLE");
        flags &= ~MAP_EXECUTABLE;
    }

    if (flags & MAP_LOCKED) {
        PUTS("|MAP_LOCKED");
        flags &= ~MAP_LOCKED;
    }

    if (flags & MAP_NORESERVE) {
        PUTS("|MAP_NORESERVE");
        flags &= ~MAP_NORESERVE;
    }

    if (flags & MAP_POPULATE) {
        PUTS("|MAP_POPULATE");
        flags &= ~MAP_POPULATE;
    }

    if (flags & MAP_NONBLOCK) {
        PUTS("|MAP_NONBLOCK");
        flags &= ~MAP_NONBLOCK;
    }

    if (flags & MAP_STACK) {
        PUTS("|MAP_STACK");
        flags &= ~MAP_STACK;
    }

    if (flags & MAP_HUGETLB) {
        PUTS("|MAP_HUGETLB");
        flags &= ~MAP_HUGETLB;
    }

#ifdef MAP_SYNC
    if (flags & MAP_SYNC) {
        PUTS("|MAP_SYNC");
        flags &= ~MAP_SYNC;
    }
#endif

    if (flags)
        PRINTF("|0x%x", flags);
}

static void parse_exec_args(va_list* ap) {
    const char** args = va_arg(*ap, const char**);

    PUTS("[");

    for (;; args++) {
        if (test_user_memory(args, sizeof(*args), false)) {
            PRINTF("(invalid-argv %p)", args);
            break;
        }
        if (*args == NULL)
            break;
        if (test_user_string(*args)) {
            PRINTF("(invalid-addr %p),", *args);
            continue;
        }
        PUTS(*args);
        PUTS(",");
    }

    PUTS("]");
}

static void parse_exec_envp(va_list* ap) {
    const char** envp = va_arg(*ap, const char**);

    if (!envp) {
        PUTS("NULL");
        return;
    }

    PUTS("[");

    int cnt = 0;
    for (; cnt < 2; cnt++, envp++) {
        if (test_user_memory(envp, sizeof(*envp), false)) {
            PRINTF("(invalid-envp %p)", envp);
            break;
        }
        if (*envp == NULL)
            break;
        if (test_user_string(*envp)) {
            PRINTF("(invalid-addr %p),", *envp);
            continue;
        }
        PUTS(*envp);
        PUTS(",");
    }

    if (cnt > 2)
        PRINTF("(%d more)", cnt);

    PUTS("]");
}

static void parse_pipe_fds(va_list* ap) {
    int* fds = va_arg(*ap, int*);

    if (test_user_memory(fds, 2 * sizeof(*fds), false)) {
        PRINTF("[invalid-addr %p]", fds);
        return;
    }
    PRINTF("[%d, %d]", fds[0], fds[1]);
}

static void parse_signum(va_list* ap) {
    int signum = va_arg(*ap, int);
    char str[6];
    PRINTF("[%s]", signal_name(signum, str));
}

static void parse_sigmask(va_list* ap) {
    __sigset_t* sigset = va_arg(*ap, __sigset_t*);

    if (!sigset) {
        PUTS("NULL");
        return;
    }

    if (test_user_memory(sigset, sizeof(*sigset), false)) {
        PRINTF("(invalid-addr %p)", sigset);
        return;
    }

    PUTS("[");

    for (size_t signum = 1; signum <= sizeof(sigset) * 8; signum++)
        if (__sigismember(sigset, signum)) {
            char str[6];
            PUTS(signal_name(signum, str));
            PUTS(",");
        }

    PUTS("]");
}

static void parse_sigprocmask_how(va_list* ap) {
    int how = va_arg(*ap, int);

    switch (how) {
        case SIG_BLOCK:
            PUTS("BLOCK");
            break;
        case SIG_UNBLOCK:
            PUTS("UNBLOCK");
            break;
        case SIG_SETMASK:
            PUTS("SETMASK");
            break;
        default:
            PUTS("<unknown>");
            break;
    }
}

static void parse_madvise_behavior(va_list* ap) {
    int behavior = va_arg(*ap, int);
    switch (behavior) {
        case MADV_DOFORK:
            PUTS("MADV_DOFORK");
            break;
        case MADV_DONTFORK:
            PUTS("MADV_DONTFORK");
            break;
        case MADV_NORMAL:
            PUTS("MADV_NORMAL");
            break;
        case MADV_SEQUENTIAL:
            PUTS("MADV_SEQUENTIAL");
            break;
        case MADV_RANDOM:
            PUTS("MADV_RANDOM");
            break;
        case MADV_REMOVE:
            PUTS("MADV_REMOVE");
            break;
        case MADV_WILLNEED:
            PUTS("MADV_WILLNEED");
            break;
        case MADV_DONTNEED:
            PUTS("MADV_DONTNEED");
            break;
        case MADV_FREE:
            PUTS("MADV_FREE");
            break;
        case MADV_MERGEABLE:
            PUTS("MADV_MERGEABLE");
            break;
        case MADV_UNMERGEABLE:
            PUTS("MADV_UNMERGEABLE");
            break;
        case MADV_HUGEPAGE:
            PUTS("MADV_HUGEPAGE");
            break;
        case MADV_NOHUGEPAGE:
            PUTS("MADV_NOHUGEPAGE");
            break;
        case MADV_DONTDUMP:
            PUTS("MADV_DONTDUMP");
            break;
        case MADV_DODUMP:
            PUTS("MADV_DODUMP");
            break;
        case MADV_WIPEONFORK:
            PUTS("MADV_WIPEONFORK");
            break;
        case MADV_KEEPONFORK:
            PUTS("MADV_KEEPONFORK");
            break;
        case MADV_SOFT_OFFLINE:
            PUTS("MADV_SOFT_OFFLINE");
            break;
        case MADV_HWPOISON:
            PUTS("MADV_HWPOISON");
            break;
        default:
            PRINTF("(unknown: %d)", behavior);
            break;
    }
}

static void parse_timespec(va_list* ap) {
    const struct timespec* tv = va_arg(*ap, const struct timespec*);

    if (!tv) {
        PUTS("NULL");
        return;
    }

    if (test_user_memory((void*)tv, sizeof(*tv), false)) {
        PRINTF("(invalid-addr %p)", tv);
        return;
    }

    PRINTF("[%ld,%ld]", tv->tv_sec, tv->tv_nsec);
}

static void parse_sockaddr(va_list* ap) {
    const struct sockaddr* addr = va_arg(*ap, const struct sockaddr*);

    if (!addr) {
        PUTS("NULL");
        return;
    }

    if (test_user_memory((void*)addr, sizeof(*addr), false)) {
        PRINTF("(invalid-addr %p)", addr);
        return;
    }

    switch (addr->sa_family) {
        case AF_INET: {
            struct sockaddr_in* a = (void*)addr;
            unsigned char* ip     = (void*)&a->sin_addr.s_addr;
            PRINTF("{family=INET,ip=%u.%u.%u.%u,port=htons(%u)}", ip[0], ip[1], ip[2], ip[3],
                   __ntohs(a->sin_port));
            break;
        }

        case AF_INET6: {
            struct sockaddr_in6* a = (void*)addr;
            unsigned short* ip     = (void*)&a->sin6_addr.s6_addr;
            PRINTF(
                "{family=INET,ip=[%x:%x:%x:%x:%x:%x:%x:%x],"
                "port=htons(%u)}",
                __ntohs(ip[0]), __ntohs(ip[1]), __ntohs(ip[2]), __ntohs(ip[3]), __ntohs(ip[4]),
                __ntohs(ip[5]), __ntohs(ip[6]), __ntohs(ip[7]), __ntohs(a->sin6_port));
            break;
        }

        case AF_UNIX: {
            struct sockaddr_un* a = (void*)addr;
            PRINTF("{family=UNIX,path=%s}", a->sun_path);
            break;
        }

        default:
            PUTS("UNKNOWN");
            break;
    }
}

static void parse_domain(va_list* ap) {
    int domain = va_arg(*ap, int);

#define PF_UNSPEC    0  /* Unspecified.  */
#define PF_INET      2  /* IP protocol family.  */
#define PF_AX25      3  /* Amateur Radio AX.25.  */
#define PF_IPX       4  /* Novell Internet Protocol.  */
#define PF_APPLETALK 5  /* Appletalk DDP.  */
#define PF_ATMPVC    8  /* ATM PVCs.  */
#define PF_X25       9  /* Reserved for X.25 project.  */
#define PF_INET6     10 /* IP version 6.  */
#define PF_NETLINK   16
#define PF_PACKET    17 /* Packet family.  */

    switch (domain) {
        case PF_UNSPEC:
            PUTS("UNSPEC");
            break;
        case PF_UNIX:
            PUTS("UNIX");
            break;
        case PF_INET:
            PUTS("INET");
            break;
        case PF_INET6:
            PUTS("INET6");
            break;
        case PF_IPX:
            PUTS("IPX");
            break;
        case PF_NETLINK:
            PUTS("NETLINK");
            break;
        case PF_X25:
            PUTS("X25");
            break;
        case PF_AX25:
            PUTS("AX25");
            break;
        case PF_ATMPVC:
            PUTS("ATMPVC");
            break;
        case PF_APPLETALK:
            PUTS("APPLETALK");
            break;
        case PF_PACKET:
            PUTS("PACKET");
            break;
        default:
            PUTS("UNKNOWN");
            break;
    }
}

static void parse_socktype(va_list* ap) {
    int socktype = va_arg(*ap, int);

    if (socktype & SOCK_NONBLOCK) {
        socktype &= ~SOCK_NONBLOCK;
        PUTS("SOCK_NONBLOCK|");
    }

    if (socktype & SOCK_CLOEXEC) {
        socktype &= ~SOCK_CLOEXEC;
        PUTS("SOCK_CLOEXEC|");
    }

#define SOCK_RAW       3  /* Raw protocol interface.  */
#define SOCK_RDM       4  /* Reliably-delivered messages.  */
#define SOCK_SEQPACKET 5  /* Sequenced, reliable, connection-based, */
#define SOCK_DCCP      6  /* Datagram Congestion Control Protocol.  */
#define SOCK_PACKET    10 /* Linux specific way of getting packets */

    switch (socktype) {
        case SOCK_STREAM:
            PUTS("STREAM");
            break;
        case SOCK_DGRAM:
            PUTS("DGRAM");
            break;
        case SOCK_SEQPACKET:
            PUTS("SEQPACKET");
            break;
        case SOCK_RAW:
            PUTS("RAW");
            break;
        case SOCK_RDM:
            PUTS("RDM");
            break;
        case SOCK_PACKET:
            PUTS("PACKET");
            break;
        default:
            PUTS("UNKNOWN");
            break;
    }
}

static void parse_futexop(va_list* ap) {
    int op = va_arg(*ap, int);

#ifdef FUTEX_PRIVATE_FLAG
    if (op & FUTEX_PRIVATE_FLAG) {
        PUTS("FUTEX_PRIVATE|");
        op &= ~FUTEX_PRIVATE_FLAG;
    }
#endif

#ifdef FUTEX_CLOCK_REALTIME
    if (op & FUTEX_CLOCK_REALTIME) {
        PUTS("FUTEX_CLOCK_REALTIME|");
        op &= ~FUTEX_CLOCK_REALTIME;
    }
#endif

    op &= FUTEX_CMD_MASK;

    switch (op) {
        case FUTEX_WAIT:
            PUTS("FUTEX_WAIT");
            break;
        case FUTEX_WAIT_BITSET:
            PUTS("FUTEX_WAIT_BITSET");
            break;
        case FUTEX_WAKE:
            PUTS("FUTEX_WAKE");
            break;
        case FUTEX_WAKE_BITSET:
            PUTS("FUTEX_WAKE_BITSET");
            break;
        case FUTEX_FD:
            PUTS("FUTEX_FD");
            break;
        case FUTEX_REQUEUE:
            PUTS("FUTEX_REQUEUE");
            break;
        case FUTEX_CMP_REQUEUE:
            PUTS("FUTEX_CMP_REQUEUE");
            break;
        case FUTEX_WAKE_OP:
            PUTS("FUTEX_WAKE_OP");
            break;
        default:
            PRINTF("OP %d", op);
            break;
    }
}

static void parse_fcntlop(va_list* ap) {
    int op = va_arg(*ap, int);

    switch (op) {
        case F_DUPFD:
            PUTS("F_DUPFD");
            break;
        case F_GETFD:
            PUTS("F_GETFD");
            break;
        case F_SETFD:
            PUTS("F_SETFD");
            break;
        case F_GETFL:
            PUTS("F_GETFL");
            break;
        case F_SETFL:
            PUTS("F_SETFL");
            break;
        case F_GETLK:
            PUTS("F_GETLK");
            break;
        case F_SETLK:
            PUTS("F_SETLK");
            break;
        case F_SETLKW:
            PUTS("F_SETLKW");
            break;
        case F_SETOWN:
            PUTS("F_SETOWN");
            break;
        case F_GETOWN:
            PUTS("F_GETOWN");
            break;
        case F_SETSIG:
            PUTS("F_SETSIG");
            break;
        case F_GETSIG:
            PUTS("F_GETSIG");
            break;
        case F_GETLK64:
            PUTS("F_GETLK64");
            break;
        case F_SETLK64:
            PUTS("F_SETLK64");
            break;
        case F_SETLKW64:
            PUTS("F_SETLKW64");
            break;
        case F_SETOWN_EX:
            PUTS("F_SETOWN_EX");
            break;
        case F_GETOWN_EX:
            PUTS("F_GETOWN_EX");
            break;
        case F_GETOWNER_UIDS:
            PUTS("F_GETOWNER_UIDS");
            break;
        default:
            PRINTF("OP %d", op);
            break;
    }
}

static void parse_ioctlop(va_list* ap) {
    unsigned int op = va_arg(*ap, unsigned int);

    if (op >= TCGETS && op <= TIOCVHANGUP) {
        const char* opnames[] = {
            "TCGETS",       /* 0x5401 */ "TCSETS",       /* 0x5402 */
            "TCSETSW",      /* 0x5403 */ "TCSETSF",      /* 0x5404 */
            "TCGETA",       /* 0x5405 */ "TCSETA",       /* 0x5406 */
            "TCSETAW",      /* 0x5407 */ "TCSETAF",      /* 0x5408 */
            "TCSBRK",       /* 0x5409 */ "TCXONC",       /* 0x540A */
            "TCFLSH",       /* 0x540B */ "TIOCEXCL",     /* 0x540C */
            "TIOCNXCL",     /* 0x540D */ "TIOCSCTTY",    /* 0x540E */
            "TIOCGPGRP",    /* 0x540F */ "TIOCSPGRP",    /* 0x5410 */
            "TIOCOUTQ",     /* 0x5411 */ "TIOCSTI",      /* 0x5412 */
            "TIOCGWINSZ",   /* 0x5413 */ "TIOCSWINSZ",   /* 0x5414 */
            "TIOCMGET",     /* 0x5415 */ "TIOCMBIS",     /* 0x5416 */
            "TIOCMBIC",     /* 0x5417 */ "TIOCMSET",     /* 0x5418 */
            "TIOCGSOFTCAR", /* 0x5419 */ "TIOCSSOFTCAR", /* 0x541A */
            "FIONREAD",     /* 0x541B */ "TIOCLINUX",    /* 0x541C */
            "TIOCCONS",     /* 0x541D */ "TIOCGSERIAL",  /* 0x541E */
            "TIOCSSERIAL",  /* 0x541F */ "TIOCPKT",      /* 0x5420 */
            "FIONBIO",      /* 0x5421 */ "TIOCNOTTY",    /* 0x5422 */
            "TIOCSETD",     /* 0x5423 */ "TIOCGETD",     /* 0x5424 */
            "TCSBRKP",      /* 0x5425 */ "",
            "TIOCSBRK",     /* 0x5427 */ "TIOCCBRK",   /* 0x5428 */
            "TIOCGSID",     /* 0x5429 */ "TCGETS2",    /* 0x542A */
            "TCSETS2",      /* 0x542B */ "TCSETSW2",   /* 0x542C */
            "TCSETSF2",     /* 0x542D */ "TIOCGRS485", /* 0x542E */
            "TIOCSRS485",   /* 0x542F */ "TIOCGPTN",   /* 0x5430 */
            "TIOCSPTLCK",   /* 0x5431 */ "TCGETX",     /* 0x5432 */
            "TCSETX",       /* 0x5433 */ "TCSETXF",    /* 0x5434 */
            "TCSETXW",      /* 0x5435 */ "TIOCSIG",    /* 0x5436 */
            "TIOCVHANGUP",                             /* 0x5437 */
        };
        PUTS(opnames[op - TCGETS]);
        return;
    }

    if (op >= FIONCLEX && op <= TIOCSERSETMULTI) {
        const char* opnames[] = {
            "FIONCLEX",        /* 0x5450 */ "FIOCLEX",         /* 0x5451 */
            "FIOASYNC",        /* 0x5452 */ "TIOCSERCONFIG",   /* 0x5453 */
            "TIOCSERGWILD",    /* 0x5454 */ "TIOCSERSWILD",    /* 0x5455 */
            "TIOCGLCKTRMIOS",  /* 0x5456 */ "TIOCSLCKTRMIOS",  /* 0x5457 */
            "TIOCSERGSTRUCT",  /* 0x5458 */ "TIOCSERGETLSR",   /* 0x5459 */
            "TIOCSERGETMULTI", /* 0x545A */ "TIOCSERSETMULTI", /* 0x545B */
        };
        PUTS(opnames[op - FIONCLEX]);
        return;
    }

#define TIOCMIWAIT  0x545C /* wait for a change on serial input line(s) */
#define TIOCGICOUNT 0x545D /* read serial port __inline__ interrupt counts */

    PRINTF("OP 0x%04x", op);
}

static void parse_seek(va_list* ap) {
    int seek = va_arg(*ap, int);

    switch (seek) {
        case SEEK_CUR:
            PUTS("SEEK_CUR");
            break;
        case SEEK_SET:
            PUTS("SEEK_SET");
            break;
        case SEEK_END:
            PUTS("SEEK_END");
            break;
        default:
            PRINTF("%d", seek);
            break;
    }
}

static void parse_at_fdcwd(va_list* ap) {
    int fd = va_arg(*ap, int);

    switch (fd) {
        case AT_FDCWD:
            PUTS("AT_FDCWD");
            break;
        default:
            PRINTF("%d", fd);
            break;
    }
}

static void parse_wait_options(va_list* ap) {
    int flags = va_arg(*ap, int);

#define FLG(n) { #n, n }
    const struct flag_table all_flags[] = {
        FLG(WNOHANG),
        FLG(WNOWAIT),
        FLG(WEXITED),
        FLG(WSTOPPED),
        FLG(WCONTINUED),
        FLG(WUNTRACED),
    };
#undef FLG

    flags = parse_flags(flags, all_flags, ARRAY_SIZE(all_flags));
    if (flags)
        PRINTF("|0x%x", flags);
}

static void parse_waitid_which(va_list* ap) {
    int which = va_arg(*ap, int);

    switch (which) {
        case P_ALL:
            PUTS("P_ALL");
            break;
        case P_PID:
            PUTS("P_PID");
            break;
        case P_PGID:
            PUTS("P_PGID");
            break;
#ifdef P_PIDFD
        case P_PIDFD:
            PUTS("P_PIDFD");
            break;
#endif
        default:
            PRINTF("%d", which);
            break;
    }
}

static void parse_getrandom_flags(va_list* ap) {
    unsigned int flags = va_arg(*ap, unsigned int);

#define FLG(n) { #n, n }
    const struct flag_table all_flags[] = {
        FLG(GRND_NONBLOCK),
        FLG(GRND_RANDOM),
        FLG(GRND_INSECURE),
    };
#undef FLG

    flags = parse_flags(flags, all_flags, ARRAY_SIZE(all_flags));
    if (flags)
        PRINTF("|0x%x", flags);
}
