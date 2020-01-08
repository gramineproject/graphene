/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_parser.c
 *
 * This file contains codes for parsing system call arguements for debug
 * purpose.
 */

#include <asm/fcntl.h>
#include <asm/ioctls.h>
#include <asm/mman.h>
#include <asm/prctl.h>
#include <asm/unistd.h>
#include <errno.h>
#include <linux/fcntl.h>
#include <linux/futex.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/un.h>
#include <linux/wait.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_tcb.h>
#include <shim_utils.h>

static void parse_open_flags(va_list);
static void parse_open_mode(va_list);
static void parse_access_mode(va_list);
static void parse_clone_flags(va_list);
static void parse_mmap_prot(va_list);
static void parse_mmap_flags(va_list);
static void parse_exec_args(va_list);
static void parse_exec_envp(va_list);
static void parse_pipe_fds(va_list);
static void parse_signum(va_list);
static void parse_sigmask(va_list);
static void parse_sigprocmask_how(va_list);
static void parse_timespec(va_list);
static void parse_sockaddr(va_list);
static void parse_domain(va_list);
static void parse_socktype(va_list);
static void parse_futexop(va_list);
static void parse_ioctlop(va_list);
static void parse_fcntlop(va_list);
static void parse_seek(va_list);
static void parse_at_fdcwd(va_list);
static void parse_wait_option(va_list);

struct parser_table {
    int slow;
    int stop;
    void (*parser[6])(va_list);
} syscall_parser_table[LIBOS_SYSCALL_BOUND] =
    {
        {.slow = 1, .parser = {NULL}}, /* read */
        {.slow = 1, .parser = {NULL}}, /* write */
        {.slow = 1,                    /* open */
         .parser = {NULL, &parse_open_flags, &parse_open_mode}},
        {.slow = 0, .parser = {NULL}},                    /* close */
        {.slow = 0, .parser = {NULL}},                    /* stat */
        {.slow = 0, .parser = {NULL}},                    /* fstat */
        {.slow = 0, .parser = {NULL}},                    /* lstat */
        {.slow = 1, .parser = {NULL}},                    /* poll */
        {.slow = 0, .parser = {NULL, NULL, &parse_seek}}, /* lseek */
        {.slow   = 1,                                     /* mmap */
         .parser = {NULL, NULL, &parse_mmap_prot, &parse_mmap_flags}},
        {.slow   = 1, /* mprotect */
         .parser = {NULL, NULL, &parse_mmap_prot}},
        {.slow = 1, .parser = {NULL}},          /* munmap */
        {.slow = 0, .parser = {NULL}},          /* brk */
        {.slow = 0, .parser = {&parse_signum}}, /* rt_sigaction */
        {.slow   = 0,                           /* rt_sigprocmask */
         .parser = {&parse_sigprocmask_how, &parse_sigmask, &parse_sigmask}},
        {.slow = 0, .parser = {NULL}},                 /* rt_sigreturn */
        {.slow = 1, .parser = {NULL, &parse_ioctlop}}, /* ioctl */
        {.slow = 1, .parser = {NULL}},                 /* pread64 */
        {.slow = 0, .parser = {NULL}},                 /* pwrite64 */
        {.slow = 1, .parser = {NULL}},                 /* readv */
        {.slow = 0, .parser = {NULL}},                 /* writev */
        {.slow   = 0,                                  /* access */
         .parser = {NULL, &parse_access_mode}},
        {.slow   = 0, /* pipe */
         .parser = {&parse_pipe_fds}},
        {.slow = 0, .parser = {NULL}},                           /* select */
        {.slow = 0, .parser = {NULL}},                           /* sched_yield */
        {.slow = 0, .parser = {NULL}},                           /* mremap */
        {.slow = 0, .parser = {NULL}},                           /* msync */
        {.slow = 0, .parser = {NULL}},                           /* mincore */
        {.slow = 0, .parser = {NULL}},                           /* madvise */
        {.slow = 0, .parser = {NULL}},                           /* shmget */
        {.slow = 0, .parser = {NULL}},                           /* shmat */
        {.slow = 0, .parser = {NULL}},                           /* shmctl */
        {.slow = 0, .parser = {NULL}},                           /* dup */
        {.slow = 0, .parser = {NULL}},                           /* dup2 */
        {.slow = 1, .parser = {NULL}},                           /* pause */
        {.slow = 1, .parser = {&parse_timespec}},                /* nanosleep */
        {.slow = 0, .parser = {NULL}},                           /* getitimer */
        {.slow = 0, .parser = {NULL}},                           /* alarm */
        {.slow = 0, .parser = {NULL}},                           /* setitimer */
        {.slow = 0, .parser = {NULL}},                           /* getpid */
        {.slow = 0, .parser = {NULL}},                           /* sendfile */
        {.slow = 0, .parser = {&parse_domain, &parse_socktype}}, /* socket */

        {.slow = 1, .parser = {NULL, &parse_sockaddr}}, /* connect */
        {.slow = 1, .parser = {NULL}},                  /* accept */
        {.slow = 0, .parser = {NULL}},                  /* sendto */
        {.slow = 0, .parser = {NULL}},                  /* recvfrom */
        {.slow = 0, .parser = {NULL}},                  /* sendmsg */
        {.slow = 1, .parser = {NULL}},                  /* recvmsg */
        {.slow = 0, .parser = {NULL}},                  /* shutdown */
        {.slow = 0, .parser = {NULL}},                  /* bind */
        {.slow = 0, .parser = {NULL}},                  /* listen */
        {.slow = 0, .parser = {NULL}},                  /* getsockname */
        {.slow = 0, .parser = {NULL}},                  /* getpeername */
        {.slow   = 0,                                   /* socketpair */
         .stop   = 3,
         .parser = {&parse_domain, &parse_socktype, NULL, &parse_pipe_fds}},
        {.slow = 0, .parser = {NULL}},               /* setsockopt */
        {.slow = 0, .parser = {NULL}},               /* getsockopt */
        {.slow = 1, .parser = {&parse_clone_flags}}, /* clone */
        {.slow = 1, .parser = {NULL}},               /* fork */
        {.slow = 1, .parser = {NULL}},               /* vfork */
        {.slow   = 1,                                /* execve */
         .parser = {NULL, &parse_exec_args, &parse_exec_envp}},
        {.slow = 0, .parser = {NULL}},                                 /* exit */
        {.slow = 1, .parser = {NULL, NULL, &parse_wait_option, NULL}}, /* wait4 */
        {.slow   = 0,                                                  /* kill */
         .parser = {NULL, &parse_signum, }},
        {.slow = 0, .parser = {NULL}},                      /* uname */
        {.slow = 0, .parser = {NULL}},                      /* semget */
        {.slow = 1, .parser = {NULL}},                      /* semop */
        {.slow = 0, .parser = {NULL}},                      /* semctl */
        {.slow = 0, .parser = {NULL}},                      /* shmdt */
        {.slow = 1, .parser = {NULL}},                      /* msgget */
        {.slow = 1, .parser = {NULL}},                      /* msgsnd */
        {.slow = 1, .parser = {NULL}},                      /* msgrcv */
        {.slow = 1, .parser = {NULL}},                      /* msgctl */
        {.slow = 0, .parser = {NULL, &parse_fcntlop}},      /* fcntl */
        {.slow = 0, .parser = {NULL}},                      /* flock */
        {.slow = 0, .parser = {NULL}},                      /* fsync */
        {.slow = 0, .parser = {NULL}},                      /* fdatasync */
        {.slow = 0, .parser = {NULL}},                      /* truncate */
        {.slow = 0, .parser = {NULL}},                      /* ftruncate */
        {.slow = 0, .parser = {NULL}},                      /* getdents */
        {.slow = 0, .parser = {NULL}},                      /* getcwd */
        {.slow = 0, .parser = {NULL}},                      /* chdir */
        {.slow = 0, .parser = {NULL}},                      /* fchdir */
        {.slow = 0, .parser = {NULL}},                      /* rename */
        {.slow = 0, .parser = {NULL}},                      /* mkdir */
        {.slow = 0, .parser = {NULL}},                      /* rmdir */
        {.slow = 0, .parser = {NULL, &parse_open_mode}},    /* creat */
        {.slow = 0, .parser = {NULL}},                      /* link */
        {.slow = 0, .parser = {NULL}},                      /* unlink */
        {.slow = 0, .parser = {NULL}},                      /* symlink */
        {.slow = 0, .parser = {NULL}},                      /* readlink */
        {.slow = 0, .parser = {NULL}},                      /* chmod */
        {.slow = 0, .parser = {NULL}},                      /* fchmod */
        {.slow = 0, .parser = {NULL}},                      /* chown */
        {.slow = 0, .parser = {NULL}},                      /* fchown */
        {.slow = 0, .parser = {NULL}},                      /* lchown */
        {.slow = 0, .parser = {NULL}},                      /* umask */
        {.slow = 0, .parser = {NULL}},                      /* gettimeofday */
        {.slow = 0, .parser = {NULL}},                      /* getrlimit */
        {.slow = 0, .parser = {NULL}},                      /* getrusage */
        {.slow = 0, .parser = {NULL}},                      /* sysinfo */
        {.slow = 0, .parser = {NULL}},                      /* times */
        {.slow = 0, .parser = {NULL}},                      /* ptrace */
        {.slow = 0, .parser = {NULL}},                      /* getuid */
        {.slow = 0, .parser = {NULL}},                      /* syslog */
        {.slow = 0, .parser = {NULL}},                      /* getgid */
        {.slow = 0, .parser = {NULL}},                      /* setuid */
        {.slow = 0, .parser = {NULL}},                      /* setgid */
        {.slow = 0, .parser = {NULL}},                      /* geteuid */
        {.slow = 0, .parser = {NULL}},                      /* getegid */
        {.slow = 0, .parser = {NULL}},                      /* setpgid */
        {.slow = 0, .parser = {NULL}},                      /* getppid */
        {.slow = 0, .parser = {NULL}},                      /* getpgrp */
        {.slow = 0, .parser = {NULL}},                      /* setsid */
        {.slow = 0, .parser = {NULL}},                      /* setreuid */
        {.slow = 0, .parser = {NULL}},                      /* setregid */
        {.slow = 0, .parser = {NULL}},                      /* getgroups */
        {.slow = 0, .parser = {NULL}},                      /* setgroups */
        {.slow = 0, .parser = {NULL}},                      /* setresuid */
        {.slow = 0, .parser = {NULL}},                      /* getresuid */
        {.slow = 0, .parser = {NULL}},                      /* setresgid */
        {.slow = 0, .parser = {NULL}},                      /* getresgid */
        {.slow = 0, .parser = {NULL}},                      /* getpgid */
        {.slow = 0, .parser = {NULL}},                      /* setfsuid */
        {.slow = 0, .parser = {NULL}},                      /* setfsgid */
        {.slow = 0, .parser = {NULL}},                      /* getsid */
        {.slow = 0, .parser = {NULL}},                      /* capget */
        {.slow = 0, .parser = {NULL}},                      /* capset */
        {.slow = 0, .parser = {NULL}},                      /* rt_sigpending */
        {.slow = 0, .parser = {NULL}},                      /* rt_sigtimedwait */
        {.slow = 0, .parser = {NULL}},                      /* rt_sigqueueinfo */
        {.slow = 1, .parser = {NULL}},                      /* rt_sigsuspend */
        {.slow = 0, .parser = {NULL}},                      /* sigaltstack */
        {.slow = 0, .parser = {NULL}},                      /* utime */
        {.slow = 0, .parser = {NULL}},                      /* mknod */
        {.slow = 0, .parser = {NULL}},                      /* uselib */
        {.slow = 0, .parser = {NULL}},                      /* personality */
        {.slow = 0, .parser = {NULL}},                      /* ustat */
        {.slow = 0, .parser = {NULL}},                      /* statfs */
        {.slow = 0, .parser = {NULL}},                      /* fstatfs */
        {.slow = 0, .parser = {NULL}},                      /* sysfs */
        {.slow = 0, .parser = {NULL}},                      /* getpriority */
        {.slow = 0, .parser = {NULL}},                      /* setpriority */
        {.slow = 0, .parser = {NULL}},                      /* sched_setparam */
        {.slow = 0, .parser = {NULL}},                      /* sched_getparam */
        {.slow = 0, .parser = {NULL}},                      /* sched_setscheduler */
        {.slow = 0, .parser = {NULL}},                      /* sched_getscheduler */
        {.slow = 0, .parser = {NULL}},                      /* sched_get_priority_max */
        {.slow = 0, .parser = {NULL}},                      /* sched_get_priority_min */
        {.slow = 0, .parser = {NULL}},                      /* sched_rr_get_interval */
        {.slow = 0, .parser = {NULL}},                      /* mlock */
        {.slow = 0, .parser = {NULL}},                      /* munlock */
        {.slow = 0, .parser = {NULL}},                      /* mlockall */
        {.slow = 0, .parser = {NULL}},                      /* munlockall */
        {.slow = 0, .parser = {NULL}},                      /* vhangup */
        {.slow = 0, .parser = {NULL}},                      /* modify_ldt */
        {.slow = 0, .parser = {NULL}},                      /* pivot_root */
        {.slow = 0, .parser = {NULL}},                      /* _sysctl */
        {.slow = 0, .parser = {NULL}},                      /* prctl */
        {.slow = 0, .parser = {NULL}},                      /* arch_prctl */
        {.slow = 0, .parser = {NULL}},                      /* adjtimex */
        {.slow = 0, .parser = {NULL}},                      /* setrlimit */
        {.slow = 0, .parser = {NULL}},                      /* chroot */
        {.slow = 0, .parser = {NULL}},                      /* sync */
        {.slow = 0, .parser = {NULL}},                      /* acct */
        {.slow = 0, .parser = {NULL}},                      /* settimeofday */
        {.slow = 0, .parser = {NULL}},                      /* mount */
        {.slow = 0, .parser = {NULL}},                      /* umount2 */
        {.slow = 0, .parser = {NULL}},                      /* swapon */
        {.slow = 0, .parser = {NULL}},                      /* swapoff */
        {.slow = 0, .parser = {NULL}},                      /* reboot */
        {.slow = 0, .parser = {NULL}},                      /* sethostname */
        {.slow = 0, .parser = {NULL}},                      /* setdomainname */
        {.slow = 0, .parser = {NULL}},                      /* iopl */
        {.slow = 0, .parser = {NULL}},                      /* ioperm */
        {.slow = 0, .parser = {NULL}},                      /* create_module */
        {.slow = 0, .parser = {NULL}},                      /* init_module */
        {.slow = 0, .parser = {NULL}},                      /* delete_module */
        {.slow = 0, .parser = {NULL}},                      /* get_kernel_syms */
        {.slow = 0, .parser = {NULL}},                      /* query_module */
        {.slow = 0, .parser = {NULL}},                      /* quotactl */
        {.slow = 0, .parser = {NULL}},                      /* nfsservctl */
        {.slow = 0, .parser = {NULL}},                      /* getpmsg */
        {.slow = 0, .parser = {NULL}},                      /* putpmsg */
        {.slow = 0, .parser = {NULL}},                      /* afs_syscall */
        {.slow = 0, .parser = {NULL}},                      /* tuxcall */
        {.slow = 0, .parser = {NULL}},                      /* security */
        {.slow = 0, .parser = {NULL}},                      /* gettid */
        {.slow = 0, .parser = {NULL}},                      /* readahead */
        {.slow = 0, .parser = {NULL}},                      /* setxattr */
        {.slow = 0, .parser = {NULL}},                      /* lsetxattr */
        {.slow = 0, .parser = {NULL}},                      /* fsetxattr */
        {.slow = 0, .parser = {NULL}},                      /* getxattr */
        {.slow = 0, .parser = {NULL}},                      /* lgetxattr */
        {.slow = 0, .parser = {NULL}},                      /* fgetxattr */
        {.slow = 0, .parser = {NULL}},                      /* listxattr */
        {.slow = 0, .parser = {NULL}},                      /* llistxattr */
        {.slow = 0, .parser = {NULL}},                      /* flistxattr */
        {.slow = 0, .parser = {NULL}},                      /* removexattr */
        {.slow = 0, .parser = {NULL}},                      /* lremovexattr */
        {.slow = 0, .parser = {NULL}},                      /* fremovexattr */
        {.slow = 0, .parser = {NULL, &parse_signum}},       /* tkill */
        {.slow = 0, .parser = {NULL}},                      /* time */
        {.slow = 1, .parser = {NULL, &parse_futexop}},      /* futex */
        {.slow = 0, .parser = {NULL}},                      /* sched_setaffinity */
        {.slow = 0, .parser = {NULL}},                      /* sched_getaffinity */
        {.slow = 0, .parser = {NULL}},                      /* set_thread_area */
        {.slow = 0, .parser = {NULL}},                      /* io_setup */
        {.slow = 0, .parser = {NULL}},                      /* io_destroy */
        {.slow = 0, .parser = {NULL}},                      /* io_getevents */
        {.slow = 0, .parser = {NULL}},                      /* io_submit */
        {.slow = 0, .parser = {NULL}},                      /* io_cancel */
        {.slow = 0, .parser = {NULL}},                      /* get_thread_area */
        {.slow = 0, .parser = {NULL}},                      /* lookup_dcookie */
        {.slow = 0, .parser = {NULL}},                      /* epoll_create */
        {.slow = 0, .parser = {NULL}},                      /* epoll_ctl_old */
        {.slow = 0, .parser = {NULL}},                      /* epoll_wait_old */
        {.slow = 0, .parser = {NULL}},                      /* remap_file_pages */
        {.slow = 0, .parser = {NULL}},                      /* getdents64 */
        {.slow = 0, .parser = {NULL}},                      /* set_tid_address */
        {.slow = 0, .parser = {NULL}},                      /* restart_syscall */
        {.slow = 0, .parser = {NULL}},                      /* semtimedop */
        {.slow = 0, .parser = {NULL}},                      /* fadvise64 */
        {.slow = 0, .parser = {NULL}},                      /* timer_create */
        {.slow = 0, .parser = {NULL}},                      /* timer_settime */
        {.slow = 0, .parser = {NULL}},                      /* timer_gettime */
        {.slow = 0, .parser = {NULL}},                      /* timer_getoverrun */
        {.slow = 0, .parser = {NULL}},                      /* timer_delete */
        {.slow = 0, .parser = {NULL}},                      /* clock_settime */
        {.slow = 0, .parser = {NULL}},                      /* clock_gettime */
        {.slow = 0, .parser = {NULL}},                      /* clock_getres */
        {.slow = 0, .parser = {NULL}},                      /* clock_nanosleep */
        {.slow = 0, .parser = {NULL}},                      /* exit_group */
        {.slow = 1, .parser = {NULL}},                      /* epoll_wait */
        {.slow = 0, .parser = {NULL}},                      /* epoll_ctl */
        {.slow = 0, .parser = {NULL, NULL, &parse_signum}}, /* tgkill */
        {.slow = 0, .parser = {NULL}},                      /* utimes */
        {.slow = 0, .parser = {NULL}},                      /* vserver */
        {.slow = 0, .parser = {NULL}},                      /* mbind */
        {.slow = 0, .parser = {NULL}},                      /* set_mempolicy */
        {.slow = 0, .parser = {NULL}},                      /* get_mempolicy */
        {.slow = 0, .parser = {NULL}},                      /* mq_open */
        {.slow = 0, .parser = {NULL}},                      /* mq_unlink */
        {.slow = 0, .parser = {NULL}},                      /* mq_timedsend */
        {.slow = 0, .parser = {NULL}},                      /* mq_timedreceive */
        {.slow = 0, .parser = {NULL}},                      /* mq_notify */
        {.slow = 0, .parser = {NULL}},                      /* mq_getsetattr */
        {.slow = 0, .parser = {NULL}},                      /* kexec_load */
        {.slow = 1, .parser = {NULL}},                      /* waitid */
        {.slow = 0, .parser = {NULL}},                      /* add_key */
        {.slow = 0, .parser = {NULL}},                      /* request_key */
        {.slow = 0, .parser = {NULL}},                      /* keyctl */
        {.slow = 0, .parser = {NULL}},                      /* ioprio_set */
        {.slow = 0, .parser = {NULL}},                      /* ioprio_get */
        {.slow = 0, .parser = {NULL}},                      /* inotify_init */
        {.slow = 0, .parser = {NULL}},                      /* inotify_add_watch */
        {.slow = 0, .parser = {NULL}},                      /* inotify_rm_watch */
        {.slow = 0, .parser = {NULL}},                      /* migrate_pages */
        {.slow   = 0,
         .parser = {&parse_at_fdcwd, NULL, &parse_open_flags, &parse_open_mode}}, /* openat */
        {.slow = 0, .parser = {&parse_at_fdcwd}}, /* mkdirat */
        {.slow = 0, .parser = {&parse_at_fdcwd}}, /* mknodat */
        {.slow = 0, .parser = {&parse_at_fdcwd}}, /* fchownat */
        {.slow = 0, .parser = {&parse_at_fdcwd}}, /* futimesat */
        {.slow = 0, .parser = {&parse_at_fdcwd}}, /* newfstatat */
        {.slow = 0, .parser = {&parse_at_fdcwd}}, /* unlinkat */
        {.slow = 0, .parser = {&parse_at_fdcwd}}, /* renameat */
        {.slow = 0, .parser = {&parse_at_fdcwd}}, /* linkat */
        {.slow = 0, .parser = {&parse_at_fdcwd}}, /* symlinkat */
        {.slow = 0, .parser = {&parse_at_fdcwd}}, /* readlinkat */
        {.slow = 0, .parser = {&parse_at_fdcwd}}, /* fchmodat */
        {.slow = 0, .parser = {&parse_at_fdcwd}}, /* faccessat */
        {.slow = 0, .parser = {NULL}}, /* pselect6 */
        {.slow = 1, .parser = {NULL}}, /* ppoll */
        {.slow = 0, .parser = {NULL}}, /* unshare */
        {.slow = 0, .parser = {NULL}}, /* set_robust_list */
        {.slow = 0, .parser = {NULL}}, /* get_robust_list */
        {.slow = 0, .parser = {NULL}}, /* splice */
        {.slow = 0, .parser = {NULL}}, /* tee */
        {.slow = 0, .parser = {NULL}}, /* sync_file_range */
        {.slow = 0, .parser = {NULL}}, /* vmsplice */
        {.slow = 0, .parser = {NULL}}, /* move_pages */
        {.slow = 0, .parser = {NULL}}, /* utimensat */
        {.slow = 1, .parser = {NULL}}, /* epoll_pwait */
        {.slow = 0, .parser = {NULL}}, /* signalfd */
        {.slow = 0, .parser = {NULL}}, /* timerfd_create */
        {.slow = 0, .parser = {NULL}}, /* eventfd */
        {.slow = 0, .parser = {NULL}}, /* fallocate */
        {.slow = 0, .parser = {NULL}}, /* timerfd_settime */
        {.slow = 0, .parser = {NULL}}, /* timerfd_gettime */
        {.slow = 1, .parser = {NULL}}, /* accept4 */
        {.slow = 0, .parser = {NULL}}, /* signalfd4 */
        {.slow = 0, .parser = {NULL}}, /* eventfd2 */
        {.slow = 0, .parser = {NULL}}, /* epoll_create1 */
        {.slow = 0, .parser = {NULL}}, /* dup3 */
        {.slow = 0, .parser = {NULL}}, /* pipe2 */
        {.slow = 0, .parser = {NULL}}, /* inotify_init1 */
        {.slow = 0, .parser = {NULL}}, /* preadv */
        {.slow = 0, .parser = {NULL}}, /* pwritev */
        {.slow = 0, .parser = {NULL}}, /* rt_tgsigqueueinfo */
        {.slow = 0, .parser = {NULL}}, /* perf_event_open */
        {.slow = 0, .parser = {NULL}}, /* recvmmsg */

        [LIBOS_SYSCALL_BASE] = {.slow = 0, .parser = {NULL}},

        {.slow = 1, .parser = {NULL}}, /* checkpoint */
        {.slow = 1, .parser = {NULL}}, /* restore */
        {.slow = 1, .parser = {NULL}}, /* msgpersist */
        {.slow = 1, .parser = {NULL}}, /* benchmark_ipc */
        {.slow = 1, .parser = {NULL}}, /* send_rpc */
        {.slow = 1, .parser = {NULL}}, /* recv_rpc */
};

static inline int is_pointer(const char* type) {
    return type[strlen(type) - 1] == '*' || !strcmp_static(type, "long") ||
           !strcmp_static(type, "unsigned long");
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
#define VPRINTF(fmt, ap)        \
    do {                        \
        debug_vprintf(fmt, ap); \
    } while (0)

static inline void parse_string_arg(va_list ap) {
    va_list ap_test_arg;
    va_copy(ap_test_arg, ap);
    const char* test_arg = va_arg(ap_test_arg, const char*);
    if (!test_user_string(test_arg)) {
        VPRINTF("\"%s\"", ap);
    } else {
        /* invalid memory region, print arg as ptr not string */
        VPRINTF("\"(invalid-addr %p)\"", ap);
    }
    va_end(ap_test_arg);
}

static inline void parse_pointer_arg(va_list ap) {
    VPRINTF("%p", ap);
}

static inline void parse_integer_arg(va_list ap) {
    VPRINTF("%d", ap);
}

static inline void parse_syscall_args(va_list ap) {
    const char* arg_type = va_arg(ap, const char*);

    if (!strcmp_static(arg_type, "const char *") || !strcmp_static(arg_type, "const char*"))
        parse_string_arg(ap);
    else if (is_pointer(arg_type))
        parse_pointer_arg(ap);
    else
        parse_integer_arg(ap);
}

static inline void skip_syscall_args(va_list ap) {
    const char* arg_type = va_arg(ap, const char*);

    if (!strcmp_static(arg_type, "const char *") || !strcmp_static(arg_type, "const char*"))
        va_arg(ap, const char*);
    else if (is_pointer(arg_type))
        va_arg(ap, void*);
    else
        va_arg(ap, int);
}

void sysparser_printf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    VPRINTF(fmt, ap);
    va_end(ap);
}

void parse_syscall_before(int sysno, const char* name, int nr, ...) {
    if (!debug_handle)
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
            (*parser->parser[i])(ap);
        } else {
            parse_syscall_args(ap);
        }
    }

    PUTCH(')');
dotdotdot:
    PRINTF(" ... %s\n", name);
    va_end(ap);
}

void parse_syscall_after(int sysno, const char* name, int nr, ...) {
    if (!debug_handle)
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
                skip_syscall_args(ap);
                continue;
            }

            if (i)
                PUTCH(',');

            if (parser->parser[i]) {
                const char* type = va_arg(ap, const char*);
                __UNUSED(type);  // type not needed on this path
                (*parser->parser[i])(ap);
            } else {
                parse_syscall_args(ap);
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

static void parse_open_flags(va_list ap) {
    int flags = va_arg(ap, int);

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

static void parse_open_mode(va_list ap) {
    VPRINTF("%04o", ap);
}

static void parse_access_mode(va_list ap) {
    int mode = va_arg(ap, int);

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

static void parse_clone_flags(va_list ap) {
    int flags = va_arg(ap, int);

#define FLG(n) \
    { "CLONE_" #n, CLONE_##n, }
    const struct {
        const char* name;
        int flag;
    } all_flags[] = {
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

    bool printed = false;
    for (size_t i = 0; i < ARRAY_SIZE(all_flags); i++)
        if (flags & all_flags[i].flag) {
            if (printed)
                PUTCH('|');
            else
                printed = true;
            PUTS(all_flags[i].name);
            flags &= ~all_flags[i].flag;
        }

#define CLONE_SIGNAL_MASK 0xff
    int exit_signal = flags & CLONE_SIGNAL_MASK;
    flags &= ~CLONE_SIGNAL_MASK;
    if (exit_signal) {
        if (exit_signal >= 0 && exit_signal <= NUM_KNOWN_SIGS)
            PRINTF("|%s", signal_name(exit_signal));
        else
            PRINTF("|[SIG %d]", exit_signal);
    }

    if (flags)
        PRINTF("|0x%x", flags);
}

static void parse_mmap_prot(va_list ap) {
    int prot   = va_arg(ap, int);
    int nflags = 0;

    if (prot == PROT_NONE) {
        PUTS("PROT_NONE");
        return;
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
}

static void parse_mmap_flags(va_list ap) {
    int flags = va_arg(ap, int);

    if (flags & MAP_SHARED) {
        PUTS("MAP_SHARED");
        flags &= ~MAP_SHARED;
    }

    if (flags & MAP_PRIVATE) {
        PUTS("MAP_PRIVATE");
        flags &= ~MAP_PRIVATE;
    }

    if (flags & MAP_ANONYMOUS) {
        PUTS("|MAP_ANON");
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

    if (flags)
        PRINTF("|0x%x", flags);
}

static void parse_exec_args(va_list ap) {
    const char** args = va_arg(ap, const char**);

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

static void parse_exec_envp(va_list ap) {
    const char** envp = va_arg(ap, const char**);

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

static void parse_pipe_fds(va_list ap) {
    int* fds = va_arg(ap, int*);

    if (test_user_memory(fds, 2 * sizeof(*fds), false)) {
        PRINTF("[invalid-addr %p]", fds);
        return;
    }
    PRINTF("[%d, %d]", fds[0], fds[1]);
}

#define S(sig) #sig

const char* const siglist[NUM_KNOWN_SIGS + 1] = {
    S(SIGUNUSED), S(SIGHUP),  S(SIGINT),    S(SIGQUIT), S(SIGILL),   S(SIGTRAP),   S(SIGABRT),
    S(SIGBUS),    S(SIGFPE),  S(SIGKILL),   S(SIGUSR1), S(SIGSEGV),  S(SIGUSR2),   S(SIGPIPE),
    S(SIGALRM),   S(SIGTERM), S(SIGSTKFLT), S(SIGCHLD), S(SIGCONT),  S(SIGSTOP),   S(SIGTSTP),
    S(SIGTTIN),   S(SIGTTOU), S(SIGURG),    S(SIGXCPU), S(SIGXFSZ),  S(SIGVTALRM), S(SIGPROF),
    S(SIGWINCH),  S(SIGIO),   S(SIGPWR),    S(SIGSYS),  S(SIGRTMIN),
};

static void parse_signum(va_list ap) {
    int signum = va_arg(ap, int);

    if (signum >= 0 && signum <= NUM_KNOWN_SIGS)
        PUTS(signal_name(signum));
    else
        PRINTF("[SIG %d]", signum);
}

static void parse_sigmask(va_list ap) {
    __sigset_t* sigset = va_arg(ap, __sigset_t*);

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
            PUTS(signal_name(signum));
            PUTS(",");
        }

    PUTS("]");
}

static void parse_sigprocmask_how(va_list ap) {
    int how = va_arg(ap, int);

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

static void parse_timespec(va_list ap) {
    const struct timespec* tv = va_arg(ap, const struct timespec*);

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

static void parse_sockaddr(va_list ap) {
    const struct sockaddr* addr = va_arg(ap, const struct sockaddr*);

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

static void parse_domain(va_list ap) {
    int domain = va_arg(ap, int);

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

static void parse_socktype(va_list ap) {
    int socktype = va_arg(ap, int);

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

static void parse_futexop(va_list ap) {
    int op = va_arg(ap, int);

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

static void parse_fcntlop(va_list ap) {
    int op = va_arg(ap, int);

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

static void parse_ioctlop(va_list ap) {
    int op = va_arg(ap, int);

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

static void parse_seek(va_list ap) {
    int seek = va_arg(ap, int);

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

static void parse_at_fdcwd(va_list ap) {
    int fd = va_arg(ap, int);

    switch (fd) {
        case AT_FDCWD:
            PUTS("AT_FDCWD");
            break;
        default:
            PRINTF("%d", fd);
            break;
    }
}

static void parse_wait_option(va_list ap) {
    int option = va_arg(ap, int);

    if (option & WNOHANG)
        PUTS("WNOHANG");
}
