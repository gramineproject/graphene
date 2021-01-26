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

static void parse_string_arg(va_list* ap);
static void parse_pointer_arg(va_list* ap);
static void parse_long_arg(va_list* ap);
static void parse_integer_arg(va_list* ap);
static void parse_pointer_ret(va_list* ap);

struct parser_table {
    /* True if this syscall can block (in such case debug info will be printed both before and after
     * the syscall). */
    bool slow;
    /* Name of the syscall */
    const char* name;
    /* Array of parsers; first for the return value, possibly followed by 6 for arguments. Parsing
     * stops at first `NULL` (or when all 6 argument parsers are used, whichever happens first). */
    void (*parser[7])(va_list*);
} syscall_parser_table[LIBOS_SYSCALL_BOUND] = {
    [__NR_read] = {.slow = true, .name = "read", .parser = {parse_long_arg, parse_integer_arg,
                   parse_pointer_arg, parse_pointer_arg}},
    [__NR_write] = {.slow = true, .name = "write", .parser = {parse_long_arg, parse_integer_arg,
                    parse_pointer_arg, parse_pointer_arg}},
    [__NR_open] = {.slow = true, .name = "open", .parser = {parse_long_arg, parse_string_arg,
                   parse_open_flags, parse_open_mode}},
    [__NR_close] = {.slow = false, .name = "close", .parser = {parse_long_arg, parse_integer_arg}},
    [__NR_stat] = {.slow = false, .name = "stat", .parser = {parse_long_arg, parse_string_arg,
                   parse_pointer_arg}},
    [__NR_fstat] = {.slow = false, .name = "fstat", .parser = {parse_long_arg, parse_integer_arg,
                    parse_pointer_arg}},
    [__NR_lstat] = {.slow = false, .name = "lstat", .parser = {parse_long_arg, parse_string_arg,
                    parse_pointer_arg}},
    [__NR_poll] = {.slow = true, .name = "poll", .parser = {parse_long_arg, parse_pointer_arg,
                   parse_integer_arg, parse_integer_arg}},
    [__NR_lseek] = {.slow = false, .name = "lseek", .parser = {parse_long_arg, parse_integer_arg,
                    parse_long_arg, parse_seek}},
    [__NR_mmap] = {.slow = true, .name = "mmap", .parser = {parse_pointer_ret, parse_pointer_arg,
                   parse_pointer_arg, parse_mmap_prot, parse_mmap_flags, parse_integer_arg,
                   parse_long_arg}},
    [__NR_mprotect] = {.slow = true, .name = "mprotect", .parser = {parse_long_arg,
                       parse_pointer_arg, parse_pointer_arg, parse_mmap_prot}},
    [__NR_munmap] = {.slow = true, .name = "munmap", .parser = {parse_long_arg, parse_pointer_arg,
                     parse_pointer_arg}},
    [__NR_brk] = {.slow = false, .name = "brk", .parser = {parse_pointer_ret, parse_pointer_arg}},
    [__NR_rt_sigaction] = {.slow = false, .name = "rt_sigaction", .parser = {parse_long_arg,
                           parse_signum, parse_pointer_arg, parse_pointer_arg, parse_pointer_arg}},
    [__NR_rt_sigprocmask] = {.slow = false, .name = "rt_sigprocmask", .parser = {parse_long_arg,
                             parse_sigprocmask_how, parse_sigmask, parse_sigmask}},
    [__NR_rt_sigreturn] = {.slow = false, .name = "rt_sigreturn", .parser = {NULL}},
    [__NR_ioctl] = {.slow = true, .name = "ioctl", .parser = {parse_long_arg, parse_integer_arg,
                    parse_ioctlop, parse_pointer_arg}},
    [__NR_pread64] = {.slow = true, .name = "pread64", .parser = {parse_long_arg, parse_integer_arg,
                      parse_pointer_arg, parse_pointer_arg, parse_long_arg}},
    [__NR_pwrite64] = {.slow = false, .name = "pwrite64", .parser = {parse_long_arg,
                       parse_integer_arg, parse_pointer_arg, parse_pointer_arg, parse_long_arg}},
    [__NR_readv] = {.slow = true, .name = "readv", .parser = {parse_long_arg, parse_integer_arg,
                    parse_pointer_arg, parse_integer_arg}},
    [__NR_writev] = {.slow = false, .name = "writev", .parser = {parse_long_arg, parse_integer_arg,
                     parse_pointer_arg, parse_integer_arg}},
    [__NR_access] = {.slow = false, .name = "access", .parser = {parse_long_arg, parse_string_arg,
                     parse_access_mode}},
    [__NR_pipe] = {.slow = false, .name = "pipe", .parser = {parse_long_arg, parse_pipe_fds}},
    [__NR_select] = {.slow = true, .name = "select", .parser = {parse_long_arg, parse_integer_arg,
                     parse_pointer_arg, parse_pointer_arg, parse_pointer_arg, parse_pointer_arg}},
    [__NR_sched_yield] = {.slow = false, .name = "sched_yield", .parser = {parse_long_arg}},
    [__NR_mremap] = {.slow = false, .name = "mremap", .parser = {NULL}},
    [__NR_msync] = {.slow = false, .name = "msync", .parser = {NULL}},
    [__NR_mincore] = {.slow = false, .name = "mincore", .parser = {parse_long_arg,
                      parse_pointer_arg, parse_pointer_arg, parse_pointer_arg}},
    [__NR_madvise] = {.slow = false, .name = "madvise", .parser = {parse_long_arg,
                      parse_pointer_arg, parse_pointer_arg, parse_madvise_behavior}},
    [__NR_shmget] = {.slow = false, .name = "shmget", .parser = {NULL}},
    [__NR_shmat] = {.slow = false, .name = "shmat", .parser = {NULL}},
    [__NR_shmctl] = {.slow = false, .name = "shmctl", .parser = {NULL}},
    [__NR_dup] = {.slow = false, .name = "dup", .parser = {parse_long_arg, parse_integer_arg}},
    [__NR_dup2] = {.slow = false, .name = "dup2", .parser = {parse_long_arg, parse_integer_arg,
                   parse_integer_arg}},
    [__NR_pause] = {.slow = true, .name = "pause", .parser = {parse_long_arg}},
    [__NR_nanosleep] = {.slow = true, .name = "nanosleep", .parser = {parse_long_arg,
                        parse_timespec, parse_pointer_arg}},
    [__NR_getitimer] = {.slow = false, .name = "getitimer", .parser = {parse_long_arg,
                        parse_integer_arg, parse_pointer_arg}},
    [__NR_alarm] = {.slow = false, .name = "alarm", .parser = {parse_long_arg, parse_integer_arg}},
    [__NR_setitimer] = {.slow = false, .name = "setitimer", .parser = {parse_long_arg,
                        parse_integer_arg, parse_pointer_arg, parse_pointer_arg}},
    [__NR_getpid] = {.slow = false, .name = "getpid", .parser = {parse_long_arg}},
    [__NR_sendfile] = {.slow = false, .name = "sendfile", .parser = {parse_long_arg,
                       parse_integer_arg, parse_integer_arg, parse_pointer_arg, parse_pointer_arg}},
    [__NR_socket] = {.slow = false, .name = "socket", .parser = {parse_long_arg, parse_domain,
                     parse_socktype, parse_integer_arg}},
    [__NR_connect] = {.slow = true, .name = "connect", .parser = {parse_long_arg, parse_integer_arg,
                      parse_sockaddr, parse_integer_arg}},
    [__NR_accept] = {.slow = true, .name = "accept", .parser = {parse_long_arg, parse_integer_arg,
                     parse_pointer_arg, parse_pointer_arg}},
    [__NR_sendto] = {.slow = false, .name = "sendto", .parser = {parse_long_arg, parse_integer_arg,
                     parse_pointer_arg, parse_pointer_arg, parse_integer_arg, parse_pointer_arg,
                     parse_integer_arg}},
    [__NR_recvfrom] = {.slow = false, .name = "recvfrom", .parser = {parse_long_arg,
                       parse_integer_arg, parse_pointer_arg, parse_pointer_arg, parse_integer_arg,
                       parse_pointer_arg, parse_pointer_arg}},
    [__NR_sendmsg] = {.slow = false, .name = "sendmsg", .parser = {parse_long_arg,
                      parse_integer_arg, parse_pointer_arg, parse_integer_arg}},
    [__NR_recvmsg] = {.slow = true, .name = "recvmsg", .parser = {parse_long_arg, parse_integer_arg,
                      parse_pointer_arg, parse_integer_arg}},
    [__NR_shutdown] = {.slow = false, .name = "shutdown", .parser = {parse_long_arg,
                       parse_integer_arg, parse_integer_arg}},
    [__NR_bind] = {.slow = false, .name = "bind", .parser = {parse_long_arg, parse_integer_arg,
                   parse_pointer_arg, parse_integer_arg}},
    [__NR_listen] = {.slow = false, .name = "listen", .parser = {parse_long_arg, parse_integer_arg,
                     parse_integer_arg}},
    [__NR_getsockname] = {.slow = false, .name = "getsockname", .parser = {parse_long_arg,
                          parse_integer_arg, parse_pointer_arg, parse_pointer_arg}},
    [__NR_getpeername] = {.slow = false, .name = "getpeername", .parser = {parse_long_arg,
                          parse_integer_arg, parse_pointer_arg, parse_pointer_arg}},
    [__NR_socketpair] = {.slow = false, .name = "socketpair", .parser = {parse_long_arg,
                         parse_domain, parse_socktype, parse_integer_arg, parse_pipe_fds}},
    [__NR_setsockopt] = {.slow = false, .name = "setsockopt", .parser = {parse_long_arg,
                         parse_integer_arg, parse_integer_arg, parse_integer_arg, parse_pointer_arg,
                         parse_integer_arg}},
    [__NR_getsockopt] = {.slow = false, .name = "getsockopt", .parser = {parse_long_arg,
                         parse_integer_arg, parse_integer_arg, parse_integer_arg, parse_pointer_arg,
                         parse_pointer_arg}},
    [__NR_clone] = {.slow = true, .name = "clone", .parser = {parse_long_arg, parse_clone_flags,
                    parse_pointer_arg, parse_pointer_arg, parse_pointer_arg, parse_pointer_arg}},
    [__NR_fork] = {.slow = true, .name = "fork", .parser = {parse_long_arg}},
    [__NR_vfork] = {.slow = true, .name = "vfork", .parser = {parse_long_arg}},
    [__NR_execve] = {.slow = true, .name = "execve", .parser = {parse_long_arg, parse_string_arg,
                     parse_exec_args, parse_exec_envp}},
    [__NR_exit] = {.slow = false, .name = "exit", .parser = {parse_long_arg, parse_integer_arg}},
    [__NR_wait4] = {.slow = true, .name = "wait4", .parser = {parse_long_arg, parse_integer_arg,
                    parse_pointer_arg, parse_wait_options, parse_pointer_arg}},
    [__NR_kill] = {.slow = false, .name = "kill", .parser = {parse_long_arg, parse_integer_arg,
                   parse_signum}},
    [__NR_uname] = {.slow = false, .name = "uname", .parser = {parse_long_arg, parse_pointer_arg}},
    [__NR_semget] = {.slow = false, .name = "semget", .parser = {parse_long_arg, parse_integer_arg,
                     parse_integer_arg, parse_integer_arg}},
    [__NR_semop] = {.slow = true, .name = "semop", .parser = {parse_long_arg, parse_integer_arg,
                    parse_pointer_arg, parse_integer_arg}},
    [__NR_semctl] = {.slow = false, .name = "semctl", .parser = {parse_long_arg, parse_integer_arg,
                     parse_integer_arg, parse_integer_arg, parse_pointer_arg}},
    [__NR_shmdt] = {.slow = false, .name = "shmdt", .parser = {NULL}},
    [__NR_msgget] = {.slow = true, .name = "msgget", .parser = {parse_long_arg, parse_integer_arg,
                     parse_integer_arg}},
    [__NR_msgsnd] = {.slow = true, .name = "msgsnd", .parser = {parse_long_arg, parse_integer_arg,
                     parse_pointer_arg, parse_pointer_arg, parse_integer_arg}},
    [__NR_msgrcv] = {.slow = true, .name = "msgrcv", .parser = {parse_long_arg, parse_integer_arg,
                     parse_pointer_arg, parse_pointer_arg, parse_long_arg, parse_integer_arg}},
    [__NR_msgctl] = {.slow = true, .name = "msgctl", .parser = {parse_long_arg, parse_integer_arg,
                     parse_integer_arg, parse_pointer_arg}},
    [__NR_fcntl] = {.slow = false, .name = "fcntl", .parser = {parse_long_arg, parse_integer_arg,
                    parse_fcntlop, parse_pointer_arg}},
    [__NR_flock] = {.slow = false, .name = "flock", .parser = {NULL}},
    [__NR_fsync] = {.slow = false, .name = "fsync", .parser = {parse_long_arg, parse_integer_arg}},
    [__NR_fdatasync] = {.slow = false, .name = "fdatasync", .parser = {parse_long_arg,
                        parse_integer_arg}},
    [__NR_truncate] = {.slow = false, .name = "truncate", .parser = {parse_long_arg,
                       parse_string_arg, parse_long_arg}},
    [__NR_ftruncate] = {.slow = false, .name = "ftruncate", .parser = {parse_long_arg,
                        parse_integer_arg, parse_long_arg}},
    [__NR_getdents] = {.slow = false, .name = "getdents", .parser = {parse_long_arg,
                       parse_integer_arg, parse_pointer_arg, parse_pointer_arg}},
    [__NR_getcwd] = {.slow = false, .name = "getcwd", .parser = {parse_long_arg, parse_pointer_arg,
                     parse_pointer_arg}},
    [__NR_chdir] = {.slow = false, .name = "chdir", .parser = {parse_long_arg, parse_string_arg}},
    [__NR_fchdir] = {.slow = false, .name = "fchdir", .parser = {parse_long_arg,
                     parse_integer_arg}},
    [__NR_rename] = {.slow = false, .name = "rename", .parser = {parse_long_arg, parse_string_arg,
                     parse_string_arg}},
    [__NR_mkdir] = {.slow = false, .name = "mkdir", .parser = {parse_long_arg, parse_string_arg,
                    parse_integer_arg}},
    [__NR_rmdir] = {.slow = false, .name = "rmdir", .parser = {parse_long_arg, parse_string_arg}},
    [__NR_creat] = {.slow = false, .name = "creat", .parser = {parse_long_arg, parse_string_arg,
                    parse_open_mode}},
    [__NR_link] = {.slow = false, .name = "link", .parser = {NULL}},
    [__NR_unlink] = {.slow = false, .name = "unlink", .parser = {parse_long_arg, parse_string_arg}},
    [__NR_symlink] = {.slow = false, .name = "symlink", .parser = {NULL}},
    [__NR_readlink] = {.slow = false, .name = "readlink", .parser = {parse_long_arg,
                       parse_string_arg, parse_pointer_arg, parse_integer_arg}},
    [__NR_chmod] = {.slow = false, .name = "chmod", .parser = {parse_long_arg, parse_string_arg,
                    parse_integer_arg}},
    [__NR_fchmod] = {.slow = false, .name = "fchmod", .parser = {parse_long_arg, parse_integer_arg,
                     parse_integer_arg}},
    [__NR_chown] = {.slow = false, .name = "chown", .parser = {parse_long_arg, parse_string_arg,
                    parse_integer_arg, parse_integer_arg}},
    [__NR_fchown] = {.slow = false, .name = "fchown", .parser = {parse_long_arg, parse_integer_arg,
                     parse_integer_arg, parse_integer_arg}},
    [__NR_lchown] = {.slow = false, .name = "lchown", .parser = {NULL}},
    [__NR_umask] = {.slow = false, .name = "umask", .parser = {parse_long_arg, parse_integer_arg}},
    [__NR_gettimeofday] = {.slow = false, .name = "gettimeofday", .parser = {parse_long_arg,
                           parse_pointer_arg, parse_pointer_arg}},
    [__NR_getrlimit] = {.slow = false, .name = "getrlimit", .parser = {parse_long_arg,
                        parse_integer_arg, parse_pointer_arg}},
    [__NR_getrusage] = {.slow = false, .name = "getrusage", .parser = {NULL}},
    [__NR_sysinfo] = {.slow = false, .name = "sysinfo", .parser = {NULL}},
    [__NR_times] = {.slow = false, .name = "times", .parser = {NULL}},
    [__NR_ptrace] = {.slow = false, .name = "ptrace", .parser = {NULL}},
    [__NR_getuid] = {.slow = false, .name = "getuid", .parser = {parse_long_arg}},
    [__NR_syslog] = {.slow = false, .name = "syslog", .parser = {NULL}},
    [__NR_getgid] = {.slow = false, .name = "getgid", .parser = {parse_long_arg}},
    [__NR_setuid] = {.slow = false, .name = "setuid", .parser = {parse_long_arg,
                     parse_integer_arg}},
    [__NR_setgid] = {.slow = false, .name = "setgid", .parser = {parse_long_arg,
                     parse_integer_arg}},
    [__NR_geteuid] = {.slow = false, .name = "geteuid", .parser = {parse_long_arg}},
    [__NR_getegid] = {.slow = false, .name = "getegid", .parser = {parse_long_arg}},
    [__NR_setpgid] = {.slow = false, .name = "setpgid", .parser = {parse_long_arg,
                      parse_integer_arg, parse_integer_arg}},
    [__NR_getppid] = {.slow = false, .name = "getppid", .parser = {parse_long_arg}},
    [__NR_getpgrp] = {.slow = false, .name = "getpgrp", .parser = {parse_long_arg}},
    [__NR_setsid] = {.slow = false, .name = "setsid", .parser = {parse_long_arg}},
    [__NR_setreuid] = {.slow = false, .name = "setreuid", .parser = {NULL}},
    [__NR_setregid] = {.slow = false, .name = "setregid", .parser = {NULL}},
    [__NR_getgroups] = {.slow = false, .name = "getgroups", .parser = {parse_long_arg,
                        parse_integer_arg, parse_pointer_arg}},
    [__NR_setgroups] = {.slow = false, .name = "setgroups", .parser = {parse_long_arg,
                        parse_integer_arg, parse_pointer_arg}},
    [__NR_setresuid] = {.slow = false, .name = "setresuid", .parser = {NULL}},
    [__NR_getresuid] = {.slow = false, .name = "getresuid", .parser = {NULL}},
    [__NR_setresgid] = {.slow = false, .name = "setresgid", .parser = {NULL}},
    [__NR_getresgid] = {.slow = false, .name = "getresgid", .parser = {NULL}},
    [__NR_getpgid] = {.slow = false, .name = "getpgid", .parser = {parse_long_arg,
                      parse_integer_arg}},
    [__NR_setfsuid] = {.slow = false, .name = "setfsuid", .parser = {NULL}},
    [__NR_setfsgid] = {.slow = false, .name = "setfsgid", .parser = {NULL}},
    [__NR_getsid] = {.slow = false, .name = "getsid", .parser = {parse_long_arg,
                     parse_integer_arg}},
    [__NR_capget] = {.slow = false, .name = "capget", .parser = {NULL}},
    [__NR_capset] = {.slow = false, .name = "capset", .parser = {NULL}},
    [__NR_rt_sigpending] = {.slow = false, .name = "rt_sigpending", .parser = {parse_long_arg,
                            parse_pointer_arg, parse_pointer_arg}},
    [__NR_rt_sigtimedwait] = {.slow = false, .name = "rt_sigtimedwait", .parser = {NULL}},
    [__NR_rt_sigqueueinfo] = {.slow = false, .name = "rt_sigqueueinfo", .parser = {NULL}},
    [__NR_rt_sigsuspend] = {.slow = true, .name = "rt_sigsuspend", .parser = {parse_long_arg,
                            parse_pointer_arg, parse_pointer_arg}},
    [__NR_sigaltstack] = {.slow = false, .name = "sigaltstack", .parser = {parse_long_arg,
                          parse_pointer_arg, parse_pointer_arg}},
    [__NR_utime] = {.slow = false, .name = "utime", .parser = {NULL}},
    [__NR_mknod] = {.slow = false, .name = "mknod", .parser = {parse_long_arg, parse_string_arg,
                    parse_open_mode, parse_integer_arg}},
    [__NR_uselib] = {.slow = false, .name = "uselib", .parser = {NULL}},
    [__NR_personality] = {.slow = false, .name = "personality", .parser = {NULL}},
    [__NR_ustat] = {.slow = false, .name = "ustat", .parser = {NULL}},
    [__NR_statfs] = {.slow = false, .name = "statfs", .parser = {parse_long_arg, parse_string_arg,
                     parse_pointer_arg}},
    [__NR_fstatfs] = {.slow = false, .name = "fstatfs", .parser = {parse_long_arg,
                      parse_integer_arg, parse_pointer_arg}},
    [__NR_sysfs] = {.slow = false, .name = "sysfs", .parser = {NULL}},
    [__NR_getpriority] = {.slow = false, .name = "getpriority", .parser = {parse_long_arg,
                          parse_integer_arg, parse_integer_arg}},
    [__NR_setpriority] = {.slow = false, .name = "setpriority", .parser = {parse_long_arg,
                          parse_integer_arg, parse_integer_arg, parse_integer_arg}},
    [__NR_sched_setparam] = {.slow = false, .name = "sched_setparam", .parser = {parse_long_arg,
                             parse_integer_arg, parse_pointer_arg}},
    [__NR_sched_getparam] = {.slow = false, .name = "sched_getparam", .parser = {parse_long_arg,
                             parse_integer_arg, parse_pointer_arg}},
    [__NR_sched_setscheduler] = {.slow = false, .name = "sched_setscheduler", .parser =
                                 {parse_long_arg, parse_integer_arg, parse_integer_arg,
                                 parse_pointer_arg}},
    [__NR_sched_getscheduler] = {.slow = false, .name = "sched_getscheduler", .parser =
                                 {parse_long_arg, parse_integer_arg}},
    [__NR_sched_get_priority_max] = {.slow = false, .name = "sched_get_priority_max", .parser =
                                     {parse_long_arg, parse_integer_arg}},
    [__NR_sched_get_priority_min] = {.slow = false, .name = "sched_get_priority_min", .parser =
                                     {parse_long_arg, parse_integer_arg}},
    [__NR_sched_rr_get_interval] = {.slow = false, .name = "sched_rr_get_interval", .parser =
                                    {parse_long_arg, parse_integer_arg, parse_pointer_arg}},
    [__NR_mlock] = {.slow = false, .name = "mlock", .parser = {NULL}},
    [__NR_munlock] = {.slow = false, .name = "munlock", .parser = {NULL}},
    [__NR_mlockall] = {.slow = false, .name = "mlockall", .parser = {NULL}},
    [__NR_munlockall] = {.slow = false, .name = "munlockall", .parser = {NULL}},
    [__NR_vhangup] = {.slow = false, .name = "vhangup", .parser = {NULL}},
    [__NR_modify_ldt] = {.slow = false, .name = "modify_ldt", .parser = {NULL}},
    [__NR_pivot_root] = {.slow = false, .name = "pivot_root", .parser = {NULL}},
    [__NR__sysctl] = {.slow = false, .name = "_sysctl", .parser = {NULL}},
    [__NR_prctl] = {.slow = false, .name = "prctl", .parser = {NULL}},
#ifdef __NR_arch_prctl
    [__NR_arch_prctl] = {.slow = false, .name = "arch_prctl", .parser = {parse_long_arg,
                         parse_integer_arg, parse_pointer_arg}},
#endif
    [__NR_adjtimex] = {.slow = false, .name = "adjtimex", .parser = {NULL}},
    [__NR_setrlimit] = {.slow = false, .name = "setrlimit", .parser = {parse_long_arg,
                        parse_integer_arg, parse_pointer_arg}},
    [__NR_chroot] = {.slow = false, .name = "chroot", .parser = {parse_long_arg, parse_string_arg}},
    [__NR_sync] = {.slow = false, .name = "sync", .parser = {NULL}},
    [__NR_acct] = {.slow = false, .name = "acct", .parser = {NULL}},
    [__NR_settimeofday] = {.slow = false, .name = "settimeofday", .parser = {NULL}},
    [__NR_mount] = {.slow = false, .name = "mount", .parser = {NULL}},
    [__NR_umount2] = { .slow = false, .name = "umount2", .parser = {NULL}},
    [__NR_swapon] = {.slow = false, .name = "swapon", .parser = {NULL}},
    [__NR_swapoff] = {.slow = false, .name = "swapoff", .parser = {NULL}},
    [__NR_reboot] = {.slow = false, .name = "reboot", .parser = {NULL}},
    [__NR_sethostname] = {.slow = false, .name = "sethostname", .parser = {parse_long_arg,
                          parse_pointer_arg, parse_integer_arg}},
    [__NR_setdomainname] = {.slow = false, .name = "setdomainname", .parser = {parse_long_arg,
                            parse_pointer_arg, parse_integer_arg}},
#ifdef __NR_iopl
    [__NR_iopl] = {.slow = false, .name = "iopl", .parser = {NULL}},
#endif
#ifdef __NR_ioperm
    [__NR_ioperm] = {.slow = false, .name = "ioperm", .parser = {NULL}},
#endif
    [__NR_create_module] = {.slow = false, .name = "create_module", .parser = {NULL}},
    [__NR_init_module] = {.slow = false, .name = "init_module", .parser = {NULL}},
    [__NR_delete_module] = {.slow = false, .name = "delete_module", .parser = {NULL}},
    [__NR_get_kernel_syms] = {.slow = false, .name = "get_kernel_syms", .parser = {NULL}},
    [__NR_query_module] = {.slow = false, .name = "query_module", .parser = {NULL}},
    [__NR_quotactl] = {.slow = false, .name = "quotactl", .parser = {NULL}},
    [__NR_nfsservctl] = {.slow = false, .name = "nfsservctl", .parser = {NULL}},
    [__NR_getpmsg] = {.slow = false, .name = "getpmsg", .parser = {NULL}},
    [__NR_putpmsg] = {.slow = false, .name = "putpmsg", .parser = {NULL}},
    [__NR_afs_syscall] = {.slow = false, .name = "afs_syscall", .parser = {NULL}},
    [__NR_tuxcall] = {.slow = false, .name = "tuxcall", .parser = {NULL}},
    [__NR_security] = {.slow = false, .name = "security", .parser = {NULL}},
    [__NR_gettid] = {.slow = false, .name = "gettid", .parser = {parse_long_arg}},
    [__NR_readahead] = {.slow = false, .name = "readahead", .parser = {NULL}},
    [__NR_setxattr] = {.slow = false, .name = "setxattr", .parser = {NULL}},
    [__NR_lsetxattr] = {.slow = false, .name = "lsetxattr", .parser = {NULL}},
    [__NR_fsetxattr] = {.slow = false, .name = "fsetxattr", .parser = {NULL}},
    [__NR_getxattr] = {.slow = false, .name = "getxattr", .parser = {NULL}},
    [__NR_lgetxattr] = {.slow = false, .name = "lgetxattr", .parser = {NULL}},
    [__NR_fgetxattr] = {.slow = false, .name = "fgetxattr", .parser = {NULL}},
    [__NR_listxattr] = {.slow = false, .name = "listxattr", .parser = {NULL}},
    [__NR_llistxattr] = {.slow = false, .name = "llistxattr", .parser = {NULL}},
    [__NR_flistxattr] = {.slow = false, .name = "flistxattr", .parser = {NULL}},
    [__NR_removexattr] = {.slow = false, .name = "removexattr", .parser = {NULL}},
    [__NR_lremovexattr] = {.slow = false, .name = "lremovexattr", .parser = {NULL}},
    [__NR_fremovexattr] = {.slow = false, .name = "fremovexattr", .parser = {NULL}},
    [__NR_tkill] = {.slow = false, .name = "tkill", .parser = {parse_long_arg, parse_integer_arg,
                    parse_signum}},
    [__NR_time] = {.slow = false, .name = "time", .parser = {parse_long_arg, parse_pointer_arg}},
    [__NR_futex] = {.slow = true, .name = "futex", .parser = {parse_long_arg, parse_pointer_arg,
                    parse_futexop, parse_integer_arg, parse_pointer_arg, parse_pointer_arg,
                    parse_integer_arg}},
    [__NR_sched_setaffinity] = {.slow = false, .name = "sched_setaffinity", .parser =
                                {parse_long_arg, parse_integer_arg, parse_integer_arg,
                                parse_pointer_arg}},
    [__NR_sched_getaffinity] = {.slow = false, .name = "sched_getaffinity", .parser =
                                {parse_long_arg, parse_integer_arg, parse_integer_arg,
                                parse_pointer_arg}},
#ifdef __NR_set_thread_area
    [__NR_set_thread_area] = {.slow = false, .name = "set_thread_area", .parser = {NULL}},
#endif
    [__NR_io_setup] = {.slow = false, .name = "io_setup", .parser = {NULL}},
    [__NR_io_destroy] = {.slow = false, .name = "io_destroy", .parser = {NULL}},
    [__NR_io_getevents] = {.slow = false, .name = "io_getevents", .parser = {NULL}},
    [__NR_io_submit] = {.slow = false, .name = "io_submit", .parser = {NULL}},
    [__NR_io_cancel] = {.slow = false, .name = "io_cancel", .parser = {NULL}},
#ifdef __NR_get_thread_area
    [__NR_get_thread_area] = {.slow = false, .name = "get_thread_area", .parser = {NULL}},
#endif
    [__NR_lookup_dcookie] = {.slow = false, .name = "lookup_dcookie", .parser = {NULL}},
    [__NR_epoll_create] = {.slow = false, .name = "epoll_create", .parser = {parse_long_arg,
                           parse_integer_arg}},
    [__NR_epoll_ctl_old] = {.slow = false, .name = "epoll_ctl_old", .parser = {NULL}},
    [__NR_epoll_wait_old] = {.slow = false, .name = "epoll_wait_old", .parser = {NULL}},
    [__NR_remap_file_pages] = {.slow = false, .name = "remap_file_pages", .parser = {NULL}},
    [__NR_getdents64] = {.slow = false, .name = "getdents64", .parser = {parse_long_arg,
                         parse_integer_arg, parse_pointer_arg, parse_pointer_arg}},
    [__NR_set_tid_address] = {.slow = false, .name = "set_tid_address", .parser = {parse_long_arg,
                              parse_pointer_arg}},
    [__NR_restart_syscall] = {.slow = false, .name = "restart_syscall", .parser = {NULL}},
    [__NR_semtimedop] = {.slow = false, .name = "semtimedop", .parser = {parse_long_arg,
                         parse_integer_arg, parse_pointer_arg, parse_integer_arg,
                         parse_pointer_arg}},
    [__NR_fadvise64] = {.slow = false, .name = "fadvise64", .parser = {NULL}},
    [__NR_timer_create] = {.slow = false, .name = "timer_create", .parser = {NULL}},
    [__NR_timer_settime] = {.slow = false, .name = "timer_settime", .parser = {NULL}},
    [__NR_timer_gettime] = {.slow = false, .name = "timer_gettime", .parser = {NULL}},
    [__NR_timer_getoverrun] = {.slow = false, .name = "timer_getoverrun", .parser = {NULL}},
    [__NR_timer_delete] = {.slow = false, .name = "timer_delete", .parser = {NULL}},
    [__NR_clock_settime] = {.slow = false, .name = "clock_settime", .parser = {NULL}},
    [__NR_clock_gettime] = {.slow = false, .name = "clock_gettime", .parser = {parse_long_arg,
                            parse_integer_arg, parse_pointer_arg}},
    [__NR_clock_getres] = {.slow = false, .name = "clock_getres", .parser = {parse_long_arg,
                           parse_integer_arg, parse_pointer_arg}},
    [__NR_clock_nanosleep] = {.slow = false, .name = "clock_nanosleep", .parser = {parse_long_arg,
                              parse_integer_arg, parse_integer_arg, parse_pointer_arg,
                              parse_pointer_arg}},
    [__NR_exit_group] = {.slow = false, .name = "exit_group", .parser = {parse_long_arg,
                         parse_integer_arg}},
    [__NR_epoll_wait] = {.slow = true, .name = "epoll_wait", .parser = {parse_long_arg,
                         parse_integer_arg, parse_pointer_arg, parse_integer_arg,
                         parse_integer_arg}},
    [__NR_epoll_ctl] = {.slow = false, .name = "epoll_ctl", .parser = {parse_long_arg,
                        parse_integer_arg, parse_integer_arg, parse_integer_arg,
                        parse_pointer_arg}},
    [__NR_tgkill] = {.slow = false, .name = "tgkill", .parser = {parse_long_arg, parse_integer_arg,
                     parse_integer_arg, parse_signum}},
    [__NR_utimes] = {.slow = false, .name = "utimes", .parser = {NULL}},
#ifdef __NR_vserver
    [__NR_vserver] = {.slow = false, .name = "vserver", .parser = {NULL}},
#endif
    [__NR_mbind] = {.slow = false, .name = "mbind", .parser = {parse_long_arg, parse_pointer_arg,
                    parse_pointer_arg, parse_integer_arg, parse_pointer_arg, parse_pointer_arg,
                    parse_integer_arg}},
    [__NR_set_mempolicy] = {.slow = false, .name = "set_mempolicy", .parser = {NULL}},
    [__NR_get_mempolicy] = {.slow = false, .name = "get_mempolicy", .parser = {NULL}},
    [__NR_mq_open] = {.slow = false, .name = "mq_open", .parser = {NULL}},
    [__NR_mq_unlink] = {.slow = false, .name = "mq_unlink", .parser = {NULL}},
    [__NR_mq_timedsend] = {.slow = false, .name = "mq_timedsend", .parser = {NULL}},
    [__NR_mq_timedreceive] = {.slow = false, .name = "mq_timedreceive", .parser = {NULL}},
    [__NR_mq_notify] = {.slow = false, .name = "mq_notify", .parser = {NULL}},
    [__NR_mq_getsetattr] = {.slow = false, .name = "mq_getsetattr", .parser = {NULL}},
    [__NR_kexec_load] = {.slow = false, .name = "kexec_load", .parser = {NULL}},
    [__NR_waitid] = {.slow = true, .name = "waitid", .parser = {parse_long_arg, parse_waitid_which,
                     parse_integer_arg, parse_pointer_arg, parse_wait_options, parse_pointer_arg}},
    [__NR_add_key] = {.slow = false, .name = "add_key", .parser = {NULL}},
    [__NR_request_key] = {.slow = false, .name = "request_key", .parser = {NULL}},
    [__NR_keyctl] = {.slow = false, .name = "keyctl", .parser = {NULL}},
    [__NR_ioprio_set] = {.slow = false, .name = "ioprio_set", .parser = {NULL}},
    [__NR_ioprio_get] = {.slow = false, .name = "ioprio_get", .parser = {NULL}},
    [__NR_inotify_init] = {.slow = false, .name = "inotify_init", .parser = {NULL}},
    [__NR_inotify_add_watch] = {.slow = false, .name = "inotify_add_watch", .parser = {NULL}},
    [__NR_inotify_rm_watch] = {.slow = false, .name = "inotify_rm_watch", .parser = {NULL}},
    [__NR_migrate_pages] = {.slow = false, .name = "migrate_pages", .parser = {NULL}},
    [__NR_openat] = {.slow = false, .name = "openat", .parser = {parse_long_arg, parse_at_fdcwd,
                     parse_string_arg, parse_open_flags, parse_open_mode}},
    [__NR_mkdirat] = {.slow = false, .name = "mkdirat", .parser = {parse_long_arg, parse_at_fdcwd,
                      parse_string_arg, parse_integer_arg}},
    [__NR_mknodat] = {.slow = false, .name = "mknodat", .parser = {parse_long_arg, parse_at_fdcwd,
                      parse_string_arg, parse_open_mode, parse_integer_arg}},
    [__NR_fchownat] = {.slow = false, .name = "fchownat", .parser = {parse_long_arg, parse_at_fdcwd,
                       parse_string_arg, parse_integer_arg, parse_integer_arg, parse_integer_arg}},
    [__NR_futimesat] = {.slow = false, .name = "futimesat", .parser = {NULL}},
    [__NR_newfstatat] = {.slow = false, .name = "newfstatat", .parser = {parse_long_arg,
                         parse_at_fdcwd, parse_string_arg, parse_pointer_arg, parse_integer_arg}},
    [__NR_unlinkat] = {.slow = false, .name = "unlinkat", .parser = {parse_long_arg, parse_at_fdcwd,
                       parse_string_arg, parse_integer_arg}},
    [__NR_renameat] = {.slow = false, .name = "renameat", .parser = {parse_long_arg, parse_at_fdcwd,
                       parse_string_arg, parse_integer_arg, parse_string_arg}},
    [__NR_linkat] = {.slow = false, .name = "linkat", .parser = {NULL}},
    [__NR_symlinkat] = {.slow = false, .name = "symlinkat", .parser = {NULL}},
    [__NR_readlinkat] = {.slow = false, .name = "readlinkat", .parser = {parse_long_arg,
                         parse_at_fdcwd, parse_string_arg, parse_pointer_arg, parse_integer_arg}},
    [__NR_fchmodat] = {.slow = false, .name = "fchmodat", .parser = {parse_long_arg, parse_at_fdcwd,
                       parse_string_arg, parse_integer_arg}},
    [__NR_faccessat] = {.slow = false, .name = "faccessat", .parser = {parse_long_arg,
                        parse_at_fdcwd, parse_string_arg, parse_integer_arg}},
    [__NR_pselect6] = {.slow = true, .name = "pselect6", .parser = {parse_long_arg,
                       parse_integer_arg, parse_pointer_arg, parse_pointer_arg, parse_pointer_arg,
                       parse_pointer_arg, parse_pointer_arg}},
    [__NR_ppoll] = {.slow = true, .name = "ppoll", .parser = {parse_long_arg, parse_pointer_arg,
                    parse_integer_arg, parse_pointer_arg, parse_pointer_arg, parse_pointer_arg}},
    [__NR_unshare] = {.slow = false, .name = "unshare", .parser = {NULL}},
    [__NR_set_robust_list] = {.slow = false, .name = "set_robust_list", .parser = {parse_long_arg,
                              parse_pointer_arg, parse_pointer_arg}},
    [__NR_get_robust_list] = {.slow = false, .name = "get_robust_list", .parser = {parse_long_arg,
                              parse_integer_arg, parse_pointer_arg, parse_pointer_arg}},
    [__NR_splice] = {.slow = false, .name = "splice", .parser = {NULL}},
    [__NR_tee] = {.slow = false, .name = "tee", .parser = {NULL}},
    [__NR_sync_file_range] = {.slow = false, .name = "sync_file_range", .parser = {NULL}},
    [__NR_vmsplice] = {.slow = false, .name = "vmsplice", .parser = {NULL}},
    [__NR_move_pages] = {.slow = false, .name = "move_pages", .parser = {NULL}},
    [__NR_utimensat] = {.slow = false, .name = "utimensat", .parser = {NULL}},
    [__NR_epoll_pwait] = {.slow = true, .name = "epoll_pwait", .parser = {parse_long_arg,
                          parse_integer_arg, parse_pointer_arg, parse_integer_arg,
                          parse_integer_arg, parse_pointer_arg, parse_pointer_arg}},
    [__NR_signalfd] = {.slow = false, .name = "signalfd", .parser = {NULL}},
    [__NR_timerfd_create] = {.slow = false, .name = "timerfd_create", .parser = {NULL}},
    [__NR_eventfd] = {.slow = false, .name = "eventfd", .parser = {parse_long_arg,
                      parse_integer_arg}},
    [__NR_fallocate] = {.slow = false, .name = "fallocate", .parser = {NULL}},
    [__NR_timerfd_settime] = {.slow = false, .name = "timerfd_settime", .parser = {NULL}},
    [__NR_timerfd_gettime] = {.slow = false, .name = "timerfd_gettime", .parser = {NULL}},
    [__NR_accept4] = {.slow = true, .name = "accept4", .parser = {parse_long_arg, parse_integer_arg,
                      parse_pointer_arg, parse_pointer_arg, parse_integer_arg}},
    [__NR_signalfd4] = {.slow = false, .name = "signalfd4", .parser = {NULL}},
    [__NR_eventfd2] = {.slow = false, .name = "eventfd2", .parser = {parse_long_arg,
                       parse_integer_arg, parse_integer_arg}},
    [__NR_epoll_create1] = {.slow = false, .name = "epoll_create1", .parser = {parse_long_arg,
                            parse_integer_arg}},
    [__NR_dup3] = {.slow = false, .name = "dup3", .parser = {parse_long_arg, parse_integer_arg,
                   parse_integer_arg, parse_integer_arg}},
    [__NR_pipe2] = {.slow = false, .name = "pipe2", .parser = {parse_long_arg, parse_pointer_arg,
                    parse_integer_arg}},
    [__NR_inotify_init1] = {.slow = false, .name = "inotify_init1", .parser = {NULL}},
    [__NR_preadv] = {.slow = false, .name = "preadv", .parser = {NULL}},
    [__NR_pwritev] = {.slow = false, .name = "pwritev", .parser = {NULL}},
    [__NR_rt_tgsigqueueinfo] = {.slow = false, .name = "rt_tgsigqueueinfo", .parser = {NULL}},
    [__NR_perf_event_open] = {.slow = false, .name = "perf_event_open", .parser = {NULL}},
    [__NR_recvmmsg] = {.slow = false, .name = "recvmmsg", .parser = {parse_long_arg,
                       parse_integer_arg, parse_pointer_arg, parse_integer_arg, parse_integer_arg,
                       parse_pointer_arg}},
    [__NR_prlimit64] = {.slow = false, .name = "prlimit64", .parser = {parse_long_arg,
                        parse_integer_arg, parse_integer_arg, parse_pointer_arg,
                        parse_pointer_arg}},
    [__NR_sendmmsg] = {.slow = false, .name = "sendmmsg", .parser = {parse_long_arg,
                       parse_integer_arg, parse_pointer_arg, parse_integer_arg, parse_integer_arg,
                       parse_pointer_arg}},
    [__NR_getcpu] = {.slow = false, .name = "getcpu", .parser = {parse_long_arg, parse_pointer_arg,
                     parse_pointer_arg, parse_pointer_arg}},
    [__NR_process_vm_readv] = {.slow = false, .name = "process_vm_readv", .parser = {NULL}},
    [__NR_process_vm_writev] = {.slow = false, .name = "process_vm_writev", .parser = {NULL}},
    [__NR_kcmp] = {.slow = false, .name = "kcmp", .parser = {NULL}},
    [__NR_finit_module] = {.slow = false, .name = "finit_module", .parser = {NULL}},
    [__NR_sched_setattr] = {.slow = false, .name = "sched_setattr", .parser = {NULL}},
    [__NR_sched_getattr] = {.slow = false, .name = "sched_getattr", .parser = {NULL}},
    [__NR_renameat2] = {.slow = false, .name = "renameat2", .parser = {NULL}},
    [__NR_seccomp] = {.slow = false, .name = "seccomp", .parser = {NULL}},
    [__NR_getrandom] = {.slow = false, .name = "getrandom", .parser = {parse_long_arg,
                        parse_pointer_arg, parse_pointer_arg, parse_getrandom_flags}},
    [__NR_memfd_create] = {.slow = false, .name = "memfd_create", .parser = {NULL}},
    [__NR_kexec_file_load] = {.slow = false, .name = "kexec_file_load", .parser = {NULL}},
    [__NR_bpf] = {.slow = false, .name = "bpf", .parser = {NULL}},
    [__NR_execveat] = {.slow = false, .name = "execveat", .parser = {NULL}},
    [__NR_userfaultfd] = {.slow = false, .name = "userfaultfd", .parser = {NULL}},
    [__NR_membarrier] = {.slow = false, .name = "membarrier", .parser = {NULL}},
    [__NR_mlock2] = {.slow = false, .name = "mlock2", .parser = {NULL}},
    [__NR_copy_file_range] = {.slow = false, .name = "copy_file_range", .parser = {NULL}},
    [__NR_preadv2] = {.slow = false, .name = "preadv2", .parser = {NULL}},
    [__NR_pwritev2] = {.slow = false, .name = "pwritev2", .parser = {NULL}},
    [__NR_pkey_mprotect] = {.slow = false, .name = "pkey_mprotect", .parser = {NULL}},
    [__NR_pkey_alloc] = {.slow = false, .name = "pkey_alloc", .parser = {NULL}},
    [__NR_pkey_free] = {.slow = false, .name = "pkey_free", .parser = {NULL}},
    [__NR_statx] = {.slow = false, .name = "statx", .parser = {NULL}},
    [__NR_io_pgetevents] = {.slow = false, .name = "io_pgetevents", .parser = {NULL}},
    [__NR_rseq] = {.slow = false, .name = "rseq", .parser = {NULL}},
    [__NR_pidfd_send_signal] = {.slow = false, .name = "pidfd_send_signal", .parser = {NULL}},
    [__NR_io_uring_setup] = {.slow = false, .name = "io_uring_setup", .parser = {NULL}},
    [__NR_io_uring_enter] = {.slow = false, .name = "io_uring_enter", .parser = {NULL}},
    [__NR_io_uring_register] = {.slow = false, .name = "io_uring_register", .parser = {NULL}},
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
        PRINTF("|0x%x", flags);
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

static void parse_string_arg(va_list* ap) {
    const char* arg = va_arg(*ap, const char*);
    if (!test_user_string(arg)) {
        PRINTF("\"%s\"", arg);
    } else {
        /* invalid memory region, print arg as ptr not string */
        PRINTF("(invalid-addr %p)", arg);
    }
}

static void parse_pointer_arg(va_list* ap) {
    PRINTF("%p", va_arg(*ap, void*));
}

static void parse_long_arg(va_list* ap) {
    long x = va_arg(*ap, long);
    if (x >= 0) {
        PRINTF("0x%lx", (unsigned long)x);
    } else {
        PRINTF("%ld", x);
    }
}

static void parse_integer_arg(va_list* ap) {
    int x = va_arg(*ap, int);
    PRINTF("%d", x);
}

static void parse_pointer_ret(va_list* ap) {
    void* ptr = va_arg(*ap, void*);
    if ((uintptr_t)ptr < (uintptr_t)-4095LL) {
        PRINTF("%p", ptr);
    } else {
        PRINTF("%ld", (intptr_t)ptr);
    }
}

static void print_syscall_name(const char* name, int sysno) {
    PUTS("shim_");
    if (name) {
        PRINTF("%s", name);
    } else {
        PRINTF("syscall%d", sysno);
    }
}

void debug_print_syscall_before(int sysno, ...) {
    if (g_log_level < PAL_LOG_DEBUG)
        return;

    struct parser_table* parser = &syscall_parser_table[sysno];

    if (!parser->slow)
        return;

    va_list ap;
    va_start(ap, sysno);

    PUTS("---- ");
    print_syscall_name(parser->name, sysno);
    PUTS("(");

    for (int i = 0; i < 6; i++) {
        if (parser->parser[i + 1]) {
            if (i)
                PUTS(", ");
            parser->parser[i + 1](&ap);
        } else {
            break;
        }
    }

    PUTS(") ...");
    /* Apparently `PUTS` does not flush buffer if it's ended with '\n'. */
    PUTCH('\n');
    va_end(ap);
}

void debug_print_syscall_after(int sysno, ...) {
    if (g_log_level < PAL_LOG_DEBUG)
        return;

    struct parser_table* parser = &syscall_parser_table[sysno];

    va_list ap;
    va_start(ap, sysno);

    /* Skip return value, as it's passed as first argument. */
    va_arg(ap, long);

    if (parser->slow) {
        PUTS("---- return from ");
        print_syscall_name(parser->name, sysno);
        PUTS("(...");
    } else {
        PUTS("---- ");
        print_syscall_name(parser->name, sysno);
        PUTS("(");

        for (int i = 0; i < 6; i++) {
            if (parser->parser[i + 1]) {
                if (i)
                    PUTS(", ");
                parser->parser[i + 1](&ap);
            } else {
                break;
            }
        }
    }

    va_end(ap);

    PUTS(")");
    if (parser->parser[0]) {
        PUTS(" = ");
        /* Return value is passed as the first argument, restart the list. */
        va_start(ap, sysno);
        parser->parser[0](&ap);
        va_end(ap);
    }
    PUTCH('\n');
}
