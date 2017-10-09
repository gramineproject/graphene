/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

typedef __builtin_va_list __gnuc_va_list;

#include "pal_linux_defs.h"
#include "bpf-helper.h"
#include "internal.h"
#include "graphene-ipc.h"
#include "graphene-rm.h"
#include "graphene-sandbox.h"

#include <linux/types.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/prctl.h>
#include <sys/socket.h>
#include <asm/fcntl.h>
#include <asm/mman.h>
#include <asm/ioctls.h>

#ifndef PR_SET_NO_NEW_PRIVS
# define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef SYS_SECCOMP
# define SYS_SECCOMP 1
#endif

#define SYSCALL_FILTERS                                  \
    LOAD_SYSCALL_NR,                                     \
                                                         \
    SYSCALL(__NR_fstat,         ALLOW),                  \
    SYSCALL(__NR_accept4,       ALLOW),                  \
    SYSCALL(__NR_clone,         JUMP(&labels, clone)),   \
    SYSCALL(__NR_close,         ALLOW),                  \
    SYSCALL(__NR_dup2,          ALLOW),                  \
    SYSCALL(__NR_exit,          ALLOW),                  \
    SYSCALL(__NR_exit_group,    ALLOW),                  \
    SYSCALL(__NR_fchmod,        ALLOW),                  \
    SYSCALL(__NR_fcntl,         JUMP(&labels, fcntl)),   \
    SYSCALL(__NR_fsync,         ALLOW),                  \
    SYSCALL(__NR_ftruncate,     ALLOW),                  \
    SYSCALL(__NR_futex,         ALLOW),                  \
    SYSCALL(__NR_getdents64,    ALLOW),                  \
    SYSCALL(__NR_getsockname,   ALLOW),                  \
    SYSCALL(__NR_getsockopt,    ALLOW),                  \
    SYSCALL(__NR_ioctl,         JUMP(&labels, ioctl)),   \
    SYSCALL(__NR_listen,        ALLOW),                  \
    SYSCALL(__NR_lseek,         ALLOW),                  \
    SYSCALL(__NR_mkdir,         ALLOW),                  \
    SYSCALL(__NR_mmap,          ALLOW),                  \
    SYSCALL(__NR_mprotect,      ALLOW),                  \
    SYSCALL(__NR_munmap,        ALLOW),                  \
    SYSCALL(__NR_nanosleep,     ALLOW),                  \
    SYSCALL(__NR_pipe2,         ALLOW),                  \
    SYSCALL(__NR_ppoll,         ALLOW),                  \
    SYSCALL(__NR_read,          ALLOW),                  \
    SYSCALL(__NR_readlink,      ALLOW),                  \
    SYSCALL(__NR_recvmsg,       ALLOW),                  \
    SYSCALL(__NR_rename,        ALLOW),                  \
    SYSCALL(__NR_rmdir,         ALLOW),                  \
    SYSCALL(__NR_sched_yield,   ALLOW),                  \
    SYSCALL(__NR_sendmsg,       ALLOW),                  \
    SYSCALL(__NR_setsockopt,    ALLOW),                  \
    SYSCALL(__NR_shutdown,      ALLOW),                  \
    SYSCALL(__NR_socket,        JUMP(&labels, socket)),  \
    SYSCALL(__NR_socketpair,    JUMP(&labels, socket)),  \
    SYSCALL(__NR_tgkill,        ALLOW),                  \
    SYSCALL(__NR_unlink,        ALLOW),                  \
    SYSCALL(__NR_wait4,         ALLOW),                  \
    SYSCALL(__NR_write,         ALLOW),                  \
                                                         \
    SYSCALL_ARCH_FILTERS

#ifdef __x86_64__
# define SYSCALL_ARCH_FILTERS                            \
    SYSCALL(__NR_arch_prctl,        ALLOW),              \
    SYSCALL(__NR_rt_sigaction,      ALLOW),              \
    SYSCALL(__NR_rt_sigprocmask,    ALLOW),              \
    SYSCALL(__NR_rt_sigreturn,      ALLOW),
#else
# error "Unsupported architecture"
#endif

#define SYSCALL_UNSAFE_FILTERS                           \
    SYSCALL(__NR_open,          ALLOW),                  \
    SYSCALL(__NR_stat,          ALLOW),                  \
    SYSCALL(__NR_bind,          ALLOW),                  \
    SYSCALL(__NR_connect,       ALLOW),                  \
    SYSCALL(__NR_execve,        ALLOW),

#ifndef SIGCHLD
# define SIGCHLD 17
#endif

#define CLONE_ALLOWED_FLAGS                              \
    (CLONE_FILES|CLONE_FS|CLONE_IO|CLONE_THREAD|         \
     CLONE_SIGHAND|CLONE_PTRACE|CLONE_SYSVSEM|CLONE_VM|  \
     CLONE_VFORK|CLONE_PARENT_SETTID|SIGCHLD)

#define SYSCALL_ACTIONS                                  \
    TRAP,                                                \
                                                         \
    LABEL(&labels, ioctl),                               \
    ARG(1),                                              \
    JEQ(GRM_SYS_OPEN,   ALLOW),                          \
    JEQ(GRM_SYS_STAT,   ALLOW),                          \
    JEQ(GRM_SYS_BIND,   ALLOW),                          \
    JEQ(GRM_SYS_CONNECT,ALLOW),                          \
    JEQ(GRM_SYS_EXECVE, ALLOW),                          \
    JEQ(FIONREAD,       ALLOW),                          \
    JEQ(GIPC_CREATE,    ALLOW),                          \
    JEQ(GIPC_JOIN,      ALLOW),                          \
    JEQ(GIPC_RECV,      ALLOW),                          \
    JEQ(GIPC_SEND,      ALLOW),                          \
    JEQ(GRM_SET_SANDBOX,ALLOW),                          \
    TRAP,                                                \
                                                         \
    LABEL(&labels, fcntl),                               \
    ARG(1),                                              \
    JEQ(F_SETFD,   ALLOW),                               \
    JEQ(F_SETFL,   ALLOW),                               \
    TRAP,                                                \
                                                         \
    LABEL(&labels, clone),                               \
    ARG_FLAG(0, CLONE_ALLOWED_FLAGS),                    \
    JEQ(0, ALLOW),                                       \
    TRAP,                                                \
                                                         \
    LABEL(&labels, socket),                              \
    ARG(0),                                              \
    JEQ(AF_UNIX,    ALLOW),                              \
    JEQ(AF_INET,    ALLOW),                              \
    JEQ(AF_INET6,   ALLOW),                              \
    TRAP,


/* VERY IMPORTANT: This is the filter that gets applied to the startup code
 * before applying the real filter in the function install_syscall_filter. If
 * you face any issues, you may have to enable certain syscalls here to
 * successfully make changes to startup code. Also, all the syscalls allowed
 * in install_syscall_filter must be allowed in install_initial_syscall_filter
 * as well.
 */

int install_initial_syscall_filter (int has_reference_monitor)
{
    int err = 0;
    struct bpf_labels labels = { .count = 0 };

    struct sock_filter filter[] = {
        SYSCALL_FILTERS

#if USE_CLOCK_GETTIME == 1
        SYSCALL(__NR_clock_gettime, ALLOW),
#else
        SYSCALL(__NR_gettimeofday,  ALLOW),
#endif
        SYSCALL(__NR_prctl,     JUMP(&labels, prctl)),

        SYSCALL_ACTIONS
        LABEL(&labels, prctl),
        ARG(0),
        JEQ(PR_SET_SECCOMP,     ALLOW),
        TRAP,
    };

    struct sock_filter filter_unsafe[] = {
        SYSCALL_FILTERS
        SYSCALL_UNSAFE_FILTERS

#if USE_CLOCK_GETTIME == 1
        SYSCALL(__NR_clock_gettime, ALLOW),
#else
        SYSCALL(__NR_gettimeofday,  ALLOW),
#endif
        SYSCALL(__NR_prctl,     JUMP(&labels, prctl)),

        SYSCALL_ACTIONS
        LABEL(&labels, prctl),
        ARG(0),
        JEQ(PR_SET_SECCOMP,     ALLOW),
        TRAP,
    };

    struct sock_fprog prog = {
        .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (!has_reference_monitor) {
        prog.len = (unsigned short)
            (sizeof(filter_unsafe) / sizeof(filter_unsafe[0]));
        prog.filter = filter_unsafe;
    }

    bpf_resolve_jumps(&labels, prog.filter, prog.len);

    char buffer[2] = "\0\0";
    char proc_jit_enable[] = "/proc/sys/net/core/bpf_jit_enable";

    int fd = sys_open(proc_jit_enable, O_RDONLY, 0);
    if (!IS_ERR(fd)) {
        err = INLINE_SYSCALL(read, 3, fd, &buffer, 2);
        if (IS_ERR(err) || buffer[0] == '0')
            printf("Set \"%s\" to 1 for better performance.\n",
                   proc_jit_enable);
        INLINE_SYSCALL(close, 1, fd);
    }

    err = INLINE_SYSCALL(prctl, 5, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (IS_ERR(err))
        goto failed;

    err = INLINE_SYSCALL(prctl, 3, PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
                         &prog);
    if (IS_ERR(err))
        goto failed;

    return 0;

failed:
    return -ERRNO(err);
}

int install_syscall_filter (void * pal_code_start, void * pal_code_end)
{
    int err = 0;
    struct bpf_labels labels = { .count = 0 };

    struct sock_filter filter[] = {
        LOAD_SYSCALL_NR,
        SYSCALL(__NR_prctl,     TRAP),

        IP,
        JLT((uint64_t) TEXT_START,         TRAP),
        JLT((uint64_t) TEXT_END,           ALLOW),
        JLT((uint64_t) pal_code_start,     TRAP),
        JGT((uint64_t) pal_code_end,       TRAP),

        ALLOW,
    };

    struct sock_fprog prog = {
        .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    bpf_resolve_jumps(&labels, filter, prog.len);

    err = INLINE_SYSCALL(prctl, 3, PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
                         &prog);

    if (IS_ERR(err))
        goto failed;

    return 0;

failed:
    return -ERRNO(err);
}
