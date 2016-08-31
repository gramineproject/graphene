/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

typedef __builtin_va_list __gnuc_va_list;

#include "pal_linux_defs.h"
#include "bpf-helper.h"
#include "internal.h"
#include "graphene-ipc.h"
#include "graphene.h"

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
    SYSCALL(__NR_open,          ALLOW),                  \
    SYSCALL(__NR_fstat,         ALLOW),                  \
    SYSCALL(__NR_accept4,       ALLOW),                  \
    SYSCALL(__NR_bind,          ALLOW),                  \
    SYSCALL(__NR_clone,         ALLOW),                  \
    SYSCALL(__NR_close,         ALLOW),                  \
    SYSCALL(__NR_dup2,          ALLOW),                  \
    SYSCALL(__NR_connect,       ALLOW),                  \
    SYSCALL(__NR_execve,        ALLOW),                  \
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
    SYSCALL(__NR_mmap,          JUMP(&labels, mmap)),    \
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
    SYSCALL(__NR_socket,        ALLOW),                  \
    SYSCALL(__NR_socketpair,    ALLOW),                  \
    SYSCALL(__NR_stat,          ALLOW),                  \
    SYSCALL(__NR_tgkill,        ALLOW),                  \
    SYSCALL(__NR_unlink,        ALLOW),                  \
    SYSCALL(__NR_vfork,         ALLOW),                  \
    SYSCALL(__NR_wait4,         ALLOW),                  \
    SYSCALL(__NR_write,         ALLOW),                  \
                                                         \
    SYSCALL_ARCH_FILTERS

#ifdef __x86_64__
# define SYSCALL_ARCH_FILTERS                            \
    SYSCALL(__NR_arch_prctl,        ALLOW),              \
    SYSCALL(__NR_rt_sigaction,      ALLOW),              \
    SYSCALL(__NR_rt_sigprocmask,    ALLOW),              \
    SYSCALL(__NR_rt_sigreturn,      ALLOW)
#else
# error "Unsupported architecture"
#endif

#ifndef SIGCHLD
# define SIGCHLD 17
#endif

#define SYSCALL_ACTIONS                                  \
    DENY,                                                \
                                                         \
    LABEL(&labels, ioctl),                               \
    ARG(1),                                              \
    JEQ(FIONREAD,       ALLOW),                          \
    JEQ(GIPC_CREATE,    ALLOW),                          \
    JEQ(GIPC_JOIN,      ALLOW),                          \
    JEQ(GIPC_RECV,      ALLOW),                          \
    JEQ(GIPC_SEND,      ALLOW),                          \
    JEQ(GRAPHENE_SET_TASK,  ALLOW),                      \
    DENY,                                                \
                                                         \
    LABEL(&labels, fcntl),                               \
    ARG(1),                                              \
    JEQ(F_SETFD,   ALLOW),                               \
    JEQ(F_SETFL,   ALLOW),                               \
    DENY,                                                \
                                                         \
    LABEL(&labels, mmap),                                \
    ARG_FLAG(3, MAP_HUGETLB),                            \
    JEQ(0, ALLOW),                                       \
    DENY,                                                \
                                                         \
    LABEL(&labels, clone),                               \
    ARG_FLAG(2, (CLONE_IO|CLONE_VM|CLONE_VFORK)),        \
    JEQ(0, ALLOW),                                       \
    JEQ(SIGCHLD, ALLOW),                                 \
    DENY,                                                \
                                                         \
    LABEL(&labels, socket),                              \
    ARG(0),                                              \
    JEQ(AF_UNIX,    ALLOW),                              \
    JEQ(AF_INET,    ALLOW),                              \
    JEQ(AF_INET6,   ALLOW),                              \
    DENY


/* VERY IMPORTANT: This is the filter that gets applied to the startup code
 * before applying the real filter in the function install_syscall_filter. If
 * you face any issues, you may have to enable certain syscalls here to
 * successfully make changes to startup code. Also, all the syscalls allowed
 * in install_syscall_filter must be allowed in install_initial_syscall_filter
 * as well.
 */

int install_initial_syscall_filter (void)
{
    int err = 0;
    struct bpf_labels labels = { .count = 0 };

    struct sock_filter filter[] = {
        SYSCALL_FILTERS,

#if USE_CLOCK_GETTIME == 1
        SYSCALL(__NR_clock_gettime, ALLOW),
#else
        SYSCALL(__NR_gettimeofday,  ALLOW),
#endif
        SYSCALL(__NR_prctl,     JUMP(&labels, prctl)),

        SYSCALL_ACTIONS,

        LABEL(&labels, prctl),
        ARG(0),
        JEQ(PR_SET_SECCOMP,     ALLOW),
        DENY,
    };

    struct sock_fprog prog = {
        .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    bpf_resolve_jumps(&labels, filter, prog.len);

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

int install_syscall_filter (void * code_start, void * code_end)
{
    int err = 0;
    struct bpf_labels labels = { .count = 0 };

    printf("set up filter in %p-%p\n", code_start, code_end);

    struct sock_filter filter[] = {
        IP,
        JLT((unsigned long) code_start, DENY),
        JGT((unsigned long) code_end,   DENY),

        SYSCALL(__NR_prctl,     DENY),
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
