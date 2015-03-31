/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

typedef __builtin_va_list __gnuc_va_list;

#include <linux/types.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/prctl.h>
#include <asm/fcntl.h>
#include <asm/ioctls.h>

#include <sys/socket.h>
#include <sys/mman.h>

#include "bpf-helper.h"
#include "utils.h"
#include "graphene-ipc.h"
#include "graphene.h"

#ifndef PR_SET_NO_NEW_PRIVS
# define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef SYS_SECCOMP
# define SYS_SECCOMP 1
#endif

#define SYSCALL_FILTERS                                         \
    LOAD_SYSCALL_NR,                                            \
                                                                \
    SYSCALL(__NR_gettimeofday,  action_allow),                  \
    SYSCALL(__NR_open,          action_trace),                  \
    SYSCALL(__NR_fstat,         action_allow),                  \
    SYSCALL(__NR_accept4,       action_allow),                  \
    SYSCALL(__NR_bind,          action_trace),                  \
    SYSCALL(__NR_clone,         action_allow),                  \
    SYSCALL(__NR_close,         action_allow),                  \
    SYSCALL(__NR_dup2,          action_allow),                  \
    SYSCALL(__NR_connect,       action_trace),                  \
    SYSCALL(__NR_execve,        action_trace),                  \
    SYSCALL(__NR_exit,          action_allow),                  \
    SYSCALL(__NR_exit_group,    action_allow),                  \
    SYSCALL(__NR_fchmod,        action_trace),                  \
    SYSCALL(__NR_fcntl,         JUMP(&labels, fcntl)),          \
    SYSCALL(__NR_fsync,         action_allow),                  \
    SYSCALL(__NR_ftruncate,     action_allow),                  \
    SYSCALL(__NR_futex,         action_allow),                  \
    SYSCALL(__NR_getdents64,    action_allow),                  \
    SYSCALL(__NR_getsockname,   action_allow),                  \
    SYSCALL(__NR_getsockopt,    action_allow),                  \
    SYSCALL(__NR_getpid,        action_allow),                  \
    SYSCALL(__NR_ioctl,         JUMP(&labels, ioctl)),          \
    SYSCALL(__NR_kill,          action_trace),                  \
    SYSCALL(__NR_listen,        action_allow),                  \
    SYSCALL(__NR_lseek,         action_allow),                  \
    SYSCALL(__NR_mkdir,         action_trace),                  \
    SYSCALL(__NR_mmap,          JUMP(&labels, mmap)),           \
    SYSCALL(__NR_mprotect,      action_allow),                  \
    SYSCALL(__NR_munmap,        action_allow),                  \
    SYSCALL(__NR_nanosleep,     action_allow),                  \
    SYSCALL(__NR_pipe2,         action_allow),                  \
    SYSCALL(__NR_ppoll,         action_allow),                  \
    SYSCALL(__NR_read,          action_allow),                  \
    SYSCALL(__NR_readlink,      action_allow),                  \
    SYSCALL(__NR_recvmsg,       action_allow),                  \
    SYSCALL(__NR_rename,        action_trace),                  \
    SYSCALL(__NR_rmdir,         action_trace),                  \
    SYSCALL(__NR_sched_yield,   action_allow),                  \
    SYSCALL(__NR_sendmsg,       action_allow),                  \
    SYSCALL(__NR_setsockopt,    action_allow),                  \
    SYSCALL(__NR_shutdown,      action_allow),                  \
    SYSCALL(__NR_socket,        action_allow),                  \
    SYSCALL(__NR_socketpair,    action_allow),                  \
    SYSCALL(__NR_stat,          action_trace),                  \
    SYSCALL(__NR_tgkill,        action_trace),                  \
    SYSCALL(__NR_unlink,        action_trace),                  \
    SYSCALL(__NR_vfork,         action_allow),                  \
    SYSCALL(__NR_wait4,         action_allow),                  \
    SYSCALL(__NR_write,         action_allow),                  \
                                                                \
    SYSCALL_ARCH_FILTERS

#ifdef __x86_64__
# define SYSCALL_ARCH_FILTERS                                   \
    SYSCALL(__NR_arch_prctl,        action_allow),              \
    SYSCALL(__NR_rt_sigaction,      action_allow),              \
    SYSCALL(__NR_rt_sigprocmask,    action_allow),              \
    SYSCALL(__NR_rt_sigreturn,      action_allow)
#endif

#define SYSCALL_ACTIONS                                         \
    DENY,                                                       \
                                                                \
    LABEL(&labels, ioctl),                                      \
    ARG(1),                                                     \
    JEQ(FIONREAD,       action_allow),                          \
    JEQ(GIPC_CREATE,    action_allow),                          \
    JEQ(GIPC_JOIN,      action_allow),                          \
    JEQ(GIPC_RECV,      action_allow),                          \
    JEQ(GIPC_SEND,      action_allow),                          \
    JEQ(GRAPHENE_SET_TASK,  action_allow),                      \
    DENY,                                                       \
                                                                \
    LABEL(&labels, fcntl),                                      \
    ARG(1),                                                     \
    JEQ(F_SETFD,   action_allow),                               \
    JEQ(F_SETFL,   action_allow),                               \
    DENY,                                                       \
                                                                \
    LABEL(&labels, mmap),                                       \
    ARG_FLAG(3, MAP_HUGETLB),                                   \
    JEQ(0, action_allow),                                       \
    DENY,                                                       \
                                                                \
    LABEL(&labels, clone),                                      \
    ARG_FLAG(2, CLONE_IO),                                      \
    JEQ(0, action_allow),                                       \
    DENY,                                                       \
                                                                \
    LABEL(&labels, socket),                                     \
    ARG(0),                                                     \
    JEQ(AF_UNIX,    action_allow),                              \
    JEQ(AF_INET,    action_allow),                              \
    JEQ(AF_INET6,   action_allow),                              \
    DENY


/* VERY IMPORTANT: This is the filter that gets applied to the startup code
 * before applying the real filter in the function install_syscall_filter. If
 * you face any issues, you may have to enable certain syscalls here to
 * successfully make changes to startup code. Also, all the syscalls allowed
 * in install_syscall_filter must be allowed in install_initial_syscall_filter
 * as well.
 */

int install_initial_syscall_filter ()
{
    int err = 0;
    struct bpf_labels labels = { .count = 0 };

#define action_allow    ALLOW
#define action_trace    ALLOW

    struct sock_filter filter[] = {
        SYSCALL_FILTERS,

        SYSCALL(__NR_fork,      ALLOW),
        SYSCALL(__NR_prctl,     JUMP(&labels, prctl)),
        SYSCALL(__NR_chmod,     ALLOW),

        SYSCALL_ACTIONS,

        LABEL(&labels, prctl),
        ARG(0),
        JEQ(PR_SET_SECCOMP,     ALLOW),
        DENY,
    };

#undef action_allow
#undef action_trace

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

int install_syscall_filter (const char * lib_name, unsigned long lib_start,
                            unsigned long lib_end, int trace)
{
    int err = 0;
    struct bpf_labels labels = { .count = 0 };

#define action_allow    ALLOW // JUMP(&labels, allow)
#define action_trace    ALLOW // JUMP(&labels, likely_trace)

    struct sock_filter filter[] = {
        IP,
        JLT((unsigned long) lib_start, DENY),
        JGT((unsigned long) lib_end, DENY),

        SYSCALL(__NR_fork,      DENY),
        SYSCALL(__NR_prctl,     DENY),
        SYSCALL(__NR_chmod,     DENY),
        ALLOW,
    };

#undef action_allow
#undef action_trace

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
