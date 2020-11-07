/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * Implementation of system calls "sigaction", "sigreturn", "sigprocmask", "kill", "tkill"
 * and "tgkill".
 */

#include <errno.h>
#include <stddef.h>  // FIXME(mkow): Without this we get:
                     //     asm/signal.h:126:2: error: unknown type name ‘size_t’
                     // It definitely shouldn't behave like this...
#include <limits.h>
#include <linux/signal.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_table.h"
#include "shim_thread.h"
#include "shim_utils.h"

int shim_do_sigaction(int signum, const struct __kernel_sigaction* act,
                      struct __kernel_sigaction* oldact, size_t sigsetsize) {
    /* SIGKILL and SIGSTOP cannot be caught or ignored */
    if (signum == SIGKILL || signum == SIGSTOP || signum <= 0 || signum > NUM_SIGS ||
            sigsetsize != sizeof(__sigset_t))
        return -EINVAL;

    if (act && test_user_memory((void*)act, sizeof(*act), false))
        return -EFAULT;

    if (oldact && test_user_memory(oldact, sizeof(*oldact), false))
        return -EFAULT;

    struct shim_thread* cur = get_cur_thread();

    lock(&cur->signal_handles->lock);

    struct __kernel_sigaction* sigaction = &cur->signal_handles->actions[signum - 1];

    if (oldact) {
        memcpy(oldact, sigaction, sizeof(*oldact));
    }

    if (act) {
        memcpy(sigaction, act, sizeof(*sigaction));
    }

    unlock(&cur->signal_handles->lock);
    return 0;
}

int shim_do_sigreturn(int __unused) {
    __UNUSED(__unused);
    /* do nothing */
    return 0;
}

int shim_do_sigprocmask(int how, const __sigset_t* set, __sigset_t* oldset) {
    __sigset_t* old;
    __sigset_t tmp;
    __sigset_t set_tmp;

    if (how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK)
        return -EINVAL;

    if (set && test_user_memory((void*)set, sizeof(*set), false))
        return -EFAULT;

    if (oldset && test_user_memory(oldset, sizeof(*oldset), false))
        return -EFAULT;

    struct shim_thread* cur = get_cur_thread();
    int err = 0;

    lock(&cur->lock);

    old = get_sig_mask(cur);
    if (oldset) {
        memcpy(&tmp, old, sizeof(__sigset_t));
        old = &tmp;
    }

    /* if set is NULL, then the signal mask is unchanged, but the current
       value of the signal mask is nevertheless returned in oldset */
    if (!set)
        goto out;

    memcpy(&set_tmp, old, sizeof(__sigset_t));

    switch (how) {
        case SIG_BLOCK:
            __sigorset(&set_tmp, &set_tmp, set);
            break;

        case SIG_UNBLOCK:
            __signotset(&set_tmp, &set_tmp, set);
            break;

        case SIG_SETMASK:
            memcpy(&set_tmp, set, sizeof(__sigset_t));
            break;
    }

    set_sig_mask(cur, &set_tmp);

out:
    unlock(&cur->lock);

    if (!err && oldset)
        memcpy(oldset, old, sizeof(__sigset_t));

    return err;
}

int shim_do_sigaltstack(const stack_t* ss, stack_t* oss) {
    if (ss && (ss->ss_flags & ~SS_DISABLE))
        return -EINVAL;

    struct shim_thread* cur = get_cur_thread();
    lock(&cur->lock);

    stack_t* cur_ss = &cur->signal_altstack;

    if (oss)
        *oss = *cur_ss;

    void* sp = (void*)shim_context_get_sp(&(shim_get_tcb()->context));
    /* check if thread is currently executing on an active altstack */
    if (!(cur_ss->ss_flags & SS_DISABLE) && sp && cur_ss->ss_sp <= sp &&
            sp < cur_ss->ss_sp + cur_ss->ss_size) {
        if (oss)
            oss->ss_flags |= SS_ONSTACK;
        if (ss) {
            unlock(&cur->lock);
            return -EPERM;
        }
    }

    if (ss) {
        if (ss->ss_flags & SS_DISABLE) {
            memset(cur_ss, 0, sizeof(*cur_ss));
            cur_ss->ss_flags = SS_DISABLE;
        } else {
            if (ss->ss_size < MINSIGSTKSZ) {
                unlock(&cur->lock);
                return -ENOMEM;
            }

            *cur_ss = *ss;
        }
    }

    unlock(&cur->lock);
    return 0;
}

int shim_do_sigsuspend(const __sigset_t* mask) {
    if (!mask || test_user_memory((void*)mask, sizeof(*mask), false))
        return -EFAULT;

    __sigset_t old;
    struct shim_thread* cur = get_cur_thread();

    __atomic_store_n(&cur->signal_handled, SIGNAL_NOT_HANDLED, __ATOMIC_RELEASE);

    lock(&cur->lock);
    memcpy(&old, get_sig_mask(cur), sizeof(old));

    set_sig_mask(cur, mask);
    unlock(&cur->lock);

    /* We might have unblocked some pending signals. */
    handle_signals();

    thread_setwait(NULL, NULL);

    if (__atomic_load_n(&cur->signal_handled, __ATOMIC_ACQUIRE) != SIGNAL_NOT_HANDLED) {
        goto out;
    }

    thread_sleep(NO_TIMEOUT);

out:
    lock(&cur->lock);
    set_sig_mask(cur, &old);
    unlock(&cur->lock);
    return -EINTR;
}

int shim_do_sigpending(__sigset_t* set, size_t sigsetsize) {
    if (sigsetsize != sizeof(*set))
        return -EINVAL;

    if (!set || test_user_memory(set, sigsetsize, false))
        return -EFAULT;

    struct shim_thread* cur = get_cur_thread();

    get_pending_signals(cur, set);

    return 0;
}

struct signal_thread_arg {
    int sig;
    bool current_should_handle;
};

static int _wakeup_one_thread(struct shim_thread* thread, void* _arg) {
    struct signal_thread_arg* arg = (struct signal_thread_arg*)_arg;
    int ret = 0;

    lock(&thread->lock);

    if (!__sigismember(&thread->signal_mask, arg->sig)) {
        if (thread == get_cur_thread()) {
            arg->current_should_handle = true;
        } else {
            thread_wakeup(thread);
            DkThreadResume(thread->pal_handle);
        }
        ret = 1;
    }

    unlock(&thread->lock);
    return ret;
}

int kill_current_proc(siginfo_t* info) {
    if (!info->si_signo) {
        return 0;
    }

    int ret = append_signal(NULL, info);
    if (ret < 0) {
        return ret;
    }

    struct signal_thread_arg arg = {
        .sig = info->si_signo,
        .current_should_handle = false,
    };

    ret = walk_thread_list(_wakeup_one_thread, &arg, /*one_shot=*/true);
    /* Ignore `-ESRCH` as this just means that currently no thread is able to handle the signal. */
    if (ret < 0 && ret != -ESRCH) {
        return ret;
    }

    if (arg.current_should_handle) {
        assert(ret == 0);
        /* We've delivered the signal to the current thread, now need to handle it. */
        handle_signals();
    }

    return 0;
}

int do_kill_proc(IDTYPE sender, IDTYPE tgid, int sig, bool use_ipc) {
    if (g_process.pid != tgid) {
        if (use_ipc) {
            return ipc_pid_kill_send(sender, tgid, KILL_PROCESS, sig);
        }
        return -ESRCH;
    }

    siginfo_t info = {
        .si_signo = sig,
        .si_pid   = sender,
        .si_code  = SI_USER
    };
    return kill_current_proc(&info);
}

int do_kill_pgroup(IDTYPE sender, IDTYPE pgid, int sig, bool use_ipc) {
    int ret = -ESRCH;
    IDTYPE current_pgid = __atomic_load_n(&g_process.pgid, __ATOMIC_ACQUIRE);
    if (!pgid) {
        pgid = current_pgid;
    }

    if (use_ipc) {
        ret = ipc_pid_kill_send(sender, pgid, KILL_PGROUP, sig);
        if (ret < 0 && ret != -ESRCH) {
            return ret;
        }
    }

    if (current_pgid != pgid) {
        /* `ret` might have been set if IPC message was sent. */
        return ret;
    }

    siginfo_t info = {
        .si_signo = sig,
        .si_pid   = sender,
        .si_code  = SI_USER
    };
    return kill_current_proc(&info);
}

int shim_do_kill(pid_t pid, int sig) {
    if (sig < 0 || sig > NUM_SIGS) {
        return -EINVAL;
    }

    if (pid == INT_MIN) {
        /* We should not negate INT_MIN. */
        return -ESRCH;
    }

    if (pid > 0) {
        /* If `pid` is positive, then signal is sent to the process with that pid. */
        return do_kill_proc(g_process.pid, pid, sig, /*use_ipc=*/true);
    } else if (pid == -1) {
        /* If `pid` equals -1, then signal is sent to every process for which the calling process
         * has permission to send, which means all processes in Graphene. NOTE: On Linux, kill(-1)
         * does not signal the calling process. */
        return ipc_pid_kill_send(g_process.pid, /*target=*/0, KILL_ALL, sig);
    } else if (pid == 0) {
        /* If `pid` equals 0, then signal is sent to every process in the process group of
         * the calling process. */
        return do_kill_pgroup(g_process.pid, 0, sig, /*use_ipc=*/true);
    } else { // pid < -1
        /* If `pid` is less than -1, then signal is sent to every process in the process group
         * `-pid`. */
        return do_kill_pgroup(g_process.pid, -pid, sig, /*use_ipc=*/true);
    }
}

int do_kill_thread(IDTYPE sender, IDTYPE tgid, IDTYPE tid, int sig, bool use_ipc) {
    if (sig < 0 || sig > NUM_SIGS)
        return -EINVAL;

    if (!tgid || g_process.pid == tgid) {
        struct shim_thread* thread = lookup_thread(tid);
        if (!thread) {
            goto maybe_try_ipc;
        }

        if (!sig) {
            put_thread(thread);
            return 0;
        }

        siginfo_t info = {
            .si_signo = sig,
            .si_pid   = sender,
            .si_code  = SI_TKILL,
        };
        if (thread == get_cur_thread()) {
            deliver_signal(&info, NULL);
        } else {
            int ret = append_signal(thread, &info);
            if (ret < 0) {
                put_thread(thread);
                return ret;
            }
            thread_wakeup(thread);
            DkThreadResume(thread->pal_handle);
        }

        put_thread(thread);
        return 0;
    }

maybe_try_ipc:
    if (g_process.pid != tgid) {
        if (use_ipc) {
            return ipc_pid_kill_send(sender, tid, KILL_THREAD, sig);
        }
    }

    return -ESRCH;
}

int shim_do_tkill(pid_t tid, int sig) {
    if (tid <= 0)
        return -EINVAL;

    return do_kill_thread(g_process.pid, 0, tid, sig, /*use_ipc=*/true);
}

int shim_do_tgkill(pid_t tgid, pid_t tid, int sig) {
    if (tgid <= 0 || tid <= 0)
        return -EINVAL;

    return do_kill_thread(g_process.pid, tgid, tid, sig, /*use_ipc=*/true);
}

void fill_siginfo_code_and_status(siginfo_t* info, int signal, int exit_code) {
    if (signal == 0) {
        info->si_code = CLD_EXITED;
        info->si_status = exit_code;
    } else if (signal & __WCOREDUMP_BIT) {
        info->si_code = CLD_DUMPED;
        info->si_status = signal & ~__WCOREDUMP_BIT;
    } else {
        info->si_code = CLD_KILLED;
        info->si_status = signal;
    }
}
