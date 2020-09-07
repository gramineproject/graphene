/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * shim_sigaction.c
 *
 * Implementation of system call "sigaction", "sigreturn", "sigprocmask",
 * "kill", "tkill" and "tgkill".
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

    __atomic_store_n(&cur->signal_handled, false, __ATOMIC_RELEASE);

    lock(&cur->lock);
    memcpy(&old, get_sig_mask(cur), sizeof(old));

    set_sig_mask(cur, mask);
    unlock(&cur->lock);

    /* We might have unblocked some pending signals. */
    handle_signals();

    thread_setwait(NULL, NULL);

    if (__atomic_load_n(&cur->signal_handled, __ATOMIC_ACQUIRE)) {
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

enum signal_thread_arg_type {
    TGID = 1,
    PGID,
};

struct signal_thread_arg {
    int sig;
    IDTYPE sender;
    IDTYPE cmp_val;
    enum signal_thread_arg_type cmp_type;
    bool sent;
};

static int _signal_one_thread(struct shim_thread* thread, void* _arg) {
    struct signal_thread_arg* arg = (struct signal_thread_arg*)_arg;
    int ret = 0;

    lock(&thread->lock);

    if (!thread->in_vm || !thread->is_alive) {
        goto out;
    }

    switch (arg->cmp_type) {
        case TGID:
            if (thread->tgid != arg->cmp_val) {
                goto out;
            }
            break;
        case PGID:
            if (thread->pgid != arg->cmp_val) {
                goto out;
            }
            break;
        default:
            debug("Invalid signal_thread_arg_type: %d\n", arg->cmp_type);
            BUG();
    }

    if (!arg->sig) {
        /* special case of sig == 0: don't really send signal but simply report success */
        arg->sent = true;
        ret = 1;
        goto out;
    }

    /* Appending the signal to the whole process. */
    if (!arg->sent) {
        siginfo_t info = {
            .si_signo = arg->sig,
            .si_pid   = arg->sender,
        };
        ret = append_signal(NULL, &info);
        if (ret < 0) {
            goto out;
        }
        arg->sent = true;
    }
    if (arg->sent && !__sigismember(&thread->signal_mask, arg->sig)) {
        if (thread == get_cur_thread()) {
            /* We are ending this walk anyway, lets reuse sent field to mark that current thread
             * needs to handle a signal. */
            arg->sent = false;
        } else {
            thread_wakeup(thread);
            DkThreadResume(thread->pal_handle);
        }
        ret = 1;
    }

out:
    unlock(&thread->lock);
    return ret;
}

int do_kill_proc(IDTYPE sender, IDTYPE tgid, int sig, bool use_ipc) {
    /* This might be called by an internal thread (like IPC), so we cannot inspect `cur_thread` ids
     * to check whether `sig` is targetted at it, but need to do a full search. */
    struct signal_thread_arg arg = {
        .sig      = sig,
        .sender   = sender,
        .cmp_val  = tgid,
        .cmp_type = TGID,
        .sent     = false,
    };
    int ret = walk_thread_list(_signal_one_thread, &arg, /*one_shot=*/true);
    if (ret < 0 && ret != -ESRCH) {
        return ret;
    }

    if (ret == 0) {
        if (!arg.sent) {
            /* We delivered the signal to self, now need to handle it. */
            handle_signals();
        }
        return 0;
    }

    assert(ret == -ESRCH);

    if (arg.sent) {
        /* We've sent the signal successfully, but all threads have it blocked for now. */
        return 0;
    }

    if (use_ipc) {
        return ipc_pid_kill_send(sender, tgid, KILL_PROCESS, sig);
    }

    return -ESRCH;
}

int do_kill_pgroup(IDTYPE sender, IDTYPE pgid, int sig, bool use_ipc) {
    struct shim_thread* cur = get_cur_thread();
    int ret = 0;

    if (!pgid) {
        pgid = cur->pgid;
    }

    if (use_ipc) {
        ret = ipc_pid_kill_send(sender, pgid, KILL_PGROUP, sig);
        if (ret < 0 && ret != -ESRCH) {
            return ret;
        }
    }

    /* This might be called by an internal thread (like IPC), so we cannot inspect `cur_thread` ids
     * to check whether `sig` is targetted at it, but need to do a full search. */
    struct signal_thread_arg arg = {
        .sig      = sig,
        .sender   = sender,
        .cmp_val  = pgid,
        .cmp_type = PGID,
        .sent     = false,
    };
    ret = walk_thread_list(_signal_one_thread, &arg, /*one_shot=*/true);

    if (ret == 0 && !arg.sent) {
        /* We delivered the signal to self, now need to handle it. */
        handle_signals();
    }

    if (ret == -ESRCH && arg.sent) {
        /* We've sent the signal successfully, but all threads have it blocked for now. */
        ret = 0;
    }

    return ret;
}

int shim_do_kill(pid_t pid, int sig) {
    if (sig < 0 || sig > NUM_SIGS) {
        return -EINVAL;
    }

    if (pid == INT_MIN) {
        /* We should not negate INT_MIN. */
        return -ESRCH;
    }

    struct shim_thread* cur = get_cur_thread();

    if (pid > 0) {
        /* If `pid` is positive, then signal is sent to the process with that pid. */
        return do_kill_proc(cur->tid, pid, sig, /*use_ipc=*/true);
    } else if (pid == -1) {
        /* If `pid` equals -1, then signal is sent to every process for which the calling process
         * has permission to send, which means all processes in Graphene. NOTE: On Linux, kill(-1)
         * does not signal the calling process. */
        ipc_pid_kill_send(cur->tid, /*target=*/0, KILL_ALL, sig);
        return do_kill_proc(cur->tid, cur->tgid, sig, /*use_ipc=*/false);
    } else if (pid == 0) {
        /* If `pid` equals 0, then signal is sent to every process in the process group of
         * the calling process. */
        return do_kill_pgroup(cur->tid, 0, sig, /*use_ipc=*/true);
    } else { // pid < -1
        /* If `pid` is less than -1, then signal is sent to every process in the process group
         * `-pid`. */
        return do_kill_pgroup(cur->tid, -pid, sig, /*use_ipc=*/true);
    }
}

int do_kill_thread(IDTYPE sender, IDTYPE tgid, IDTYPE tid, int sig, bool use_ipc) {
    if (sig < 0 || sig > NUM_SIGS)
        return -EINVAL;

    struct shim_thread* thread = lookup_thread(tid);
    int ret = -ESRCH;

    if (thread) {
        lock(&thread->lock);

        if (thread->in_vm) {
            if (!tgid || thread->tgid == tgid) {
                if (!sig) {
                    /* special case of sig == 0: don't really send signal but report success */
                    unlock(&thread->lock);
                    put_thread(thread);
                    return 0;
                }

                siginfo_t info = {
                    .si_signo = sig,
                    .si_pid   = sender,
                };
                ret = append_signal(thread, &info);
                if (ret >= 0) {
                    thread_wakeup(thread);
                    DkThreadResume(thread->pal_handle);
                }
            }
            use_ipc = false;
        } else {
            use_ipc = true;
        }

        unlock(&thread->lock);
        put_thread(thread);
    }

    if (!use_ipc) {
        return ret;
    }

    return ipc_pid_kill_send(sender, tid, KILL_THREAD, sig);
}

int shim_do_tkill(pid_t tid, int sig) {
    if (tid <= 0)
        return -EINVAL;

    struct shim_thread* cur = get_cur_thread();

    if ((IDTYPE)tid == cur->tid) {
        if (sig) {
            siginfo_t info;
            memset(&info, 0, sizeof(siginfo_t));
            info.si_signo = sig;
            info.si_pid   = cur->tid;
            deliver_signal(&info, NULL);
        }
        return 0;
    }

    return do_kill_thread(cur->tgid, 0, tid, sig, /*use_ipc=*/true);
}

int shim_do_tgkill(pid_t tgid, pid_t tid, int sig) {
    if (tgid < -1 || tgid == 0 || tid <= 0)
        return -EINVAL;

    if (tgid == -1)
        tgid = 0;

    struct shim_thread* cur = get_cur_thread();

    if ((IDTYPE)tid == cur->tid) {
        if (sig) {
            siginfo_t info;
            memset(&info, 0, sizeof(siginfo_t));
            info.si_signo = sig;
            info.si_pid   = cur->tid;
            deliver_signal(&info, NULL);
        }
        return 0;
    }

    return do_kill_thread(cur->tgid, tgid, tid, sig, /*use_ipc=*/true);
}
