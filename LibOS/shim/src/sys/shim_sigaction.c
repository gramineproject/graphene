/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * Implementation of system calls "sigaction", "sigreturn", "sigprocmask", "kill", "tkill"
 * and "tgkill".
 */

#include <asm/unistd.h>
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

long shim_do_rt_sigaction(int signum, const struct __kernel_sigaction* act,
                          struct __kernel_sigaction* oldact, size_t sigsetsize) {
    /* SIGKILL and SIGSTOP cannot be caught or ignored */
    if (signum == SIGKILL || signum == SIGSTOP || signum <= 0 || signum > NUM_SIGS ||
            sigsetsize != sizeof(__sigset_t))
        return -EINVAL;

    if (act && test_user_memory((void*)act, sizeof(*act), false))
        return -EFAULT;

    if (oldact && test_user_memory(oldact, sizeof(*oldact), true))
        return -EFAULT;

    if (act && !(act->sa_flags & SA_RESTORER)) {
        /* XXX: This might not be true for all architectures (but is for x86_64) ...
         * Check `shim_signal.c` if you update this! */
        debug("SA_RESTORER flag is required!\n");
        return -EINVAL;
    }

    struct shim_thread* cur = get_cur_thread();

    lock(&cur->signal_dispositions->lock);

    struct __kernel_sigaction* sigaction = &cur->signal_dispositions->actions[signum - 1];

    if (oldact)
        *oldact = *sigaction;

    if (act)
        *sigaction = *act;

    clear_illegal_signals(&sigaction->sa_mask);

    unlock(&cur->signal_dispositions->lock);
    return 0;
}

long shim_do_rt_sigreturn(void) {
    PAL_CONTEXT* context = SHIM_TCB_GET(context.regs);

    __sigset_t new_mask;
    restore_sigreturn_context(context, &new_mask);
    clear_illegal_signals(&new_mask);

    struct shim_thread* current = get_cur_thread();
    lock(&current->lock);
    set_sig_mask(current, &new_mask);
    unlock(&current->lock);

    /* We restored user context, it's not a syscall. */
    SHIM_TCB_SET(context.syscall_nr, -1);

    return pal_context_get_retval(context);
}

long shim_do_rt_sigprocmask(int how, const __sigset_t* set, __sigset_t* oldset) {
    __sigset_t old;

    if (how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK)
        return -EINVAL;

    if (set && test_user_memory((void*)set, sizeof(*set), false))
        return -EFAULT;

    if (oldset && test_user_memory(oldset, sizeof(*oldset), false))
        return -EFAULT;

    struct shim_thread* cur = get_cur_thread();

    lock(&cur->lock);

    get_sig_mask(cur, &old);

    if (oldset) {
        *oldset = old;
    }

    /* If set is NULL, then the signal mask is unchanged. */
    if (!set)
        goto out;

    switch (how) {
        case SIG_BLOCK:
            __sigorset(&old, &old, set);
            break;

        case SIG_UNBLOCK:
            __signotset(&old, &old, set);
            break;

        case SIG_SETMASK:
            old = *set;
            break;
    }

    clear_illegal_signals(&old);
    set_sig_mask(cur, &old);

out:
    unlock(&cur->lock);

    return 0;
}

long shim_do_sigaltstack(const stack_t* ss, stack_t* oss) {
    if (ss && test_user_memory((void*)ss, sizeof(*ss), /*writable=*/false)) {
        return -EFAULT;
    }
    if (oss && test_user_memory(oss, sizeof(*oss), /*writable=*/true)) {
        return -EFAULT;
    }

    if (ss && (ss->ss_flags & ~SS_DISABLE))
        return -EINVAL;

    struct shim_thread* cur = get_cur_thread();

    stack_t* cur_ss = &cur->signal_altstack;

    if (oss) {
        *oss = *cur_ss;
        if (cur_ss->ss_size == 0) {
            oss->ss_flags |= SS_DISABLE;
        }
    }

    if (is_on_altstack(pal_context_get_sp(shim_get_tcb()->context.regs), cur_ss)) {
        if (oss)
            oss->ss_flags |= SS_ONSTACK;
        if (ss && !(cur_ss->ss_flags & SS_DISABLE)) {
            return -EPERM;
        }
    }

    if (ss) {
        if (ss->ss_flags & SS_DISABLE) {
            memset(cur_ss, 0, sizeof(*cur_ss));
            cur_ss->ss_flags = SS_DISABLE;
        } else {
            if (ss->ss_size < MINSIGSTKSZ) {
                return -ENOMEM;
            }

            *cur_ss = *ss;
        }
    }

    return 0;
}

long shim_do_rt_sigsuspend(const __sigset_t* mask_ptr, size_t setsize) {
    if (setsize != sizeof(sigset_t)) {
        return -EINVAL;
    }
    if (!mask_ptr || test_user_memory((void*)mask_ptr, sizeof(*mask_ptr), false))
        return -EFAULT;

    __sigset_t mask = *mask_ptr;
    clear_illegal_signals(&mask);

    struct shim_thread* current = get_cur_thread();
    __sigset_t old;
    lock(&current->lock);
    get_sig_mask(current, &old);
    set_sig_mask(current, &mask);
    unlock(&current->lock);

    DkEventClear(current->scheduler_event);
    while (!have_pending_signals()) {
        int ret = thread_sleep(NO_TIMEOUT, /*ignore_pending_signals=*/false);
        if (ret < 0 && ret != -EINTR && ret != -EAGAIN) {
            return ret;
        }
    }

    /* XXX: This basicaly doubles the work of `shim_do_syscall`. The alternative would be to add
     * handling of saved signal mask (probably inside `current`) to `shim_do_syscall`, but as it
     * is specific to sigsuspend I'm leaving this here for now. */
    int ret = -EINTR;
    PAL_CONTEXT* context = SHIM_TCB_GET(context.regs);
    pal_context_set_retval(context, ret);

    debug_print_syscall_after(__NR_rt_sigsuspend, ret, ALL_SYSCALL_ARGS(context));

    if (!handle_signal(context, &old)) {
        restart_syscall(context, __NR_rt_sigsuspend);
    }

    SHIM_TCB_SET(context.syscall_nr, -1);
    SHIM_TCB_SET(context.regs, NULL);
    return_from_syscall(context);
}

long shim_do_rt_sigpending(__sigset_t* set, size_t sigsetsize) {
    if (sigsetsize != sizeof(*set))
        return -EINVAL;

    if (!set || test_user_memory(set, sigsetsize, false))
        return -EFAULT;

    get_pending_signals(set);

    return 0;
}

static int _wakeup_one_thread(struct shim_thread* thread, void* arg) {
    int sig = (int)(long)arg;
    int ret = 0;

    if (thread == get_cur_thread()) {
        return ret;
    }

    lock(&thread->lock);

    if (!__sigismember(&thread->signal_mask, sig)) {
        thread_wakeup(thread);
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

    int sig = info->si_signo;
    struct shim_thread* current = get_cur_thread();
    if (!is_internal(current)) {
        /* Can we handle this singal? */
        lock(&current->lock);
        if (!__sigismember(&current->signal_mask, sig)) {
            /* Yes we can. */
            unlock(&current->lock);
            return 0;
        }
        unlock(&current->lock);
    }

    ret = walk_thread_list(_wakeup_one_thread, (void*)(long)sig, /*one_shot=*/true);
    /* Ignore `-ESRCH` as this just means that currently no thread is able to handle the signal. */
    if (ret < 0 && ret != -ESRCH) {
        return ret;
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

int do_kill_pgroup(IDTYPE sender, IDTYPE pgid, int sig) {
    IDTYPE current_pgid = __atomic_load_n(&g_process.pgid, __ATOMIC_ACQUIRE);
    if (!pgid) {
        pgid = current_pgid;
    }

    int ret = ipc_pid_kill_send(sender, pgid, KILL_PGROUP, sig);
    if (ret < 0 && ret != -ESRCH) {
        return ret;
    }

    if (current_pgid != pgid) {
        return ret;
    }

    siginfo_t info = {
        .si_signo = sig,
        .si_pid   = sender,
        .si_code  = SI_USER
    };
    return kill_current_proc(&info);
}

long shim_do_kill(pid_t pid, int sig) {
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
        return do_kill_pgroup(g_process.pid, 0, sig);
    } else { // pid < -1
        /* If `pid` is less than -1, then signal is sent to every process in the process group
         * `-pid`. */
        return do_kill_pgroup(g_process.pid, -pid, sig);
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
        int ret = append_signal(thread, &info);
        if (ret < 0) {
            put_thread(thread);
            return ret;
        }
        if (thread != get_cur_thread()) {
            thread_wakeup(thread);
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

long shim_do_tkill(pid_t tid, int sig) {
    if (tid <= 0)
        return -EINVAL;

    return do_kill_thread(g_process.pid, 0, tid, sig, /*use_ipc=*/true);
}

long shim_do_tgkill(pid_t tgid, pid_t tid, int sig) {
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
