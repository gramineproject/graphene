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
 * shim_sigaction.c
 *
 * Implementation of system call "sigaction", "sigreturn", "sigprocmask",
 * "kill", "tkill" and "tgkill".
 */

#include <errno.h>
#include <stddef.h>  // FIXME(mkow): Without this we get:
                     //     asm/signal.h:126:2: error: unknown type name ‘size_t’
                     // It definitely shouldn't behave like this...
#include <linux/signal.h>

#include <pal.h>
#include <pal_error.h>
#include <shim_internal.h>
#include <shim_ipc.h>
#include <shim_profile.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_utils.h>

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
    int err = 0;

    assert(!act || (void*)act->k_sa_handler != (void*)0x11);

    struct shim_signal_handle* sighdl = &cur->signal_handles[signum - 1];

    lock(&cur->lock);

    if (oldact) {
        if (sighdl->action) {
            memcpy(oldact, sighdl->action, sizeof(struct __kernel_sigaction));
        } else {
            memset(oldact, 0, sizeof(struct __kernel_sigaction));
            oldact->k_sa_handler = SIG_DFL;
        }
    }

    if (act) {
        if (!(sighdl->action))
            sighdl->action = malloc(sizeof(struct __kernel_sigaction));

        if (!(sighdl->action)) {
            err = -ENOMEM;
            goto out;
        }

        memcpy(sighdl->action, act, sizeof(struct __kernel_sigaction));
    }

    err = 0;
out:
    unlock(&cur->lock);
    return err;
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

    void* sp = (void*)shim_get_tcb()->context.regs->rsp;
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

    __sigset_t* old;
    __sigset_t tmp;
    struct shim_thread* cur = get_cur_thread();

    lock(&cur->lock);

    /* return immediately on some pending unblocked signal */
    for (int sig = 1; sig <= NUM_SIGS; sig++) {
        if (signal_logs_pending(cur->signal_logs, sig)) {
            /* at least one signal of type sig... */
            if (!__sigismember(mask, sig)) {
                /* ...and this type is not blocked in supplied mask */
                unlock(&cur->lock);
                return -EINTR;
            }
        }
    }

    old = get_sig_mask(cur);
    memcpy(&tmp, old, sizeof(__sigset_t));
    old = &tmp;

    set_sig_mask(cur, mask);
    cur->suspend_on_signal = true;
    unlock(&cur->lock);

    thread_setwait(NULL, NULL);
    thread_sleep(NO_TIMEOUT);

    lock(&cur->lock);
    set_sig_mask(cur, old);
    unlock(&cur->lock);
    return -EINTR;
}

int shim_do_sigpending(__sigset_t* set, size_t sigsetsize) {
    if (sigsetsize != sizeof(*set))
        return -EINVAL;

    if (!set || test_user_memory(set, sigsetsize, false))
        return -EFAULT;

    struct shim_thread* cur = get_cur_thread();

    __sigemptyset(set);

    if (!cur->signal_logs)
        return 0;

    for (int sig = 1; sig <= NUM_SIGS; sig++) {
        if (signal_logs_pending(cur->signal_logs, sig))
            __sigaddset(set, sig);
    }

    return 0;
}

struct walk_arg {
    struct shim_thread* current;
    IDTYPE sender;
    IDTYPE id;
    int sig;
    bool use_ipc;
};

// Need to hold thread->lock
static inline void __append_signal(struct shim_thread* thread, int sig, IDTYPE sender) {
    assert(locked(&thread->lock));

    debug("Thread %d killed by signal %d\n", thread->tid, sig);
    siginfo_t info;
    memset(&info, 0, sizeof(siginfo_t));
    info.si_signo = sig;
    info.si_pid   = sender;
    append_signal(thread, sig, &info, true);
}

static int __kill_proc(struct shim_thread* thread, void* arg, bool* unlocked) {
    struct walk_arg* warg = (struct walk_arg*)arg;
    int srched = 0;

    if (!warg->use_ipc && !thread->in_vm)
        return 0;

    if (thread->tgid != warg->id)
        return 0;

    if (warg->current == thread)
        return 1;

    /* DEP: Let's do a racy read of is_alive and in_vm.
     * If either of these are zero it is a stable condition,
     * and we can elide the lock acquire (which helps perf).
     */
    if (!thread->is_alive)
        goto out;

    if (!thread->in_vm) {
        unlock(&thread_list_lock);
        *unlocked = true;
        return (!ipc_pid_kill_send(warg->sender, warg->id, KILL_PROCESS, warg->sig)) ? 1 : 0;
    } else {
        lock(&thread->lock);

        if (!thread->is_alive)
            goto out_locked;

        if (thread->in_vm) {
            if (warg->sig > 0)
                __append_signal(thread, warg->sig, warg->sender);
            srched = 1;
        } else {
            /* This double-check case is probably unnecessary, but keep it for now */
            unlock(&thread->lock);
            unlock(&thread_list_lock);
            *unlocked = true;
            return (!ipc_pid_kill_send(warg->sender, warg->id, KILL_PROCESS, warg->sig)) ? 1 : 0;
        }
    }
out_locked:
    unlock(&thread->lock);
out:
    return srched;
}

static int __kill_proc_simple(struct shim_simple_thread* sthread, void* arg, bool* unlocked) {
    struct walk_arg* warg = (struct walk_arg*)arg;
    int srched = 0;

    if (sthread->tgid != warg->id)
        return 0;

    lock(&sthread->lock);

    if (sthread->is_alive) {
        unlock(&sthread->lock);
        unlock(&thread_list_lock);
        *unlocked = true;
        return (!ipc_pid_kill_send(warg->sender, warg->id, KILL_PROCESS, warg->sig)) ? 1 : 0;
    }

    unlock(&sthread->lock);
    return srched;
}

int do_kill_proc(IDTYPE sender, IDTYPE tgid, int sig, bool use_ipc) {
    struct shim_thread* cur = get_cur_thread();

    if (!tgid) {
        /* DEP: cur->tgid never changes.  No lock needed */
        tgid = cur->tgid;
    }

    struct walk_arg arg;
    arg.current = cur;
    arg.sender  = sender;
    arg.id      = tgid;
    arg.sig     = sig;
    arg.use_ipc = use_ipc;

    bool srched = false;

    if (!walk_thread_list(__kill_proc, &arg))
        srched = true;

    if (!use_ipc || srched)
        goto out;

    if (!walk_simple_thread_list(__kill_proc_simple, &arg))
        srched = true;

    if (!srched && !ipc_pid_kill_send(sender, tgid, KILL_PROCESS, sig))
        srched = true;

out:
    return srched ? 0 : -ESRCH;
}

static int __kill_pgroup(struct shim_thread* thread, void* arg, bool* unlocked) {
    struct walk_arg* warg = (struct walk_arg*)arg;
    int srched = 0;

    if (!warg->use_ipc && !thread->in_vm)
        return 0;

    if (thread->pgid != warg->id)
        return 0;

    if (warg->current == thread)
        return 1;

    lock(&thread->lock);

    if (!thread->is_alive)
        goto out;

    if (thread->in_vm) {
        if (warg->sig > 0)
            __append_signal(thread, warg->sig, warg->sender);

        srched = 1;
    } else {
        unlock(&thread->lock);
        unlock(&thread_list_lock);
        *unlocked = true;
        return (!ipc_pid_kill_send(warg->sender, warg->id, KILL_PGROUP, warg->sig)) ? 1 : 0;
    }

out:
    unlock(&thread->lock);
    return srched;
}

static int __kill_pgroup_simple(struct shim_simple_thread* sthread, void* arg, bool* unlocked) {
    struct walk_arg* warg = (struct walk_arg*)arg;
    int srched = 0;

    if (sthread->pgid != warg->id)
        return 0;

    lock(&sthread->lock);

    if (sthread->is_alive) {
        unlock(&sthread->lock);
        unlock(&thread_list_lock);
        *unlocked = true;
        return (!ipc_pid_kill_send(warg->sender, warg->id, KILL_PGROUP, warg->sig)) ? 1 : 0;
    }

    unlock(&sthread->lock);
    return srched;
}

int do_kill_pgroup(IDTYPE sender, IDTYPE pgid, int sig, bool use_ipc) {
    struct shim_thread* cur = get_cur_thread();

    if (!pgid) {
        pgid = cur->pgid;
    }

    struct walk_arg arg;
    arg.current = cur;
    arg.sender  = sender;
    arg.id      = pgid;
    arg.sig     = sig;
    arg.use_ipc = use_ipc;

    bool srched = false;

    if (!walk_thread_list(__kill_pgroup, &arg))
        srched = true;

    if (!use_ipc || srched)
        goto out;

    if (!walk_simple_thread_list(__kill_pgroup_simple, &arg))
        srched = true;

    if (!srched && !ipc_pid_kill_send(sender, pgid, KILL_PGROUP, sig))
        srched = true;

out:
    return srched ? 0 : -ESRCH;
}

static int __kill_all_threads(struct shim_thread* thread, void* arg, bool* unlocked) {
    __UNUSED(unlocked);  // Retained for API compatibility
    int srched = 0;
    struct walk_arg* warg = (struct walk_arg*)arg;

    if (thread->tgid != thread->tid)
        return 0;

    if (warg->current == thread)
        return 1;

    lock(&thread->lock);

    if (thread->in_vm) {
        __append_signal(thread, warg->sig, warg->sender);
        srched = 1;
    }

    unlock(&thread->lock);
    return srched;
}

int kill_all_threads(struct shim_thread* cur, IDTYPE sender, int sig) {
    struct walk_arg arg;
    arg.current = cur;
    arg.sender  = sender;
    arg.id      = 0;
    arg.sig     = sig;
    arg.use_ipc = false;
    walk_thread_list(__kill_all_threads, &arg);
    return 0;
}

int shim_do_kill(pid_t pid, int sig) {
    INC_PROFILE_OCCURENCE(syscall_use_ipc);

    if (sig < 0 || sig > NUM_SIGS)
        return -EINVAL;

    struct shim_thread* cur = get_cur_thread();
    int ret = 0;
    bool send_to_self = false;

    /* If pid equals 0, then sig is sent to every process in the process group
       of the calling process. */
    if (pid == 0) {
        ret = do_kill_pgroup(cur->tgid, 0, sig, true);
        send_to_self = true;
    }

    /* If pid equals -1, then sig is sent to every process for which the
       calling process has permission to send */
    else if (pid == -1) {
        ipc_pid_kill_send(cur->tid, /*target=*/0, KILL_ALL, sig);
        kill_all_threads(cur, cur->tid, sig);
        send_to_self = true;
    }

    /* If pid is positive, then signal sig is sent to the process with the ID
       specified by pid. */
    else if (pid > 0) {
        ret = do_kill_proc(cur->tid, pid, sig, true);
        send_to_self = (IDTYPE)pid == cur->tgid;
    }

    /* If pid is less than -1, then sig is sent to every process in the
       process group whose id is -pid */
    else {
        ret = do_kill_pgroup(cur->tid, -pid, sig, true);
        send_to_self = (IDTYPE)-pid == cur->pgid;
    }

    if (send_to_self) {
        if (ret == -ESRCH)
            ret = 0;
        if (sig) {
            siginfo_t info;
            memset(&info, 0, sizeof(siginfo_t));
            info.si_signo = sig;
            info.si_pid   = cur->tid;
            deliver_signal(&info, NULL);
        }
    }

    return ret < 0 ? ret : 0;
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
                __append_signal(thread, sig, sender);
                ret = 0;
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
    INC_PROFILE_OCCURENCE(syscall_use_ipc);

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

    return do_kill_thread(cur->tgid, 0, tid, sig, true);
}

int shim_do_tgkill(pid_t tgid, pid_t tid, int sig) {
    INC_PROFILE_OCCURENCE(syscall_use_ipc);

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

    return do_kill_thread(cur->tgid, tgid, tid, sig, true);
}
