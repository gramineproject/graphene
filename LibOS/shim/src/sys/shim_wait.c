/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/* We need to include this to get size_t definition, which otherwise is missing in <linux/signal.h>
 * (at least on Ubuntu16.04) */
#include <stddef.h>

#include <linux/signal.h>
#include <linux/wait.h>
#include <stdbool.h>

#include "assert.h"
#include "api.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_signal.h"
#include "shim_table.h"
#include "shim_thread.h"
#include "shim_types.h"

/* For wait4() return value */
#define WCOREFLAG 0x80

static bool child_matches_flags(struct shim_child_process* child, int flags) {
    if (flags & __WALL) {
        return true;
    }

    return (!!(flags & __WCLONE)) ^ (child->child_termination_signal == SIGCHLD);
}

static bool child_matches(struct shim_child_process* child, int which, IDTYPE id, int flags) {
    if (!child_matches_flags(child, flags)) {
        return false;
    }

    bool ret = false;
    switch (which) {
        case P_PID:
            if (child->pid == id) {
                ret = true;
            }
            break;
        case P_PGID:
            /* TODO: this makes no sense, until we implement IPC pgid change. */
            break;
        case P_ALL:
            ret = true;
            break;
        default:
            /* Impossible. */
            BUG();
            break;
    }

    return ret;
}

static void remove_qnode_from_wait_queue(struct shim_thread_queue* qnode) {
    lock(&g_process.children_lock);

    bool seen = false;
    if (g_process.wait_queue == qnode) {
        g_process.wait_queue = qnode->next;
        seen = true;
    } else if (g_process.wait_queue) {
        struct shim_thread_queue* tmp = g_process.wait_queue;
        while (tmp->next) {
            if (tmp->next == qnode) {
                tmp->next = qnode->next;
                seen = true;
                break;
            }
            tmp = tmp->next;
        }
    }

    unlock(&g_process.children_lock);

    while (!seen) {
        DkEventClear(get_cur_thread()->scheduler_event);
        /* Check `mark_child_exited` for explanation why we might need this compiler barrier. */
        COMPILER_BARRIER();
        /* Check if `qnode` is no longer used. */
        if (!__atomic_load_n(&qnode->in_use, __ATOMIC_ACQUIRE)) {
            break;
        }
        /* We cannot handle any errors here. */
        (void)thread_sleep(NO_TIMEOUT);
    }
}

static long do_waitid(int which, pid_t id, siginfo_t* infop, int options) {
    if (options & __WALL) {
        options &= ~__WCLONE;
    }

    if (options & WSTOPPED) {
        debug("Ignoring unsupported WSTOPPED flag to wait4\n");
        options &= ~WSTOPPED;
    }
    if (options & WCONTINUED) {
        debug("Ignoring unsupported WCONTINUED flag to wait4\n");
        options &= ~WCONTINUED;
    }
    assert(options & WEXITED);

    if (options & __WNOTHREAD) {
        debug("Ignoring unsupported __WNOTHREAD flag to wait4\n");
        options &= ~__WNOTHREAD;
    }

    if (!(which == P_PGID || which == P_ALL || which == P_PID))
        return -EINVAL;

    long ret = 0;

    lock(&g_process.children_lock);

    while (1) {
        struct shim_child_process* child;
        /* First search already exited children. */
        LISTP_FOR_EACH_ENTRY(child, &g_process.zombies, list) {
            if (child_matches(child, which, id, options)) {
                /* We have a match! */
                if (infop) {
                    infop->si_pid = child->pid;
                    infop->si_uid = child->uid;
                    infop->si_signo = SIGCHLD;

                    fill_siginfo_code_and_status(infop, child->term_signal, child->exit_code);
                }

                if (!(options & WNOWAIT)) {
                    LISTP_DEL_INIT(child, &g_process.zombies, list);
                    destroy_child_process(child);
                }
                ret = 0;
                goto out;
            }
        }

        /* Do we have any non-exited child to wait for? */
        bool have_waitable_child = false;
        LISTP_FOR_EACH_ENTRY(child, &g_process.children, list) {
            if (child_matches(child, which, id, options)) {
                have_waitable_child = true;
                break;
            }
        }

        if (!have_waitable_child) {
            ret = -ECHILD;
            goto out;
        }
        /* There are some children we can wait for. */

        if (options & WNOHANG) {
            if (infop) {
                infop->si_pid = 0;
                infop->si_signo = 0;
            }
            ret = 0;
            goto out;
        }

        /* Ok, let's wait. */
        struct shim_thread* self = get_cur_thread();
        struct shim_thread_queue qnode = {
            .thread = self,
            .next = g_process.wait_queue,
        };
        g_process.wait_queue = &qnode;
        __atomic_store_n(&qnode.in_use, true, __ATOMIC_RELEASE);

        __atomic_store_n(&self->signal_handled, SIGNAL_NOT_HANDLED, __ATOMIC_RELEASE);

        unlock(&g_process.children_lock);

        while (1) {
            if (__atomic_load_n(&self->signal_handled, __ATOMIC_ACQUIRE) == SIGNAL_HANDLED) {
                remove_qnode_from_wait_queue(&qnode);
                return -EINTR;
            }

            DkEventClear(self->scheduler_event);
            /* Check `mark_child_exited` for explanation why we might need this compiler barrier. */
            COMPILER_BARRIER();
            /* Check that we are still supposed to sleep. */
            if (!__atomic_load_n(&qnode.in_use, __ATOMIC_ACQUIRE)) {
                break;
            }
            ret = thread_sleep(NO_TIMEOUT);
            if (ret < 0 && ret != -EINTR && ret != -EAGAIN && ret != -EWOULDBLOCK) {
                debug("thread_sleep failed in waitid\n");

                remove_qnode_from_wait_queue(&qnode);
                /* `ret` is already set. */
                return ret;
            }

            handle_signals();
        }

        lock(&g_process.children_lock);
    }

out:
    unlock(&g_process.children_lock);
    return ret;
}

long shim_do_waitid(int which, pid_t id, siginfo_t* infop, int options, struct __kernel_rusage* ru) {
    __UNUSED(ru);

    if (options & ~(WNOHANG | WNOWAIT | WEXITED | WSTOPPED | WCONTINUED |
                    __WNOTHREAD | __WCLONE | __WALL))
        return -EINVAL;

    if (!(options & (WEXITED | WSTOPPED | WCONTINUED)))
        return -EINVAL;

    if (infop && test_user_memory(infop, sizeof(*infop), /*write=*/true))
        return -EFAULT;

    return do_waitid(which, id, infop, options);
}

long shim_do_wait4(pid_t pid, int* status, int options, struct __kernel_rusage* ru) {
    __UNUSED(ru);

    int which;
    pid_t id;
    siginfo_t info;

    if (options & ~(WNOHANG | WUNTRACED | WCONTINUED | __WNOTHREAD | __WCLONE | __WALL)) {
        return -EINVAL;
    }

    if (status && test_user_memory(status, sizeof(*status), /*write=*/true))
        return -EFAULT;

    /* Prepare options for do_waitid(). */
    options |= WEXITED;
    if (options & WUNTRACED) {
        options &= ~WUNTRACED;
        options |= WSTOPPED;
    }

    if (pid < -1) {
        which = P_PGID;
        id = -pid;
    } else if (pid == -1) {
        which = P_ALL;
        id = 0;
    } else if (pid == 0) {
        which = P_PGID;
        id = 0;
    } else {
        which = P_PID;
        id = pid;
    }

    info.si_pid = 0;
    int ret = do_waitid(which, id, &info, options);
    if (ret < 0)
        return ret;

    if (info.si_pid == 0)
        return 0;

    if (status) {
        if (info.si_code == CLD_EXITED) {
            *status = (info.si_status & 0xff) << 8;
        } else if (info.si_code == CLD_DUMPED) {
            *status = info.si_status | WCOREFLAG;
        } else {
            *status = info.si_status;
        }
    }
    return info.si_pid;
}
