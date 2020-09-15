/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * shim_wait.c
 *
 * Implementation of system call "wait4".
 */

#include <errno.h>
#include <linux/wait.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_internal.h"
#include "shim_signal.h"
#include "shim_table.h"
#include "shim_thread.h"
#include "shim_utils.h"


/* For wait4() return value */
#define WCOREFLAG 0x80


long shim_do_waitid(int which, pid_t id, siginfo_t* infop, int options, struct __kernel_rusage* ru) {
    struct shim_thread* cur    = get_cur_thread();
    struct shim_thread* thread = NULL;
    int ret;
    __UNUSED(ru);

    /* Note that we don't support WSTOPPED or WCONTINUED correctly. */
    if (options & ~(WNOHANG | WNOWAIT | WEXITED | WSTOPPED | WCONTINUED |
                    __WNOTHREAD| __WCLONE | __WALL))
        return -EINVAL;

    if (!(options & (WEXITED | WSTOPPED | WCONTINUED)))
        return -EINVAL;

    if (!(which == P_PGID || which == P_ALL || which == P_PID))
        return -EINVAL;

    if (infop && test_user_memory(infop, sizeof(*infop), /*write=*/true))
        return -EFAULT;

    if (which == P_PID) {
        pid_t pid = id;

        if (!(thread = lookup_thread(pid)))
            return -ECHILD;

        if (!(options & WNOHANG)) {
        block_pid:
            object_wait_with_retry(thread->exit_event);
        }

        lock(&thread->lock);

        if (thread->is_alive) {
            unlock(&thread->lock);
            if (!(options & WNOHANG))
                goto block_pid;
            put_thread(thread);

            if (infop) {
                infop->si_pid = 0;
                infop->si_signo = 0;
            }
            return 0;
        }

        if (!(options & WNOWAIT) && !LIST_EMPTY(thread, siblings)) {
            debug("reaping thread %p\n", thread);
            struct shim_thread* parent = thread->parent;
            assert(parent);

            lock(&parent->lock);
            /* DEP 5/15/17: These threads are exited */
            assert(!thread->is_alive);
            LISTP_DEL_INIT(thread, &parent->exited_children, siblings);
            unlock(&parent->lock);

            put_thread(parent);
            thread->parent = NULL;
            put_thread(thread);
        }

        unlock(&thread->lock);
        goto found;
    }

    lock(&cur->lock);

    if (LISTP_EMPTY(&cur->children) && LISTP_EMPTY(&cur->exited_children)) {
        unlock(&cur->lock);
        return -ECHILD;
    }

    if (!(options & WNOHANG)) {
    block:
        if (cur->child_exit_event)
            while (LISTP_EMPTY(&cur->exited_children)) {
                unlock(&cur->lock);
                object_wait_with_retry(cur->child_exit_event);
                lock(&cur->lock);
            }
    }

    if (which == P_PGID) {
        IDTYPE pgid;
        if (id == 0)
            pgid = cur->pgid;
        else
            pgid = id;

        LISTP_FOR_EACH_ENTRY(thread, &cur->exited_children, siblings) {
            if (thread->pgid == pgid) {
                get_thread(thread);
                goto found_child;
            }
        }

        if (!(options & WNOHANG))
            goto block;
    } else {
        assert(which == P_ALL);

        if (!LISTP_EMPTY(&cur->exited_children)) {
            thread = LISTP_FIRST_ENTRY(&cur->exited_children, struct shim_thread, siblings);
            get_thread(thread);
            goto found_child;
        }
    }

    unlock(&cur->lock);

    if (infop) {
        infop->si_pid = 0;
        infop->si_signo = 0;
    }
    return 0;

found_child:
    if (!(options & WNOWAIT)) {
        LISTP_DEL_INIT(thread, &cur->exited_children, siblings);
        put_thread(cur);
        thread->parent = NULL;

        if (LISTP_EMPTY(&cur->exited_children))
            DkEventClear(cur->child_exit_event);
    }

    unlock(&cur->lock);

found:
    ret = 0;
    if (infop) {
        infop->si_pid = thread->tid;
        infop->si_uid = thread->uid;
        infop->si_signo = SIGCHLD;

        if (thread->term_signal == 0) {
            infop->si_code = CLD_EXITED;
            infop->si_status = thread->exit_code;
        } else if (thread->term_signal & __WCOREDUMP_BIT) {
            infop->si_code = CLD_DUMPED;
            infop->si_status = thread->term_signal & ~__WCOREDUMP_BIT;
        } else {
            infop->si_code = CLD_KILLED;
            infop->si_status = thread->term_signal;
        }
    }

    if (!(options & WNOWAIT))
        del_thread(thread);

    put_thread(thread);
    return ret;
}

long shim_do_wait4(pid_t pid, int* status, int options, struct __kernel_rusage* ru) {
    int which;
    pid_t id;
    siginfo_t info;

    /* Note that only WNOHANG is handled correctly. */
    if (options & ~(WNOHANG | WUNTRACED | WCONTINUED | __WNOTHREAD | __WCLONE | __WALL)) {
        return -EINVAL;
    }

    if (status && test_user_memory(status, sizeof(*status), /*write=*/true))
        return -EFAULT;

    /* Prepare options for shim_do_waitid(). */
    options |= WEXITED;
    if (options & WUNTRACED)
        options &= ~WUNTRACED;

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
    int ret = shim_do_waitid(which, id, &info, options, ru);
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
