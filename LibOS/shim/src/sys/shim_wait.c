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
#include "shim_table.h"
#include "shim_thread.h"
#include "shim_utils.h"

int shim_do_waitid(int which, pid_t id, siginfo_t* infop, int option, struct __kernel_rusage* ru) {
    struct shim_thread* cur    = get_cur_thread();
    struct shim_thread* thread = NULL;
    __UNUSED(ru);

    if (option & ~(WNOHANG | WUNTRACED | WEXITED | WCONTINUED | __WNOTHREAD | __WCLONE | __WALL)) {
        return -EINVAL;
    }

    if (!(which == P_PGID || which == P_ALL || which == P_PID))
        return -EINVAL;

    if (which == P_PID) {
        pid_t pid = id;

        if (!(thread = lookup_thread(pid)))
            return -ECHILD;

        if (!(option & WNOHANG)) {
        block_pid:
            object_wait_with_retry(thread->exit_event);
        }

        lock(&thread->lock);

        if (thread->is_alive) {
            unlock(&thread->lock);
            if (!(option & WNOHANG))
                goto block_pid;
            put_thread(thread);
            return 0;
        }

        if (!LIST_EMPTY(thread, siblings)) {
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

    if (!(option & WNOHANG)) {
    block:
        if (cur->child_exit_event)
            while (LISTP_EMPTY(&cur->exited_children)) {
                unlock(&cur->lock);
                object_wait_with_retry(cur->child_exit_event);
                lock(&cur->lock);
            }
    }

    if (which == P_ALL || which == P_PGID) {
        pid_t pid;
        if (which == P_ALL)
            pid = -cur->pgid;
        else
            pid = -id;

        LISTP_FOR_EACH_ENTRY(thread, &cur->exited_children, siblings) {
            if (thread->pgid == (IDTYPE)-pid)
                goto found_child;
        }

        if (!(option & WNOHANG))
            goto block;
    } else {
        assert (which == P_ALL);

        if (!LISTP_EMPTY(&cur->exited_children)) {
            thread = LISTP_FIRST_ENTRY(&cur->exited_children, struct shim_thread, siblings);
            goto found_child;
        }
    }

    unlock(&cur->lock);

    if (infop) {
        infop->si_signo = 0;
        infop->si_code = 0;
        infop->si_pid = 0;
    }
    return 0;

found_child:
    LISTP_DEL_INIT(thread, &cur->exited_children, siblings);
    put_thread(cur);
    thread->parent = NULL;

    if (LISTP_EMPTY(&cur->exited_children))
        DkEventClear(cur->child_exit_event);

    unlock(&cur->lock);

found:
    if (infop) {
        infop->si_pid = thread->tid;
        infop->si_uid = thread->uid;
        infop->si_signo = SIGCHLD;

        /* Bits 0--7 are for the signal, if any.
         * Bits 8--15 are for the exit code */
        infop->si_code = thread->term_signal;
        infop->si_code |= ((thread->exit_code & 0xff) << 8);

        if (thread->term_signal == 0)
            infop->si_status = CLD_EXITED;
        else
            infop->si_status = CLD_KILLED;
    }

    del_thread(thread);
    put_thread(thread);
    return 0;
}

pid_t shim_do_wait4(pid_t pid, int* status, int option, struct __kernel_rusage* ru) {
    int which;
    pid_t id;
    siginfo_t info;

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
    info.si_code = 0;
    int ret = shim_do_waitid(which, id, &info, option, ru);
    if (ret >= 0) {
        ret = info.si_pid;
        if (status)
            *status = info.si_code;
    }
    return ret;
}
