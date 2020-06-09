/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * shim_wait.c
 *
 * Implementation of system call "wait4".
 */

#include <errno.h>
#include <linux/wait.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_utils.h>
#include <sys/mman.h>
#include <sys/syscall.h>

pid_t shim_do_wait4(pid_t pid, int* status, int option, struct __kernel_rusage* ru) {
    struct shim_thread* cur    = get_cur_thread();
    struct shim_thread* thread = NULL;
    int ret                    = 0;
    __UNUSED(ru);

    if (option & ~(WNOHANG | WUNTRACED | WCONTINUED | __WNOTHREAD | __WCLONE | __WALL)) {
        return -EINVAL;
    }

    if (pid > 0) {
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

    if (pid == 0 || pid < -1) {
        if (pid == 0)
            pid = -cur->pgid;

        LISTP_FOR_EACH_ENTRY(thread, &cur->exited_children, siblings) {
            if (thread->pgid == (IDTYPE)-pid)
                goto found_child;
        }

        if (!(option & WNOHANG))
            goto block;
    } else {
        if (!LISTP_EMPTY(&cur->exited_children)) {
            thread = LISTP_FIRST_ENTRY(&cur->exited_children, struct shim_thread, siblings);
            goto found_child;
        }
    }

    unlock(&cur->lock);
    return 0;

found_child:
    LISTP_DEL_INIT(thread, &cur->exited_children, siblings);
    put_thread(cur);
    thread->parent = NULL;

    if (LISTP_EMPTY(&cur->exited_children))
        DkEventClear(cur->child_exit_event);

    unlock(&cur->lock);

found:
    if (status) {
        /* Bits 0--7 are for the signal, if any.
         * Bits 8--15 are for the exit code */
        *status = thread->term_signal;
        *status |= ((thread->exit_code & 0xff) << 8);
    }

    ret = thread->tid;
    del_thread(thread);
    put_thread(thread);
    return ret;
}
