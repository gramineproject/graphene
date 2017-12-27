/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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
 * shim_wait.c
 *
 * Implementation of system call "wait4".
 */

#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_profile.h>

#include <pal.h>
#include <pal_error.h>

#include <sys/syscall.h>
#include <sys/mman.h>
#include <asm/prctl.h>
#include <linux/wait.h>
#include <errno.h>

DEFINE_PROFILE_CATAGORY(wait, );
DEFINE_PROFILE_INTERVAL(child_exit_notification, wait);

pid_t shim_do_wait4 (pid_t pid, int * status, int option,
                     struct __kernel_rusage * ru)
{
    struct shim_thread * cur = get_cur_thread();
    struct shim_thread * thread = NULL;
    int ret = 0;

    INC_PROFILE_OCCURENCE(syscall_use_ipc);

    if (pid > 0) {
        if (!(thread = lookup_thread(pid)))
            return -ECHILD;

        if (!(option & WNOHANG)) {
block_pid:
            DkObjectsWaitAny(1, &thread->exit_event,
                             NO_TIMEOUT);
        }

        lock(thread->lock);

        if (thread->is_alive) {
            unlock(thread->lock);
            if (!(option & WNOHANG))
                goto block_pid;
            put_thread(thread);
            return 0;
        }

        if (!list_empty(thread, siblings)) {
            debug("reaping thread %p\n", thread);
            struct shim_thread * parent = thread->parent;
            assert(parent);

            lock(parent->lock);
            /* DEP 5/15/17: These threads are exited */
            assert(!thread->is_alive);
            listp_del_init(thread, &thread->parent->exited_children, siblings);
            unlock(parent->lock);

            put_thread(parent);
            put_thread(thread);
            thread->parent = NULL;
        }

        unlock(thread->lock);
        goto found;
    }

    lock(cur->lock);

    if (listp_empty(&cur->children) &&
        listp_empty(&cur->exited_children)) {
        unlock(cur->lock);
        return -ECHILD;
    }

    if (!(option & WNOHANG)) {
block:
        if (cur->child_exit_event)
            while (listp_empty(&cur->exited_children)) {
                unlock(cur->lock);
                DkObjectsWaitAny(1, &cur->child_exit_event, NO_TIMEOUT);
                lock(cur->lock);
            }
    }

    if (pid == 0 || pid < -1) {
        if (pid == 0)
            pid = -cur->pgid;

        listp_for_each_entry(thread, &cur->exited_children, siblings)
            if (thread->pgid == -pid)
                goto found_child;

        if (!(option & WNOHANG))
            goto block;
    } else {
        if (!listp_empty(&cur->exited_children)) {
            thread = listp_first_entry(&cur->exited_children,
                                       struct shim_thread, siblings);
            goto found_child;
        }
    }

    unlock(cur->lock);
    return 0;

found_child:
    listp_del_init(thread, &cur->exited_children, siblings);
    put_thread(cur);
    thread->parent = NULL;

    if (listp_empty(&cur->exited_children))
        DkEventClear(cur->child_exit_event);

    unlock(cur->lock);

found:
    if (status) {
        /* Bits 0--7 are for the signal, if any.  
         * Bits 8--15 are for the exit code */
        *status = thread->term_signal;
        *status |= ((thread->exit_code & 0xff) << 8);
    }

    ret = thread->tid;
    SAVE_PROFILE_INTERVAL_SINCE(child_exit_notification, thread->exit_time);
    del_thread(thread);
    put_thread(thread);
    return ret;
}
