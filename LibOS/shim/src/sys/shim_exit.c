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
 * shim_exit.c
 *
 * Implementation of system call "exit" and "exit_group".
 */

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_ipc.h>
#include <shim_utils.h>
#include <shim_checkpoint.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <asm/prctl.h>
#include <linux/futex.h>

void release_robust_list (struct robust_list_head * head);

void release_clear_child_id (int * clear_child_tid);

int thread_exit(struct shim_thread * self, bool send_ipc)
{
    /* Chia-Che: Broadcast exit message as early as possible,
       so other process can start early on responding. */
    if (self->in_vm && send_ipc)
        ipc_cld_exit_send(self->ppid, self->tid, self->exit_code, self->term_signal);

    lock(self->lock);

    if (!self->is_alive) {
        debug("thread %d is dead\n", self->tid);
    out:
        unlock(self->lock);
        return 0;
    }

    #ifdef PROFILE
    self->exit_time = GET_PROFILE_INTERVAL();
    #endif

    int exit_code = self->exit_code;
    self->is_alive = false;

    if (IS_INTERNAL(self))
        goto out;

    struct shim_handle_map * handle_map = self->handle_map;
    struct shim_handle * exec = self->exec;
    struct shim_thread * parent = self->parent;
    self->handle_map = NULL;
    self->exec = NULL;

    if (parent) {
        assert(parent != self);
        assert(parent->child_exit_event);
        debug("thread exits, notifying thread %d\n", parent->tid);

        lock(parent->lock);
        listp_del_init(self, &parent->children, siblings);
        listp_add_tail(self, &parent->exited_children, siblings);

        if (!self->in_vm) {
            debug("deliver SIGCHLD (thread = %d, exitval = %d)\n",
                  self->tid, exit_code);

            siginfo_t info;
            memset(&info, 0, sizeof(siginfo_t));
            info.si_signo = SIGCHLD;
            info.si_pid   = self->tid;
            info.si_uid   = self->uid;
            info.si_status = (exit_code & 0xff) << 8;

            append_signal(parent, SIGCHLD, &info, true);
        }
        unlock(parent->lock);

        DkEventSet(parent->child_exit_event);
    } else {
        debug("parent not here, need to tell another process\n");
        ipc_cld_exit_send(self->ppid, self->tid, self->exit_code, self->term_signal);
    }

    struct robust_list_head * robust_list = (void *) self->robust_list;
    self->robust_list = NULL;

    unlock(self->lock);

    if (handle_map)
        put_handle_map(handle_map);

    if (exec)
        put_handle(exec);

    if (robust_list)
        release_robust_list(robust_list);

    if (self->clear_child_tid)
        release_clear_child_id (self->clear_child_tid);

    DkEventSet(self->exit_event);
    return 0;
}

int try_process_exit (int error_code, int term_signal)
{
    struct shim_thread * cur_thread = get_cur_thread();

    cur_thread->exit_code = -error_code;
    cur_process.exit_code = error_code;
    cur_thread->term_signal = term_signal;

    if (cur_thread->in_vm)
        thread_exit(cur_thread, true);

    if (check_last_thread(cur_thread))
        return 0;

    struct shim_thread * async_thread = terminate_async_helper();
    if (async_thread)
        /* TODO: wait for the thread to exit in host.
         * This is tracked by the following issue.
         * https://github.com/oscarlab/graphene/issues/440
         */
        put_thread(async_thread); /* free resources of the thread */

    struct shim_thread * ipc_thread;
    int ret = exit_with_ipc_helper(true, &ipc_thread);
    if (ipc_thread)
        /* TODO: wait for the thread to exit in host.
         * This is tracked by the following issue.
         * https://github.com/oscarlab/graphene/issues/440
         */
        put_thread(ipc_thread); /* free resources of the thread */
    if (!ret)
        shim_clean();
    else
        DkThreadExit();

    return 0;
}

int shim_do_exit_group (int error_code)
{
    INC_PROFILE_OCCURENCE(syscall_use_ipc);
    struct shim_thread * cur_thread = get_cur_thread();
    assert(!IS_INTERNAL(cur_thread));

    if (debug_handle)
        sysparser_printf("---- shim_exit_group (returning %d)\n", error_code);

    if (cur_thread->dummy) {
        cur_thread->term_signal = 0;
        thread_exit(cur_thread, true);
        switch_dummy_thread(cur_thread);
    }

    debug("now kill other threads in the process\n");
    do_kill_proc(cur_thread->tgid, cur_thread->tgid, SIGKILL, false);

    debug("now exit the process\n");
    try_process_exit(error_code, 0);

#ifdef PROFILE
    if (ENTER_TIME)
        SAVE_PROFILE_INTERVAL_SINCE(syscall_exit_group, ENTER_TIME);
#endif

    DkThreadExit();
    return 0;
}

int shim_do_exit (int error_code)
{
    INC_PROFILE_OCCURENCE(syscall_use_ipc);
    struct shim_thread * cur_thread = get_cur_thread();
    assert(!IS_INTERNAL(cur_thread));

    if (debug_handle)
        sysparser_printf("---- shim_exit (returning %d)\n", error_code);

    if (cur_thread->dummy) {
        cur_thread->term_signal = 0;
        thread_exit(cur_thread, true);
        switch_dummy_thread(cur_thread);
    }

    try_process_exit(error_code, 0);

#ifdef PROFILE
    if (ENTER_TIME)
        SAVE_PROFILE_INTERVAL_SINCE(syscall_exit, ENTER_TIME);
#endif

    DkThreadExit();
    return 0;
}
