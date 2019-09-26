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
    bool sent_exit_msg = false;

    /* Chia-Che: Broadcast exit message as early as possible,
       so other process can start early on responding. */
    if (self->in_vm && send_ipc) {
        ipc_cld_exit_send(self->ppid, self->tid, self->exit_code, self->term_signal);
        sent_exit_msg = true;
    }

    lock(&self->lock);

    if (!self->is_alive) {
        debug("thread %d is dead\n", self->tid);
    out:
        unlock(&self->lock);
        return 0;
    }

    #ifdef PROFILE
    self->exit_time = GET_PROFILE_INTERVAL();
    #endif

    int exit_code = self->exit_code;
    self->is_alive = false;

    if (is_internal(self))
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

        lock(&parent->lock);
        LISTP_DEL_INIT(self, &parent->children, siblings);
        LISTP_ADD_TAIL(self, &parent->exited_children, siblings);

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
        unlock(&parent->lock);

        DkEventSet(parent->child_exit_event);
    } else if (!sent_exit_msg) {
        debug("parent not here, need to tell another process\n");
        ipc_cld_exit_send(self->ppid, self->tid, self->exit_code, self->term_signal);
    }

    struct robust_list_head * robust_list = (void *) self->robust_list;
    self->robust_list = NULL;

    unlock(&self->lock);

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

/* note that term_signal argument may contain WCOREDUMP bit (0x80) */
int try_process_exit (int error_code, int term_signal)
{
    struct shim_thread * cur_thread = get_cur_thread();

    cur_thread->exit_code = -error_code;
    cur_process.exit_code = term_signal ? term_signal : error_code;
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

    struct shim_thread * ipc_thread = terminate_ipc_helper();
    if (ipc_thread)
        /* TODO: wait for the thread to exit in host.
         * This is tracked by the following issue.
         * https://github.com/oscarlab/graphene/issues/440
         */
        put_thread(ipc_thread); /* free resources of the thread */

    shim_clean(0);
    return 0;
}

noreturn int shim_do_exit_group (int error_code)
{
    INC_PROFILE_OCCURENCE(syscall_use_ipc);
    struct shim_thread * cur_thread = get_cur_thread();
    assert(!is_internal(cur_thread));

    /* If exit_group() is invoked multiple times, only a single invocation proceeds past this
     * point. Kill signals are delivered asynchronously, which will eventually kick the execution
     * out of this loop.*/
    static struct atomic_int first = ATOMIC_INIT(0);
    if (atomic_cmpxchg(&first, 0, 1) == 1) {
        while (1)
            DkThreadYieldExecution();
    }

    if (debug_handle)
        sysparser_printf("---- shim_exit_group (returning %d)\n", error_code);

#ifndef ALIAS_VFORK_AS_FORK
    if (cur_thread->dummy) {
        cur_thread->term_signal = 0;
        thread_exit(cur_thread, true);
        switch_dummy_thread(cur_thread);
    }
#endif

    debug("now kill other threads in the process\n");
    do_kill_proc(cur_thread->tgid, cur_thread->tgid, SIGKILL, false);
    /* This loop ensures that the current thread, which issues exit_group(), wins in setting the
     * process's exit code. try_process_exit() first sets the exit_code before updating the thread's
     * state to "dead". Once check_last_thread() indicates that the current thread is the last
     * thread, all the children will already have set thread->exit_code. Hence, this thread's
     * execution of try_process_exit() gets to determine the final exit_code, which is the desired
     * outcome. */
    while (check_last_thread(cur_thread)) {
        DkThreadYieldExecution();
    }

    debug("now exit the process\n");
    try_process_exit(error_code, 0);

#ifdef PROFILE
    if (ENTER_TIME)
        SAVE_PROFILE_INTERVAL_SINCE(syscall_exit_group, ENTER_TIME);
#endif

    DkThreadExit();
}

noreturn int shim_do_exit (int error_code)
{
    INC_PROFILE_OCCURENCE(syscall_use_ipc);
    struct shim_thread * cur_thread = get_cur_thread();
    __UNUSED(cur_thread);
    assert(!is_internal(cur_thread));

    if (debug_handle)
        sysparser_printf("---- shim_exit (returning %d)\n", error_code);

#ifndef ALIAS_VFORK_AS_FORK
    if (cur_thread->dummy) {
        cur_thread->term_signal = 0;
        thread_exit(cur_thread, true);
        switch_dummy_thread(cur_thread);
    }
#endif

    try_process_exit(error_code, 0);

#ifdef PROFILE
    if (ENTER_TIME)
        SAVE_PROFILE_INTERVAL_SINCE(syscall_exit, ENTER_TIME);
#endif

    DkThreadExit();
}
