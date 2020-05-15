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

#include <pal.h>
#include <pal_error.h>

#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_ipc.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_utils.h>

void release_robust_list (struct robust_list_head * head);

int thread_destroy(struct shim_thread* thread, bool send_ipc) {
    bool sent_exit_msg = false;

    /* Chia-Che: Broadcast exit message as early as possible,
       so other process can start early on responding. */
    if (thread->in_vm && send_ipc) {
        ipc_cld_exit_send(thread->ppid, thread->tid, thread->exit_code, thread->term_signal);
        sent_exit_msg = true;
    }

    lock(&thread->lock);

    if (!thread->is_alive || is_internal(thread)) {
        unlock(&thread->lock);
        return 0;
    }

    if (!thread->in_vm) {
        /* We need to mark remote threads as dead manually here. */
        thread->is_alive = false;
    }

    int exit_code = thread->exit_code;

    struct shim_handle_map * handle_map = thread->handle_map;
    struct shim_handle * exec = thread->exec;
    struct shim_thread * parent = thread->parent;
    thread->handle_map = NULL;
    thread->exec = NULL;

    if (parent) {
        assert(parent != thread);
        assert(parent->child_exit_event);
        debug("thread exits, notifying thread %d\n", parent->tid);

        lock(&parent->lock);
        LISTP_DEL_INIT(thread, &parent->children, siblings);
        LISTP_ADD_TAIL(thread, &parent->exited_children, siblings);

        if (!thread->in_vm) {
            debug("deliver SIGCHLD (thread = %d, exitval = %d)\n",
                  thread->tid, exit_code);

            siginfo_t info;
            memset(&info, 0, sizeof(siginfo_t));
            info.si_signo = SIGCHLD;
            info.si_pid   = thread->tid;
            info.si_uid   = thread->uid;
            info.si_status = (exit_code & 0xff) << 8;

            if (append_signal(parent, &info)) {
                thread_wakeup(thread);
                DkThreadResume(thread->pal_handle);
            }
        }
        unlock(&parent->lock);

        DkEventSet(parent->child_exit_event);
    } else if (!sent_exit_msg) {
        debug("parent not here, need to tell another process\n");
        ipc_cld_exit_send(thread->ppid, thread->tid, thread->exit_code, thread->term_signal);
    }

    struct robust_list_head* robust_list = thread->robust_list;
    thread->robust_list = NULL;

    unlock(&thread->lock);

    if (handle_map)
        put_handle_map(handle_map);

    if (exec)
        put_handle(exec);

    if (robust_list)
        release_robust_list(robust_list);

    DkEventSet(thread->exit_event);
    return 0;
}

static noreturn void libos_exit(int error_code, int term_signal) {
    struct shim_thread* async_thread = terminate_async_helper();
    if (async_thread) {
        /* TODO: wait for the thread to exit in host.
         * This is tracked by the following issue.
         * https://github.com/oscarlab/graphene/issues/440
         */
        put_thread(async_thread);
    }

    struct shim_thread* ipc_thread = terminate_ipc_helper();
    if (ipc_thread) {
        /* TODO: wait for the thread to exit in host.
         * This is tracked by the following issue.
         * https://github.com/oscarlab/graphene/issues/440
         */
        put_thread(ipc_thread);
    }

    shim_clean_and_exit(term_signal ? term_signal : error_code);
}

noreturn void thread_exit(int error_code, int term_signal) {
    struct shim_thread* cur_thread = get_cur_thread();

    cur_thread->exit_code = -error_code;
    cur_thread->term_signal = term_signal;

    thread_destroy(cur_thread, true);

    if (check_last_thread(cur_thread, /*mark_self_dead=*/true)) {
        /* ask Async Helper thread to cleanup this thread */
        cur_thread->clear_child_tid_pal = 1; /* any non-zero value suffices */
        int64_t ret = install_async_event(NULL, 0, &cleanup_thread, cur_thread);
        if (ret < 0) {
            debug("failed to set up async cleanup_thread (exiting without clear child tid),"
                  " return code: %ld\n", ret);
            DkThreadExit(NULL);
        }

        DkThreadExit(&cur_thread->clear_child_tid_pal);
    }

    libos_exit(error_code, term_signal);
}

static int mark_thread_to_die(struct shim_thread* thread, void* arg) {
    if (thread == (struct shim_thread*)arg) {
        return 0;
    }

    lock(&thread->lock);
    thread->time_to_die = true;
    unlock(&thread->lock);

    thread_wakeup(thread);
    DkThreadResume(thread->pal_handle);
    return 1;
}

noreturn void process_exit(int error_code, int term_signal) {
    struct shim_thread* cur_thread = get_cur_thread();

    /* If process_exit is invoked multiple times, only a single invocation proceeds past this
     * point. */
    static struct atomic_int first = ATOMIC_INIT(0);
    if (atomic_cmpxchg(&first, 0, 1) == 1) {
        /* Just exit current thread. */
        thread_exit(error_code, term_signal);
    }

    /* Tell other threads to exit. We can't do anything on failuers. */
    (void)walk_thread_list(mark_thread_to_die, cur_thread, /*one_shot=*/false);

    /* Wait for all other threads to exit. */
    while (check_last_thread(cur_thread, /*mark_self_dead=*/false)) {
        DkThreadYieldExecution();
    }

    /* Now quit our thread. Since we are the last one, this will exit the whole LibOS. */
    thread_exit(error_code, term_signal);
}

noreturn int shim_do_exit_group(int error_code) {
    assert(!is_internal(get_cur_thread()));

    if (debug_handle)
        sysparser_printf("---- shim_exit_group (returning %d)\n", error_code);

#ifndef ALIAS_VFORK_AS_FORK
    struct shim_thread* cur_thread = get_cur_thread();
    if (cur_thread->dummy) {
        cur_thread->term_signal = 0;
        thread_destroy(cur_thread, true);
        switch_dummy_thread(cur_thread);
    }
#endif

    debug("now exit the process\n");
    process_exit(error_code, 0);
}

noreturn int shim_do_exit(int error_code) {
    assert(!is_internal(get_cur_thread()));

    if (debug_handle)
        sysparser_printf("---- shim_exit (returning %d)\n", error_code);

#ifndef ALIAS_VFORK_AS_FORK
    struct shim_thread* cur_thread = get_cur_thread();
    if (cur_thread->dummy) {
        cur_thread->term_signal = 0;
        thread_destroy(cur_thread, true);
        switch_dummy_thread(cur_thread);
    }
#endif

    thread_exit(error_code, 0);
}
