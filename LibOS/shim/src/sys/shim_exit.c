/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Invisible Things Lab
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 * Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "pal.h"
#include "pal_error.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_signal.h"
#include "shim_table.h"
#include "shim_thread.h"
#include "shim_utils.h"

static noreturn void libos_clean_and_exit(int exit_code) {
    /*
     * TODO: if we are the IPC leader, we need to either:
     * 1) kill all other Graphene processes
     * 2) wait for them to exit here, before we terminate the IPC helper
     */

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

    del_all_ipc_ports();

    log_debug("process %u exited with status %d\n", g_process_ipc_info.vmid, exit_code);

    /* TODO: We exit whole libos, but there are some objects that might need cleanup, e.g. we should
     * release this (last) thread pid. We should do a proper cleanup of everything. */
    DkProcessExit(exit_code);
}

noreturn void thread_exit(int error_code, int term_signal) {
    /* Remove current thread from the threads list. */
    if (!check_last_thread(/*mark_self_dead=*/true)) {
        struct shim_thread* cur_thread = get_cur_thread();

        /* ask Async Helper thread to cleanup this thread */
        cur_thread->clear_child_tid_pal = 1; /* any non-zero value suffices */
        /* We pass this ownership to `cleanup_thread`. */
        get_thread(cur_thread);
        int64_t ret = install_async_event(NULL, 0, &cleanup_thread, cur_thread);

        /* Take the reference to the current thread from the tcb. */
        lock(&cur_thread->lock);
        assert(cur_thread->shim_tcb->tp == cur_thread);
        cur_thread->shim_tcb->tp = NULL;
        unlock(&cur_thread->lock);
        put_thread(cur_thread);

        if (ret < 0) {
            log_error("failed to set up async cleanup_thread (exiting without clear child tid),"
                      " return code: %ld\n", ret);
            /* `cleanup_thread` did not get this reference, clean it. We have to be careful, as
             * this is most likely the last reference and will free this `cur_thread`. */
            put_thread(cur_thread);
            DkThreadExit(NULL);
            /* UNREACHABLE */
        }

        DkThreadExit(&cur_thread->clear_child_tid_pal);
        /* UNREACHABLE */
    }

    /* This is the last thread of the process. Let parent know we exited. */
    int ret = ipc_cld_exit_send(error_code, term_signal);
    if (ret < 0) {
        log_error("Sending IPC process-exit notification failed: %d\n", ret);
    }

    /* At this point other threads might be still in the middle of an exit routine, but we don't
     * care since the below will call `exit_group` eventually. */
    libos_clean_and_exit(term_signal ? 128 + (term_signal & ~__WCOREDUMP_BIT) : error_code);
}

static int mark_thread_to_die(struct shim_thread* thread, void* arg) {
    if (thread == (struct shim_thread*)arg) {
        return 0;
    }

    bool need_wakeup = !__atomic_exchange_n(&thread->time_to_die, true, __ATOMIC_ACQ_REL);

    /* Now let's kick `thread`, so that it notices (in `handle_signal`) the flag `time_to_die`
     * set above (but only if we really set that flag). */
    if (need_wakeup) {
        thread_wakeup(thread);
        (void)DkThreadResume(thread->pal_handle); // There is nothing we can do on errors.
    }
    return 1;
}

bool kill_other_threads(void) {
    bool killed = false;
    /* Tell other threads to exit. Since `mark_thread_to_die` never returns an error, this call
     * cannot fail. */
    if (walk_thread_list(mark_thread_to_die, get_cur_thread(), /*one_shot=*/false) != -ESRCH) {
        killed = true;
    }
    DkThreadYieldExecution();

    /* Wait for all other threads to exit. */
    while (!check_last_thread(/*mark_self_dead=*/false)) {
        /* Tell other threads to exit again - the previous announcement could have been missed by
         * threads that were just being created. */
        if (walk_thread_list(mark_thread_to_die, get_cur_thread(), /*one_shot=*/false) != -ESRCH) {
            killed = true;
        }
        DkThreadYieldExecution();
    }

    return killed;
}

noreturn void process_exit(int error_code, int term_signal) {
    assert(!is_internal(get_cur_thread()));

    /* If process_exit is invoked multiple times, only a single invocation proceeds past this
     * point. */
    static int first = 0;
    if (__atomic_exchange_n(&first, 1, __ATOMIC_RELAXED) != 0) {
        /* Just exit current thread. */
        thread_exit(error_code, term_signal);
    }

    (void)kill_other_threads();

    /* Now quit our thread. Since we are the last one, this will exit the whole LibOS. */
    thread_exit(error_code, term_signal);
}

long shim_do_exit_group(int error_code) {
    assert(!is_internal(get_cur_thread()));

    error_code &= 0xFF;

    log_debug("---- shim_exit_group (returning %d)\n", error_code);

    process_exit(error_code, 0);
}

long shim_do_exit(int error_code) {
    assert(!is_internal(get_cur_thread()));

    error_code &= 0xFF;

    log_debug("---- shim_exit (returning %d)\n", error_code);

    thread_exit(error_code, 0);
}
