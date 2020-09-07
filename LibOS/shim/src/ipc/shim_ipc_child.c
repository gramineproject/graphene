/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * shim_ipc_child.c
 *
 * This file contains functions and callbacks to handle IPC between parent
 * processes and their children.
 */

#include <errno.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_thread.h"
#include "shim_utils.h"

struct thread_info {
    IDTYPE vmid;
    unsigned int exitcode;
    unsigned int term_signal;
};

/* walk_thread_list callback; exit each thread of child process vmid. */
static int child_thread_exit(struct shim_thread* thread, void* arg) {
    struct thread_info* info = (struct thread_info*)arg;
    int found_exiting_thread = 0;

    lock(&thread->lock);
    if (thread->vmid == info->vmid) {
        found_exiting_thread = 1;

        if (thread->is_alive) {
            thread->exit_code   = -info->exitcode;
            thread->term_signal = info->term_signal;
            unlock(&thread->lock);

            /* remote thread is "virtually" exited: SIGCHLD is generated for
             * the parent thread and exit events are arranged for subsequent
             * wait4(). */
            thread_destroy(thread, /*send_ipc=*/false);
            goto out;
        }
    }
    unlock(&thread->lock);

out:
    return found_exiting_thread;
}

/* IPC helper thread invokes this fini function when main IPC port for communication with child
 * process is disconnected/removed by host OS.
 *
 * Similarly to benign case of receiving an explicit IPC_MSG_CHILDEXIT message from exiting remote
 * thread (see ipc_cld_exit_callback()), we want to delete all remote threads associated with
 * disconnected child process.
 */
void ipc_port_with_child_fini(struct shim_ipc_port* port, IDTYPE vmid, unsigned int exitcode) {
    __UNUSED(port);

    /* NOTE: IPC port may be closed by host OS because the child process exited on host OS (and so
     *       host OS closed all its sockets).  This may happen before arrival of the "expected"
     *       IPC_MSG_CHILDEXIT message from child process. Ideally, we would inspect whether we
     *       previously sent SIGINT/SIGTERM/SIGKILL to this child and use the corresponding
     *       termination signal. For now, report that child process was killed by SIGKILL. */
    struct thread_info info = {.vmid = vmid, .exitcode = exitcode, .term_signal = SIGKILL};

    /* message cannot come from our own threads (from ourselves as process) */
    assert(vmid != cur_process.vmid);

    int ret;
    int exited_threads_cnt = 0;

    if ((ret = walk_thread_list(&child_thread_exit, &info, /*one_shot=*/false)) > 0)
        exited_threads_cnt += ret;

    debug(
        "Child process %u got disconnected: assuming that child exited and "
        "forcing %d of its threads to exit\n",
        vmid & 0xFFFF, exited_threads_cnt);
}

/* The exiting thread of this process calls this function to broadcast IPC_MSG_CHILDEXIT
 * notification to its parent process (technically, to all processes of type DIRECTPARENT or
 * DIRECTCHILD but the only interesting case is the notification of parent). */
int ipc_cld_exit_send(IDTYPE ppid, IDTYPE tid, unsigned int exitcode, unsigned int term_signal) {
    size_t total_msg_size    = get_ipc_msg_size(sizeof(struct shim_ipc_cld_exit));
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_CHILDEXIT, total_msg_size, 0);

    struct shim_ipc_cld_exit* msgin = (struct shim_ipc_cld_exit*)&msg->msg;
    msgin->ppid                     = ppid;
    msgin->tid                      = tid;
    msgin->exitcode                 = exitcode;
    msgin->term_signal              = term_signal;

    debug("IPC broadcast: IPC_MSG_CHILDEXIT(%u, %u, %d, %u)\n", ppid, tid, exitcode, term_signal);

    int ret = broadcast_ipc(msg, IPC_PORT_DIRECTPARENT | IPC_PORT_DIRECTCHILD,
                            /*exclude_port=*/NULL);
    return ret;
}

/* IPC helper thread invokes this callback on an IPC_MSG_CHILDEXIT message received from a specific
 * thread msgin->tid of the exiting child process with vmid msg->src. The thread of the exiting
 * child process informs about its exit code in msgin->exit_code and its terminating signal in
 * msgin->term_signal.
 *
 * The callback finds this remote thread of the child process among our process's threads/simple
 * threads (recall that parent process maintains remote child threads in its thread list, marking
 * them as in_vm == false).  The remote thread is "virtually" exited: SIGCHLD is generated for the
 * parent thread and exit events are arranged for subsequent wait4().
 */
int ipc_cld_exit_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    __UNUSED(port);
    int ret = 0;

    struct shim_ipc_cld_exit* msgin = (struct shim_ipc_cld_exit*)&msg->msg;

    debug("IPC callback from %u: IPC_MSG_CHILDEXIT(%u, %u, %d, %u)\n", msg->src & 0xFFFF,
          msgin->ppid, msgin->tid, msgin->exitcode, msgin->term_signal);

    /* message cannot come from our own threads (from ourselves as process) */
    assert(msg->src != cur_process.vmid);

    /* First try to find remote thread which sent this message among normal
     * threads. In the common case, we (as parent process) keep remote child
     * threads in the thread list. But sometimes the message can arrive twice
     * or very late, such that the corresponding remote thread was already
     * exited and deleted; in such cases, we fall back to simple threads. */
    struct shim_thread* thread = lookup_thread(msgin->tid);
    if (thread) {
        lock(&thread->lock);
        thread->exit_code   = -msgin->exitcode;
        thread->term_signal = msgin->term_signal;
        unlock(&thread->lock);

        /* Remote thread is "virtually" exited: SIGCHLD is generated for the
         * parent thread and exit events are arranged for subsequent wait4(). */
        ret = thread_destroy(thread, /*send_ipc=*/false);
        put_thread(thread);
    } else {
        /* Uncommon case: remote child thread was already exited and deleted
         * (probably because the same message was already received earlier).
         * We can simply do nothing here and ignore this message. */
    }

    return ret;
}
