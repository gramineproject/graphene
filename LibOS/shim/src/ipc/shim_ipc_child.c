/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 * Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "api.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_process.h"

void ipc_child_disconnect_callback(IDTYPE vmid) {
    /*
     * NOTE: IPC port may be closed by the host OS because the child process exited on the host OS
     * (and so the host OS closed all its sockets). This may happen before arrival of the expected
     * IPC_MSG_CHILDEXIT message from child process. In such case report that the child process was
     * killed by SIGPWR (we've picked this signal hoping that nothing really uses it, as this case
     * is not distinguishable from a genuine signal).
     */
    if (mark_child_exited_by_vmid(vmid, /*uid=*/0, /*exit_code=*/0, SIGPWR)) {
        log_debug("Child process (vmid: 0x%x) got disconnected\n", vmid);
    } else {
        log_debug("Unknown process (vmid: 0x%x) disconnected\n", vmid);
    }
}

int ipc_cld_exit_send(unsigned int exitcode, unsigned int term_signal) {
    if (!g_process.ppid) {
        /* We have no parent inside Graphene, so no one to notify. */
        return 0;
    }

    IDTYPE dest = g_process_ipc_ids.parent_vmid;

    size_t total_msg_size = get_ipc_msg_size(sizeof(struct shim_ipc_cld_exit));
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_CHILDEXIT, total_msg_size, dest);

    struct shim_thread* self = get_cur_thread();
    lock(&self->lock);
    IDTYPE uid = self->uid;
    unlock(&self->lock);

    struct shim_ipc_cld_exit* msgin = (struct shim_ipc_cld_exit*)&msg->msg;
    msgin->ppid                     = g_process.ppid;
    msgin->pid                      = g_process.pid;
    msgin->exitcode                 = exitcode;
    msgin->term_signal              = term_signal;
    msgin->uid                      = uid;

    return send_ipc_message(msg, dest);
}

int ipc_cld_exit_callback(struct shim_ipc_msg* msg, IDTYPE src) {
    struct shim_ipc_cld_exit* msgin = (struct shim_ipc_cld_exit*)&msg->msg;

    log_debug("IPC callback from %u: IPC_MSG_CHILDEXIT(%u, %u, %d, %u)\n", msg->src,
          msgin->ppid, msgin->pid, msgin->exitcode, msgin->term_signal);

    assert(src == msg->src);

    if (mark_child_exited_by_pid(msgin->pid, msgin->uid, msgin->exitcode, msgin->term_signal)) {
        log_debug("Child process (pid: %u) died\n", msgin->pid);
    } else {
        log_error("Unknown process sent a child-death notification: pid: %d, vmid: %u\n",
                  msgin->pid, src);
    }

    return 0;
}
