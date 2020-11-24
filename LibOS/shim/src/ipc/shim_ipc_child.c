/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * This file contains functions and callbacks to handle IPC between parent processes and their
 * children.
 */

#include "api.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_process.h"

/* IPC helper thread invokes this fini function when main IPC port for communication with child
 * process is disconnected/removed by host OS.
 */
void ipc_port_with_child_fini(struct shim_ipc_port* port, IDTYPE vmid) {
    __UNUSED(port);

    /* Message cannot come from our own process. */
    assert(vmid != g_process_ipc_info.vmid);

    /*
     * NOTE: IPC port may be closed by the host OS because the child process exited on the host OS
     * (and so the host OS closed all its sockets). This may happen before arrival of the expected
     * IPC_MSG_CHILDEXIT message from child process. In such case report that the child process was
     * killed by SIGKILL.
     */
    if (mark_child_exited_by_vmid(vmid, /*uid=*/0, /*exit_code=*/0, SIGKILL)) {
        debug("Child process (vmid: 0x%x) got disconnected\n", vmid);
    } else {
        debug("Unknown process (vmid: 0x%x) disconnected\n", vmid);
    }
}

int ipc_cld_exit_send(unsigned int exitcode, unsigned int term_signal) {
    if (!g_process.ppid) {
        /* We have no parent inside Graphene, so no one to notify. */
        return 0;
    }

    IDTYPE dest;
    struct shim_ipc_port* port = NULL;
    int ret = connect_owner(g_process.ppid, &port, &dest);
    if (ret < 0) {
        return ret;
    }

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

    ret = send_ipc_message(msg, port);
    put_ipc_port(port);
    return ret;
}

/*
 * IPC helper thread invokes this callback on an IPC_MSG_CHILDEXIT message received from the exiting
 * child process with vmid msg->src. The exiting child process informs about its exit code in
 * msgin->exit_code and its terminating signal in msgin->term_signal.
 */
int ipc_cld_exit_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    __UNUSED(port);
    struct shim_ipc_cld_exit* msgin = (struct shim_ipc_cld_exit*)&msg->msg;

    debug("IPC callback from %u: IPC_MSG_CHILDEXIT(%u, %u, %d, %u)\n", msg->src,
          msgin->ppid, msgin->pid, msgin->exitcode, msgin->term_signal);

    /* Message cannot come from our own process. */
    assert(msg->src != g_process_ipc_info.vmid);

    if (mark_child_exited_by_pid(msgin->pid, msgin->uid, msgin->exitcode, msgin->term_signal)) {
        debug("Child process (pid: %u) died\n", msgin->pid);
    } else {
        debug("Unknown process died, pid: %d\n", msgin->pid);
    }

    return 0;
}
