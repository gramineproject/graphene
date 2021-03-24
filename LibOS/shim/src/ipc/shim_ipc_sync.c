/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * IPC glue code for the sync engine. These functions handle IPC_MSG_SYNC_* messages, but delegate
 * the actual logic to sync_server_* and sync_client_* functions.
 */

#include <assert.h>

#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_sync.h"

static const char* sync_state_names[SYNC_STATE_NUM] = {
    [SYNC_STATE_CLOSED]    = "closed",
    [SYNC_STATE_INVALID]   = "invalid",
    [SYNC_STATE_SHARED]    = "shared",
    [SYNC_STATE_EXCLUSIVE] = "exclusive",
};

static const char* sync_message_names[IPC_MSG_CODE_BOUND] = {
    [IPC_MSG_SYNC_REQUEST_UPGRADE]   = "REQUEST_UPGRADE",
    [IPC_MSG_SYNC_REQUEST_DOWNGRADE] = "REQUEST_DOWNGRADE",
    [IPC_MSG_SYNC_REQUEST_CLOSE]     = "REQUEST_CLOSE",
    [IPC_MSG_SYNC_CONFIRM_UPGRADE]   = "CONFIRM_UPGRADE",
    [IPC_MSG_SYNC_CONFIRM_DOWNGRADE] = "CONFIRM_DOWNGRADE",
    [IPC_MSG_SYNC_CONFIRM_CLOSE]     = "CONFIRM_CLOSE",
};

static inline void sync_log(const char* prefix, int code, uint64_t id, int state) {
    log_trace("%s: %s(0x%lx, %s)\n", prefix, sync_message_names[code], id, sync_state_names[state]);
}

static int sync_msg_send(struct shim_ipc_port* port, int code, uint64_t id, int state,
                         size_t data_size, void* data) {
    if (!port)
        port = g_process_ipc_info.ns->port;

    size_t total_msg_size = get_ipc_msg_size(sizeof(struct shim_ipc_sync_msg) + data_size);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, code, total_msg_size, port->vmid);

    struct shim_ipc_sync_msg* msgin = (void*)&msg->msg;
    msgin->id = id;
    msgin->state = state;
    msgin->data_size = data_size;
    if (data_size > 0)
        memcpy(&msgin->data, data, data_size);

    return send_ipc_message(msg, port);
}

int ipc_sync_client_send(int code, uint64_t id, int state, size_t data_size, void* data) {
    sync_log("sync client", code, id, state);
    return sync_msg_send(/*port=*/NULL, code, id, state, data_size, data);
}

int ipc_sync_server_send(struct shim_ipc_port* port, int code, uint64_t id, int state,
                         size_t data_size, void* data) {
    sync_log("sync server", code, id, state);
    return sync_msg_send(port, code, id, state, data_size, data);
}

int ipc_sync_client_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_sync_msg* msgin = (void*)&msg->msg;
    __UNUSED(port);

    sync_log("sync client callback", msg->code, msgin->id, msgin->state);
    sync_client_handle_message(msg->code, msgin->id, msgin->state, msgin->data_size,
                               &msgin->data);
    return 0;
}

int ipc_sync_server_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_sync_msg* msgin = (void*)&msg->msg;

    sync_log("sync server callback", msg->code, msgin->id, msgin->state);
    sync_server_handle_message(port, msg->code, msgin->id, msgin->state, msgin->data_size,
                               &msgin->data);
    return 0;
}
