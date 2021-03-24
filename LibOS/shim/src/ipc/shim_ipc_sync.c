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
    "none",
    "invalid",
    "shared",
    "exclusive",
};

static int sync_request_send(struct shim_ipc_port* port, int code, uint64_t id, int state) {
    if (!port)
        port = g_process_ipc_info.ns->port;

    size_t total_msg_size = get_ipc_msg_size(sizeof(struct shim_ipc_sync_request));
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, code, total_msg_size, port->vmid);

    struct shim_ipc_sync_request* msgin = (void*)&msg->msg;
    msgin->id = id;
    msgin->state = state;

    return send_ipc_message(msg, port);
}

static int sync_response_send(struct shim_ipc_port* port, int code, uint64_t id, int state,
                               size_t data_size, void* data) {
    if (!port)
        port = g_process_ipc_info.ns->port;

    size_t total_msg_size = get_ipc_msg_size(sizeof(struct shim_ipc_sync_response) + data_size);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, code, total_msg_size, port->vmid);

    struct shim_ipc_sync_response* msgin = (void*)&msg->msg;
    msgin->id = id;
    msgin->state = state;
    msgin->data_size = data_size;
    memcpy(&msgin->data, data, data_size);

    return send_ipc_message(msg, port);
}

int ipc_sync_request_upgrade_send(uint64_t id, int state) {
    log_trace("sync client: sending REQUEST_UPGRADE(0x%lx, %s)\n", id, sync_state_names[state]);

    return sync_request_send(NULL, IPC_MSG_SYNC_REQUEST_UPGRADE, id, state);
}

int ipc_sync_request_downgrade_send(struct shim_ipc_port* port, uint64_t id, int state) {
    log_trace("sync server: sending REQUEST_DOWNGRADE(0x%lx, %s)\n", id, sync_state_names[state]);

    return sync_request_send(port, IPC_MSG_SYNC_REQUEST_DOWNGRADE, id, state);
}

int ipc_sync_upgrade_send(struct shim_ipc_port* port, uint64_t id, int state, size_t data_size,
                          void* data) {
    log_trace("sync server: sending UPGRADE(0x%lx, %s)\n", id, sync_state_names[state]);

    return sync_response_send(port, IPC_MSG_SYNC_UPGRADE, id, state, data_size, data);
}

int ipc_sync_downgrade_send(uint64_t id, int state, size_t data_size, void* data) {
    log_trace("sync client: sending DOWNGRADE(0x%lx, %s)\n", id, sync_state_names[state]);

    return sync_response_send(NULL, IPC_MSG_SYNC_DOWNGRADE, id, state, data_size, data);
}

int ipc_sync_request_upgrade_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_sync_request* msgin = (void*)&msg->msg;

    log_trace("sync server: received REQUEST_UPGRADE(0x%lx, %s)\n", msgin->id,
              sync_state_names[msgin->state]);
    return sync_server_handle_request_upgrade(port, msgin->id, msgin->state);
}

int ipc_sync_request_downgrade_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_sync_request* msgin = (void*)&msg->msg;
    __UNUSED(port);

    log_trace("sync client: received REQUEST_DOWNGRADE(0x%lx, %s)\n", msgin->id,
              sync_state_names[msgin->state]);
    return sync_client_handle_request_downgrade(msgin->id, msgin->state);
}

int ipc_sync_upgrade_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_sync_response* msgin = (void*)&msg->msg;
    __UNUSED(port);

    log_trace("sync client: received UPGRADE(0x%lx, %s)\n", msgin->id,
              sync_state_names[msgin->state]);
    return sync_client_handle_upgrade(msgin->id, msgin->state, msgin->data_size, &msgin->data);
}

int ipc_sync_downgrade_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_sync_response* msgin = (void*)&msg->msg;

    log_trace("sync server: received DOWNGRADE(0x%lx, %s)\n", msgin->id,
              sync_state_names[msgin->state]);
    return sync_server_handle_downgrade(port, msgin->id, msgin->state, msgin->data_size,
                                        &msgin->data);
}
