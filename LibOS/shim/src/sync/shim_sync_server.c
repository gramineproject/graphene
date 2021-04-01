/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Server part of the sync engine.
 *
 * TODO (performance): All the server work is protected by a global lock, and happens in one thread
 * (IPC helper). With high volume of requests, this might be a performance bottleneck.
 */

#include "pal.h"
#include "shim_ipc.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_sync.h"
#include "shim_thread.h"

#define FATAL(fmt...)                                   \
    do {                                                \
        log_error("Fatal error in sync server: " fmt);  \
        DkProcessExit(1);                               \
    } while(0)


DEFINE_LIST(server_handle_client);
DEFINE_LISTP(server_handle_client);
struct server_handle_client {
    /* Client port */
    struct shim_ipc_port* port;

    /* Current state (INVALID, SHARED or EXCLUSIVE); higher or equal to client's cur_state */
    int cur_state;
    /* Requested by client; always higher than cur_state, or NONE */
    int client_req_state;
    /* Requested by server; always lower than cur_state, or NONE */
    int server_req_state;

    LIST_TYPE(server_handle_client) list;
};

struct server_handle {
    uint64_t id;
    size_t data_size;
    void* data;

    LISTP_TYPE(server_handle_client) clients;

    UT_hash_handle hh;
};

static struct server_handle *g_server_handles = NULL;
static struct shim_lock g_server_lock;

int init_sync_server(void) {
    if (!create_lock(&g_server_lock))
        return -ENOMEM;
    return 0;
}

static struct server_handle* find_handle(uint64_t id, bool create) {
    struct server_handle* handle = NULL;
    HASH_FIND(hh, g_server_handles, &id, sizeof(id), handle);
    if (!handle && create) {
        if (!(handle = malloc(sizeof(*handle))))
            return NULL;

        handle->id = id;
        handle->data_size = 0;
        handle->data = NULL;
        INIT_LISTP(&handle->clients);
        HASH_ADD(hh, g_server_handles, id, sizeof(id), handle);
    }

    return handle;
}

static struct server_handle_client* find_handle_client(struct server_handle* handle,
                                                       struct shim_ipc_port* port,
                                                       bool create) {
    struct server_handle_client* client;
    LISTP_FOR_EACH_ENTRY(client, &handle->clients, list) {
        if (client->port == port)
            return client;
    }

    if (!create)
        return NULL;

    if (!(client = malloc(sizeof(*client))))
        return NULL;

    get_ipc_port(port);
    port->num_sync_handles++;

    client->port = port;
    client->cur_state = SYNC_STATE_INVALID;
    client->client_req_state = SYNC_STATE_NONE;
    client->server_req_state = SYNC_STATE_NONE;

    LISTP_ADD_TAIL(client, &handle->clients, list);

    return client;
}

static inline int send_confirm_upgrade(struct server_handle* handle,
                                       struct server_handle_client* client, int state) {
    return ipc_sync_server_send(client->port, IPC_MSG_SYNC_CONFIRM_UPGRADE, handle->id,
                                state, handle->data_size, handle->data);
}

static inline int send_request_downgrade(struct server_handle* handle,
                                         struct server_handle_client* client, int state) {
    return ipc_sync_server_send(client->port, IPC_MSG_SYNC_REQUEST_DOWNGRADE, handle->id,
                                state, /*data_size=*/0, /*data=*/NULL);
}

static inline int send_confirm_close(struct server_handle* handle,
                                     struct server_handle_client* client) {
    return ipc_sync_server_send(client->port, IPC_MSG_SYNC_CONFIRM_CLOSE, handle->id,
                                /*state=*/SYNC_STATE_CLOSED, /*data_size=*/0, /*data=*/NULL);
}

/* Process handle information after state change */
static int process_handle(struct server_handle* handle) {
    unsigned int n_shared = 0, n_exclusive = 0;
    unsigned int want_shared = 0, want_exclusive = 0;
    struct server_handle_client* client;
    int ret;

    LISTP_FOR_EACH_ENTRY(client, &handle->clients, list) {
        if (client->cur_state == SYNC_STATE_SHARED)
            n_shared++;
        if (client->cur_state == SYNC_STATE_EXCLUSIVE)
            n_exclusive++;
        if (client->client_req_state == SYNC_STATE_SHARED)
            want_shared++;
        if (client->client_req_state == SYNC_STATE_EXCLUSIVE)
            want_exclusive++;
    }

    /* Fulfill upgrade requests, if possible right now */

    LISTP_FOR_EACH_ENTRY(client, &handle->clients, list) {
        if (client->client_req_state == SYNC_STATE_SHARED && n_exclusive == 0) {
            /* Upgrade from INVALID to SHARED */
            assert(client->cur_state == SYNC_STATE_INVALID);
            if ((ret = send_confirm_upgrade(handle, client, SYNC_STATE_SHARED)) < 0)
                return ret;

            client->cur_state = SYNC_STATE_SHARED;
            client->client_req_state = SYNC_STATE_NONE;
            want_shared--;
            n_shared++;
        } else if (client->client_req_state == SYNC_STATE_EXCLUSIVE && n_exclusive == 0
                   && n_shared == 0) {
            /* Upgrade from INVALID to EXCLUSIVE */
            assert(client->cur_state == SYNC_STATE_INVALID);
            if ((ret = send_confirm_upgrade(handle, client, SYNC_STATE_EXCLUSIVE)) < 0)
                return ret;

            client->cur_state = SYNC_STATE_EXCLUSIVE;
            client->client_req_state = SYNC_STATE_NONE;
            want_exclusive--;
            n_exclusive++;
        } else if (client->client_req_state == SYNC_STATE_EXCLUSIVE && n_exclusive == 0
                   && n_shared == 1 && client->cur_state == SYNC_STATE_SHARED) {
            /* Upgrade from SHARED to EXCLUSIVE */
            if ((ret = send_confirm_upgrade(handle, client, SYNC_STATE_EXCLUSIVE)) < 0)
                return ret;

            client->cur_state = SYNC_STATE_EXCLUSIVE;
            client->client_req_state = SYNC_STATE_NONE;
            want_exclusive--;
            n_exclusive++;
            n_shared--;
        }
    }

    /* Issue downgrade requests, if necessary */

    if (want_exclusive) {
        /* Some clients wait for EXCLUSIVE, try to downgrade SHARED/EXCLUSIVE to INVALID */
        LISTP_FOR_EACH_ENTRY(client, &handle->clients, list) {
            if ((client->cur_state == SYNC_STATE_SHARED || client->cur_state == SYNC_STATE_EXCLUSIVE)
                    && client->server_req_state != SYNC_STATE_INVALID) {
                if ((ret = send_request_downgrade(handle, client, SYNC_STATE_INVALID)) < 0)
                    return ret;
                client->server_req_state = SYNC_STATE_INVALID;
            }
        }
    }
    else if (want_shared) {
        /* Some clients wait for SHARED, try to downgrade EXCLUSIVE to SHARED */
        LISTP_FOR_EACH_ENTRY(client, &handle->clients, list) {
            if (client->cur_state == SYNC_STATE_EXCLUSIVE && client->server_req_state != SYNC_STATE_SHARED
                    && client->server_req_state != SYNC_STATE_INVALID) {
                if ((ret = send_request_downgrade(handle, client, SYNC_STATE_SHARED)) < 0)
                    return ret;
                client->server_req_state = SYNC_STATE_SHARED;
            }
        }
    }

    return 0;
}

static void do_request_upgrade(struct shim_ipc_port* port, uint64_t id, int state) {
    assert(state == SYNC_STATE_SHARED || state == SYNC_STATE_EXCLUSIVE);

    lock(&g_server_lock);

    struct server_handle* handle;
    if (!(handle = find_handle(id, /*create=*/true)))
        FATAL("Cannot create a new handle\n");

    struct server_handle_client* client;
    if ((!(client = find_handle_client(handle, port, /*create=*/true))))
        FATAL("Cannot create a new handle client\n");

    if (client->cur_state < state) {
        client->cur_state = SYNC_STATE_INVALID;
        client->client_req_state = state;

        /* Move the client to the end of the list, so that new requests are handled in FIFO
         * order. */
        if (LISTP_NEXT_ENTRY(client, &handle->clients, list) != NULL) {
            LISTP_DEL(client, &handle->clients, list);
            LISTP_ADD_TAIL(client, &handle->clients, list);
        }

        int ret;
        if ((ret = process_handle(handle)) < 0)
            FATAL("Error messaging clients: %d\n", ret);
    }

    unlock(&g_server_lock);
}

static void update_handle_data(struct server_handle* handle, size_t data_size, void* data) {
    if (data_size != handle->data_size) {
        free(handle->data);
        handle->data = NULL;
        handle->data_size = data_size;
        if (handle->data_size > 0) {
            if (!(handle->data = malloc(handle->data_size)))
                FATAL("Cannot allocate data for handle\n");
        }
    }
    if (data_size > 0)
        memcpy(handle->data, data, data_size);
}

static void do_confirm_downgrade(struct shim_ipc_port* port, uint64_t id, int state,
                                     size_t data_size, void* data) {
    assert(state == SYNC_STATE_INVALID || state == SYNC_STATE_SHARED);

    lock(&g_server_lock);

    struct server_handle* handle;
    if (!(handle = find_handle(id, /*create=*/true)))
        FATAL("Cannot create a new handle\n");

    struct server_handle_client* client;
    if ((!(client = find_handle_client(handle, port, /*create=*/true))))
        FATAL("Cannot create a new handle client\n");

    client->cur_state = state;
    if (state <= client->server_req_state)
        client->server_req_state = SYNC_STATE_NONE;

    update_handle_data(handle, data_size, data);

    int ret;
    if ((ret = process_handle(handle)) < 0)
        FATAL("Error messaging clients: %d\n", ret);

    unlock(&g_server_lock);
}

static void do_request_close(struct shim_ipc_port* port, uint64_t id, int cur_state,
                                 size_t data_size, void* data) {
    assert(cur_state == SYNC_STATE_INVALID || cur_state == SYNC_STATE_SHARED
           || cur_state == SYNC_STATE_EXCLUSIVE);
    lock(&g_server_lock);

    struct server_handle* handle;
    if (!(handle = find_handle(id, /*create=*/false)))
        FATAL("REQUEST_CLOSE for unknown handle\n");

    struct server_handle_client* client;
    if ((!(client = find_handle_client(handle, port, /*create=*/false))))
        FATAL("REQUEST_CLOSE for unknown client\n");

    if (cur_state == SYNC_STATE_EXCLUSIVE) {
        update_handle_data(handle, data_size, data);
    }

    if (send_confirm_close(handle, client) < 0)
        FATAL("sending CONFIRM_CLOSE");

    LISTP_DEL(client, &handle->clients, list);

    assert(client->port->num_sync_handles > 0);
    client->port->num_sync_handles--;
    put_ipc_port(client->port);

    free(client);

    if (LISTP_EMPTY(&handle->clients)) {
        log_trace("sync server: deleting unused handle: 0x%lx\n", id);
        HASH_DELETE(hh, g_server_handles, handle);
    } else {
        int ret;
        if ((ret = process_handle(handle)) < 0)
            FATAL("Error messaging clients: %d\n", ret);
    }

    unlock(&g_server_lock);
}


void sync_server_message_callback(struct shim_ipc_port* port, int code, uint64_t id, int state,
                                  size_t data_size, void* data) {
    switch (code) {
        case IPC_MSG_SYNC_REQUEST_UPGRADE:
            assert(data_size == 0);
            do_request_upgrade(port, id, state);
            break;
        case IPC_MSG_SYNC_CONFIRM_DOWNGRADE:
            do_confirm_downgrade(port, id, state, data_size, data);
            break;
        case IPC_MSG_SYNC_REQUEST_CLOSE:
            do_request_close(port, id, state, data_size, data);
            break;
        default:
            FATAL("unknown message: %d\n", code);
    }
}

/*
 * Check on client disconnect if all handles of that client have been closed.
 *
 * In principle, we could try to clean up after a client exiting. However, a disconnect without
 * cleanup probably means unclean Graphene exit (host SIGKILL, or fatal error), and in the case of
 * EXCLUSIVE handles, continuing will result in data loss.
 */
void sync_server_disconnect_callback(struct shim_ipc_port* port) {
    if (!lock_created(&g_server_lock))
        return;

    lock(&g_server_lock);

    if (port->num_sync_handles > 0) {
        FATAL("Port %p disconnected without closing handles\n", port);
    }

    unlock(&g_server_lock);
}
