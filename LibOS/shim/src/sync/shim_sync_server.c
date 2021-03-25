/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Server part of the sync engine.
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
    /* Client port (or NULL if same process, i.e. process leader). */
    struct shim_ipc_port* port;

    /* Current state (INVALID, SHARED or EXCLUSIVE); higher or equal to client's cur_state */
    int cur_state;
    /* Requested by client; always higher than cur_state, or NONE */
    int up_state;
    /* Requested by server; always lower than cur_state, or NONE */
    int down_state;

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

static struct server_handle* find_handle(uint64_t id) {
    struct server_handle* handle = NULL;
    HASH_FIND(hh, g_server_handles, &id, sizeof(id), handle);
    if (!handle) {
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
                                                   struct shim_ipc_port* port) {
    struct server_handle_client* client;
    LISTP_FOR_EACH_ENTRY(client, &handle->clients, list) {
        if (client->port == port)
            return client;
    }
    if (!(client = malloc(sizeof(*client))))
        return NULL;

    client->port = port;
    client->cur_state = SYNC_STATE_INVALID;
    client->up_state = SYNC_STATE_NONE;
    client->down_state = SYNC_STATE_NONE;

    LISTP_ADD_TAIL(client, &handle->clients, list);
    return client;
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
        if (client->up_state == SYNC_STATE_SHARED)
            want_shared++;
        if (client->up_state == SYNC_STATE_EXCLUSIVE)
            want_exclusive++;
    }

    /* Fulfill upgrade requests, if possible right now */

    LISTP_FOR_EACH_ENTRY(client, &handle->clients, list) {
        if (client->up_state == SYNC_STATE_SHARED && n_exclusive == 0) {
            /* Upgrade from INVALID to SHARED */
            assert(client->cur_state == SYNC_STATE_INVALID);
            if ((ret = ipc_sync_upgrade_send(client->port, handle->id, SYNC_STATE_SHARED,
                                             handle->data_size, handle->data)) < 0)
                return ret;

            client->cur_state = SYNC_STATE_SHARED;
            client->up_state = SYNC_STATE_NONE;
            want_shared--;
            n_shared++;
        } else if (client->up_state == SYNC_STATE_EXCLUSIVE && n_exclusive == 0 && n_shared == 0) {
            /* Upgrade from INVALID to EXCLUSIVE */
            assert(client->cur_state == SYNC_STATE_INVALID);
            if ((ret = ipc_sync_upgrade_send(client->port, handle->id, SYNC_STATE_EXCLUSIVE,
                                             handle->data_size, handle->data)) < 0)
                return ret;

            client->cur_state = SYNC_STATE_EXCLUSIVE;
            client->up_state = SYNC_STATE_NONE;
            want_exclusive--;
            n_exclusive++;
        } else if (client->up_state == SYNC_STATE_EXCLUSIVE && n_exclusive == 0 && n_shared == 1
                   && client->cur_state == SYNC_STATE_SHARED) {
            /* Upgrade from SHARED to EXCLUSIVE */
            if ((ret = ipc_sync_upgrade_send(client->port, handle->id, SYNC_STATE_EXCLUSIVE,
                                             handle->data_size, handle->data) < 0))
                return ret;

            client->cur_state = SYNC_STATE_EXCLUSIVE;
            client->up_state = SYNC_STATE_NONE;
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
                    && client->down_state != SYNC_STATE_INVALID) {
                if ((ret = ipc_sync_request_downgrade_send(client->port, handle->id,
                                                           SYNC_STATE_INVALID)) < 0)
                    return ret;
                client->down_state = SYNC_STATE_INVALID;
            }
        }
    }
    else if (want_shared) {
        /* Some clients wait for SHARED, try to downgrade EXCLUSIVE to SHARED */
        LISTP_FOR_EACH_ENTRY(client, &handle->clients, list) {
            if (client->cur_state == SYNC_STATE_EXCLUSIVE && client->down_state != SYNC_STATE_SHARED
                    && client->down_state != SYNC_STATE_INVALID) {
                if ((ret = ipc_sync_request_downgrade_send(client->port, handle->id,
                                                           SYNC_STATE_SHARED)) < 0)
                    return ret;
                client->down_state = SYNC_STATE_SHARED;
            }
        }
    }

    return 0;
}

int sync_server_handle_request_upgrade(struct shim_ipc_port* port, uint64_t id, int state) {
    assert(state == SYNC_STATE_SHARED || state == SYNC_STATE_EXCLUSIVE);

    lock(&g_server_lock);

    struct server_handle* handle;
    if (!(handle = find_handle(id)))
        FATAL("Cannot create a new handle\n");

    struct server_handle_client* client;
    if ((!(client = find_handle_client(handle, port))))
        FATAL("Cannot create a new handle client\n");

    if (client->cur_state < state) {
        client->cur_state = SYNC_STATE_INVALID;
        client->up_state = state;

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
    return 0;
}

int sync_server_handle_downgrade(struct shim_ipc_port* port, uint64_t id, int state,
                                 size_t data_size, void* data) {
    assert(state == SYNC_STATE_INVALID || state == SYNC_STATE_SHARED);

    lock(&g_server_lock);

    struct server_handle* handle;
    if (!(handle = find_handle(id)))
        FATAL("Cannot create a new handle\n");

    struct server_handle_client* client;
    if ((!(client = find_handle_client(handle, port))))
        FATAL("Cannot create a new handle client\n");

    client->cur_state = state;
    if (state <= client->down_state)
        client->down_state = SYNC_STATE_NONE;

    /* Update handle data */
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

    int ret;
    if ((ret = process_handle(handle)) < 0)
        FATAL("Error messaging clients: %d\n", ret);

    unlock(&g_server_lock);
    return 0;
}
