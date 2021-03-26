/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Sync engine. The engine allows you to create *sync handles* with a global ID, and associated
 * data.
 *
 * A handle has to be locked before using, in one of two modes:
 *
 * - SYNC_STATE_SHARED: many processes can have a copy of the handle
 * - SYNC_STATE_EXCLUSIVE: only one process can have a copy of the handle, but the data stored
 *   with the handle can be updated
 *
 * When the handle is not locked, it can be downgraded to INVALID by the remote server. However,
 * this will only happen when another process needs to modify the same resource, and locks its own
 * handle in EXCLUSIVE mode (which means that data held by other processes are about to become
 * invalid). Therefore, as long as the handle is uncontested, there is not communication overhead
 * for using it.
 *
 * Example usage:
 *
 *     struct obj {
 *         int field_one;
 *         long field_two;
 *         struct sync_handle sync;
 *     };
 *     struct obj obj = {0};
 *
 *     struct obj_sync_data {
 *         int field_one;
 *         long field_two;
 *     };
 *
 *     // Initialize the handle
 *     sync_open(&obj.sync, 0, sizeof(struct obj_sync_data));
 *
 *     // Lock. Use SYNC_STATE_SHARED for reading data, SYNC_STATE_EXCLUSIVE if you need to update
 *     // it. After locking, you can read latest data (if it's there: a newly created handle will
 *     // not have any data associated).
 *     sync_lock(&obj.sync, SYNC_STATE_EXCLUSIVE);
 *     if (obj.sync.data_size != 0) {
 *         struct obj_sync_data* read_data = obj.sync.buf;
 *         assert(obj.sync.data_size == sizeof(*read_data));
 *         obj.field_one = read_data->field_one;
 *         obj.field_two = read_data->field_two;
 *     }
 *
 *     // Use the object
 *     obj.field = ...;
 *
 *     // Unlock, writing the new data first
 *     struct obj_sync_data* write_data = obj.sync.buf;
 *     obj.sync.data_size = sizeof(*write_data);
 *     assert(obj.sync.data_size <= obj.sync.buf_size);
 *     write_data->field_one = obj.field_one;
 *     write_data->field_two = obj.field_two;
 *     sync_unlock(&file->sync);
 *
 *     // Close the handle before destroying the object
 *     sync_close(&obj.sync);
 *
 * The sync engine is currently experimental. To enable it, set `libos.sync.enable = 1` in the
 * manifest. When it's not enabled, sync_lock() and sync_unlock() will function as regular, local
 * locks, and no remote communication will be performed.
 */

/*
 * Implementation overview:
 *
 * The sync engine uses a client/server architecture. The client code runs on all participating
 * processes, and the server code runs on the main process. The client and server communicate over
 * IPC.
 *
 * The client sends the following messages to server:
 *
 * - REQUEST_UPGRADE(id, state): The client requests access to a resource with given ID (in either
 *   SHARED or EXCLUSIVE) mode. The server will downgrade the handles for other clients (if that's
 *   necessary for fulfilling the request), and reply with UPGRADE once the resource can be used.
 *
 * - DOWNGRADE(id, state, data_size, data): The client confirms downgrade of its own handle, and
 *   sends the latest data associated with it. This is usually a response to REQUEST_DOWNGRADE.
 *
 * The server sends the following messages to the client:
 *
 * - UPGRADE(id, state, data_size, data): The server confirms upgrade of a handle to the client, and
 *   sends the last data associated with the handle. This is a response to REQUEST_UPGRADE.
 *
 * - REQUEST_DOWNGRADE(id, state, data_size, data): The server requests the client to downgrade its
 *   handle. The client will reply with DOWNGRADE when ready.
 *
 * Here is an example interaction:
 *
 *                                                        client1 state    client2 state
 *                                                        INVALID          INVALID
 *  1. client1 -> server: REQUEST_UPGRADE(123, SHARED)    .                .
 *  2. server -> client1: UPGRADE(123, SHARED)            SHARED           .
 *  3. client2 -> server: REQUEST_UPGRADE(123, SHARED)    |                .
 *  4. server -> client2: UPGRADE(123, SHARED)            |                SHARED
 *  5. client1 -> server: REQUEST_UPGRADE(123, EXCLUSIVE) |                |
 *  6. server -> client2: REQUEST_DOWNGRADE(123, INVALID) |                |
 *  7. client2 -> server: DOWNGRADE(123, INVALID)         |                INVALID
 *  8. server -> client1: UPGRADE(123, EXCLUSIVE)         EXCLUSIVE        .
 *
 * In the above diagram, both clients request resource 123 in SHARED mode, and they hold SHARED
 * handles at the same time. Later, when the first client requests EXCLUSIVE access, the other
 * client is asked to downgrade to INVALID before the upgrade can be confirmed.
 */

/*
 * TODO (necessary for correctness):
 * - server: delete client/handle info for unused handles
 * - server: delete client/handle info when a client disconnects
 * - client: flush all handles on process exit
 * - IPC: add a mechanism for self messages (from leader to itself) that does not use pipes
 *
 * TODO (new features for additional use cases):
 * - mechanism for independently acquiring the same handle, without knowing the ID (e.g. for a given
 *   file path)
 * - conditional acquire of a handle, perhaps similar to FUTEX_WAIT_BITSET: would allow for more
 *   fine-grained locking
 */

#ifndef _SHIM_SYNC_H_
#define _SHIM_SYNC_H_

#include <stdint.h>

#include "list.h"
#include "pal.h"
#include "shim_types.h"

#define uthash_fatal(msg)                      \
    do {                                       \
        log_error("uthash error: %s\n", msg);  \
        DkProcessExit(PAL_ERROR_NOMEM);        \
    } while (0)
#include "uthash.h"

enum {
    SYNC_STATE_NONE = 0,
    SYNC_STATE_INVALID,
    SYNC_STATE_SHARED,
    SYNC_STATE_EXCLUSIVE,

    SYNC_STATE_NUM,
};

struct sync_handle {
    uint64_t id;

    UT_hash_handle hh;

    /* Used by sync_lock .. sync_unlock. */
    struct shim_lock use_lock;

    /* Buffer for synchronized data. */
    size_t buf_size;
    void* buf;

    /* Size of currently stored data. Should be always less than buf_size. */
    size_t data_size;

    /* Internal properties lock. Protects all the following fields. */
    struct shim_lock prop_lock;

    /* Notification event for state changes. */
    PAL_HANDLE event;
    unsigned int n_waiters;

    /* Set to true if object is currently used (use_lock is locked). */
    bool used;

    /* Current state (INVALID, SHARED or EXCLUSIVE); lower or equal to server's cur_state */
    int cur_state;
    /* Requested by client; always higher than cur_state, or NONE */
    int up_state;
    /* Requested by server; always lower than cur_state, or NONE */
    int down_state;
};

/*** User interface (sync_handle) ***/

/* Initialize the sync server. Should be called for the process leader. */
int init_sync_server(void);

/* Initialize the sync client. Should be done after the IPC subsystem (including sync server) is up
 * and running. */
int init_sync_client(void);

/* Initialize and register a sync handle. If `id` is 0, allocate a fresh handle ID.
 * Before calling sync_open() on given handle, handle->id must be set to 0, for easier lifecycle
 * tracking. */
int sync_open(struct sync_handle* handle, uint64_t id, size_t buf_size);

/* Check if the handle has been initialized, to prevent sync_open()/sync_close() outside of
 * lifecycle */
static inline bool sync_is_open(struct sync_handle* handle) {
    return handle->id != 0;
}

/* Uninitialize a sync handle; call before destroying */
void sync_close(struct sync_handle* handle);

/*
 * Acquire a handle in a given state (or higher). Should be done before accessing handle.buf and
 * handle.buf_size.
 *
 * Provides the following guarantees:
 * - only one thread is holding a lock in a given process
 * - if state is SYNC_STATE_SHARED, no other process is holding a lock in SYNC_STATE_EXCLUSIVE state
 * - if state is SYNC_STATE_EXCLUSIVE, no other process is holding a lock in any state
 * - handle->buf and handle->data_size can be accessed; however, they should be modified only in
 *   SYNC_STATE_EXCLUSIVE state
 */
void sync_lock(struct sync_handle* handle, int state);

/* Release a handle. */
void sync_unlock(struct sync_handle* handle);

/*** Message handlers (called from IPC, see ipc/shim_ipc_sync.c) ***/

struct shim_ipc_port;

int sync_server_handle_request_upgrade(struct shim_ipc_port* port, uint64_t id, int state);
int sync_server_handle_downgrade(struct shim_ipc_port* port, uint64_t id, int state,
                                 size_t data_size, void* data);

int sync_client_handle_request_downgrade(uint64_t id, int state);
int sync_client_handle_upgrade(uint64_t id, int state, size_t data_size, void* data);

#endif /* _SHIM_SYNC_H_ */
