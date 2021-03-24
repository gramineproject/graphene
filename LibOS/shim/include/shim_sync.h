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
 *   handle can be updated
 *
 * When the handle is not locked, it can be downgraded to SYNC_STATE_INVALID by the remote
 * server. However, this will only happen if another process needs the handle. Therefore, as long as
 * the handle is uncontested, there is not communication overhead for using it.
 *
 * Example usage:
 *
 *     struct obj {
 *         int field;
 *         struct sync_handle sync;
 *     };
 *     struct obj obj = {0};
 *
 *     // Initialize the handle
 *     sync_open(&obj.sync, 0, sizeof(obj.field));
 *
 *     // Lock. Use SYNC_STATE_SHARED for reading data, SYNC_STATE_EXCLUSIVE if you need to update
 *     // it. After locking, you can read latest data.
 *     sync_lock(&obj.sync, SYNC_STATE_EXCLUSIVE);
 *     if (obj.sync.data_size == sizeof(obj.field))
 *         memcpy(&obj.field, obj.sync.buf, sizeof(obj.field);
 *
 *     // Use the object
 *     obj.field = ...;
 *
 *     // Unlock, writing the new data first
 *     obj.sync.data_size = sizeof(obj.field);
 *     memcpy(obj.sync.buf, &obj.field, sizeof(obj.field);
 *
 *     // Close the handle before destroying the object
 *     sync_close(&obj.sync);
 *
 * The sync engine is currently experimental. To enable it, set `libos.sync.enable = 1` in the
 * manifest. When it's not enabled, sync_lock() and sync_unlock() will function as regular, local
 * locks, and no remote communication will be performed.
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
 * The handle must have `id` set to 0, for easier lifecycle tracking. */
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
