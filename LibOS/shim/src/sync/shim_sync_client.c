/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Client part of the sync engine.
 */

#include "assert.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_sync.h"

#define FATAL(fmt...)                                   \
    do {                                                \
        log_error("Fatal error in sync client: " fmt);  \
        DkProcessExit(1);                               \
    } while (0)

static bool g_sync_enabled = false;

static struct sync_handle* g_client_handles = NULL;
static uint32_t g_client_counter = 1;
static struct shim_lock g_client_lock;

static void lock_client(void) {
    /* Allow creating/using handles in a single-thread scenario before sync client is initialized
     * (i.e. when lock is not created yet). */
    if (lock_created(&g_client_lock))
        lock(&g_client_lock);
}

static void unlock_client(void) {
    /* Allow creating/using handles in a single-thread scenario before sync client is initialized
     * (i.e. when lock is not created yet). */
    if (lock_created(&g_client_lock))
        unlock(&g_client_lock);
}

/* Generate a new handle ID. Uses current process ID to make the handles globally unique. */
static uint64_t sync_new_id(void) {
    IDTYPE pid = g_process.pid;
    assert(pid != 0);

    lock_client();
    uint64_t id = ((uint64_t)pid << 32) + g_client_counter++;
    if (g_client_counter == 0)
        FATAL("g_client_counter wrapped around\n");
    unlock_client();
    return id;
}

/* Wait for a notification on handle->event. This function expects handle->prop_lock to be held, and
 * temporarily releases it. */
static void sync_wait(struct sync_handle* handle) {
    assert(locked(&handle->prop_lock));

    handle->n_waiters++;
    unlock(&handle->prop_lock);
    if (object_wait_with_retry(handle->event) < 0)
        FATAL("waiting for event\n");
    lock(&handle->prop_lock);
    if (--handle->n_waiters == 0)
        DkEventClear(handle->event);
}

static void sync_notify(struct sync_handle* handle) {
    if (handle->n_waiters > 0)
        DkEventSet(handle->event);
}

static void sync_downgrade(struct sync_handle* handle) {
    assert(locked(&handle->prop_lock));
    assert(!handle->used);
    assert(handle->phase == SYNC_PHASE_OPEN);
    assert(handle->server_req_state != SYNC_STATE_NONE);
    assert(handle->server_req_state < handle->cur_state);

    size_t data_size;
    if (handle->data && handle->cur_state == SYNC_STATE_EXCLUSIVE) {
        data_size = handle->data_size;
    } else {
        data_size = 0;
    }
    if (ipc_sync_client_send(IPC_MSG_SYNC_CONFIRM_DOWNGRADE, handle->id, handle->server_req_state,
                             data_size, handle->data) < 0)
        FATAL("sending CONFIRM_DOWNGRADE\n");
    handle->cur_state = handle->server_req_state;
    handle->server_req_state = SYNC_STATE_NONE;
}

int init_sync_client(void) {
    if (!create_lock(&g_client_lock))
        return -ENOMEM;

    assert(g_manifest_root);
    int64_t sync_enable = 0;
    int ret = toml_int_in(g_manifest_root, "libos.sync.enable", /*defaultval=*/0, &sync_enable);
    if (ret < 0 || (sync_enable != 0 && sync_enable != 1)) {
        log_error("Cannot parse 'libos.sync.enable' (the value must be 0 or 1)\n");
        return -EINVAL;
    }
    if (sync_enable) {
        log_debug("Enabling sync client\n");
        g_sync_enabled = true;
    }
    return 0;
}

int sync_init(struct sync_handle* handle, uint64_t id, size_t data_size) {
    int ret;

    assert(handle->id == 0);

    if (id == 0)
        id = sync_new_id();

    memset(handle, 0, sizeof(*handle));
    handle->id = id;
    handle->data_size = data_size;
    handle->data = NULL;

    if (!create_lock(&handle->use_lock)) {
        ret = -ENOMEM;
        goto err;
    }
    if (!create_lock(&handle->prop_lock)) {
        ret = -ENOMEM;
        goto err;
    }
    if ((ret = DkEventCreate(&handle->event, /*init_signaled=*/false, /*aut_clear=*/false)) < 0) {
        ret = pal_to_unix_errno(ret);
        goto err;
    }

    handle->n_waiters = 0;

    handle->phase = SYNC_PHASE_NEW;
    handle->cur_state = SYNC_STATE_INVALID;
    handle->client_req_state = SYNC_STATE_NONE;
    handle->server_req_state = SYNC_STATE_NONE;
    handle->used = false;

    lock_client();

    /* Check if we're not creating a handle with the same ID twice. */
    struct sync_handle *handle_prev;
    HASH_FIND(hh, g_client_handles, &id, sizeof(id), handle_prev);
    if (handle_prev) {
        ret = -EINVAL;
        unlock_client();
        goto err;
    }

    HASH_ADD(hh, g_client_handles, id, sizeof(id), handle);

    unlock_client();

    return 0;

err:
    handle->id = 0;
    if (lock_created(&handle->use_lock))
        destroy_lock(&handle->use_lock);
    if (lock_created(&handle->prop_lock))
        destroy_lock(&handle->prop_lock);
    if (handle->event)
        DkObjectClose(handle->event);
    return ret;
}

static void __sync_destroy(struct sync_handle* handle) {
    free(handle->data);
    destroy_lock(&handle->use_lock);
    destroy_lock(&handle->prop_lock);
    DkObjectClose(handle->event);

    handle->id = 0;
}

static int send_request_close(struct sync_handle* handle) {
    assert(locked(&handle->prop_lock));
    size_t data_size;
    if (handle->data && handle->cur_state == SYNC_STATE_EXCLUSIVE) {
        data_size = handle->data_size;
    } else {
        data_size = 0;
    }

    return ipc_sync_client_send(IPC_MSG_SYNC_REQUEST_CLOSE, handle->id,
                                handle->cur_state, data_size, handle->data);
}

void sync_destroy(struct sync_handle* handle) {
    assert(handle->id != 0);

    lock(&handle->prop_lock);
    assert(!handle->used);
    assert(handle->n_waiters == 0);

    if (g_sync_enabled && handle->phase == SYNC_PHASE_OPEN) {
        if (send_request_close(handle) < 0)
            FATAL("sending REQUEST_CLOSE\n");
        handle->phase = SYNC_PHASE_CLOSING;
        handle->cur_state = SYNC_STATE_INVALID;
        do {
            sync_wait(handle);
        } while (handle->phase != SYNC_PHASE_CLOSED);
    }
    unlock(&handle->prop_lock);

    lock_client();
    HASH_DELETE(hh, g_client_handles, handle);
    unlock_client();

    __sync_destroy(handle);
}

bool sync_lock(struct sync_handle* handle, int state, void* data) {
    assert(state == SYNC_STATE_SHARED || state == SYNC_STATE_EXCLUSIVE);

    lock(&handle->use_lock);
    if (!g_sync_enabled)
        return false;

    lock(&handle->prop_lock);
    assert(!handle->used);
    handle->used = true;

    bool updated = false;

    if (handle->cur_state < state) {
        do {
            if (handle->phase == SYNC_PHASE_CLOSING || handle->phase == SYNC_PHASE_CLOSED)
                FATAL("sync_lock() on a closed handle\n");

            if (handle->client_req_state < state && handle->cur_state ) {
                if (ipc_sync_client_send(IPC_MSG_SYNC_REQUEST_UPGRADE, handle->id, state,
                                         /*data_size=*/0, /*data=*/NULL) < 0)
                    FATAL("sending REQUEST_UPGRADE\n");
                handle->client_req_state = state;
                handle->phase = SYNC_PHASE_OPEN;
            }
            sync_wait(handle);
        } while (handle->cur_state < state);

        if (data && handle->data) {
            memcpy(data, handle->data, handle->data_size);
            updated = true;
        }
    }

    unlock(&handle->prop_lock);
    return updated;
}

void sync_unlock(struct sync_handle* handle, void* data) {
    if (!g_sync_enabled) {
        unlock(&handle->use_lock);
        return;
    }

    lock(&handle->prop_lock);
    assert(handle->used);

    if (data) {
        if (!handle->data && !(handle->data = malloc(handle->data_size)))
            FATAL("allocating handle data\n");

        memcpy(handle->data, data, handle->data_size);
    }

    handle->used = false;
    if (handle->phase == SYNC_PHASE_OPEN && handle->server_req_state < handle->cur_state
            && handle->server_req_state != SYNC_STATE_NONE)
        sync_downgrade(handle);
    unlock(&handle->prop_lock);
    unlock(&handle->use_lock);
}

int shutdown_sync_client(void) {
    lock_client();

    /* Send REQUEST_CLOSE for all open handles. At this point, no threads using the sync engine
     * should be running (except for the IPC helper), so no handles will be created or upgraded. */
    log_debug("sync client shutdown: closing handles\n");
    struct sync_handle* handle;
    struct sync_handle* tmp;
    HASH_ITER(hh, g_client_handles, handle, tmp) {
        lock(&handle->prop_lock);
        if (g_sync_enabled && handle->phase == SYNC_PHASE_OPEN) {
            if (send_request_close(handle) < 0)
                FATAL("sending REQUEST_CLOSE\n");
            handle->phase = SYNC_PHASE_CLOSING;
            handle->cur_state = SYNC_STATE_INVALID;
        }
        unlock(&handle->prop_lock);
    }

    /* Wait for server to confirm the handles are closed, and delete them. */
    log_debug("sync client shutdown: waiting for confirmation and deleting handles\n");
    while (g_client_handles) {
        handle = g_client_handles;
        unlock_client();

        lock(&handle->prop_lock);
        if (handle->phase == SYNC_PHASE_CLOSING) {
            do {
                sync_wait(handle);
            } while (handle->phase != SYNC_PHASE_CLOSED);
        }
        unlock(&handle->prop_lock);

        lock_client();
        HASH_DELETE(hh, g_client_handles, handle);
        __sync_destroy(handle);
    }
    unlock_client();

    log_debug("sync client shutdown: finished\n");

    return 0;
}

static struct sync_handle* find_handle(uint64_t id) {
    lock_client();
    struct sync_handle* handle = NULL;
    HASH_FIND(hh, g_client_handles, &id, sizeof(id), handle);

    if (!handle)
        FATAL("message for unknown handle\n");
    unlock_client();
    return handle;
}

static void do_request_downgrade(uint64_t id, int state) {
    assert(g_sync_enabled);

    struct sync_handle* handle = find_handle(id);
    lock(&handle->prop_lock);
    if (handle->phase == SYNC_PHASE_OPEN && handle->cur_state > state
            && (handle->server_req_state > state || handle->server_req_state == SYNC_STATE_NONE)) {
        handle->server_req_state = state;
        if (!handle->used)
            sync_downgrade(handle);
    }
    unlock(&handle->prop_lock);
}

static void do_confirm_upgrade(uint64_t id, int state, size_t data_size, void* data) {
    assert(g_sync_enabled);

    struct sync_handle* handle = find_handle(id);

    lock(&handle->prop_lock);
    if (handle->phase == SYNC_PHASE_OPEN && handle->cur_state < state) {
        handle->cur_state = state;
        handle->client_req_state = SYNC_STATE_NONE;
        sync_notify(handle);
    }

    if (data_size > 0) {
        if (data_size != handle->data_size)
            FATAL("handle data size mismatch\n");
        if (!handle->data && !(handle->data = malloc(handle->data_size)))
            FATAL("allocating handle data\n");
        memcpy(handle->data, data, data_size);
    }

    unlock(&handle->prop_lock);
}

static void do_confirm_close(uint64_t id) {
    assert(g_sync_enabled);

    struct sync_handle* handle = find_handle(id);

    lock(&handle->prop_lock);
    if (handle->phase != SYNC_PHASE_CLOSED) {
        handle->phase = SYNC_PHASE_CLOSED;
        sync_notify(handle);
    }
    unlock(&handle->prop_lock);
}

void sync_client_message_callback(int code, uint64_t id, int state, size_t data_size, void* data) {
    switch (code) {
        case IPC_MSG_SYNC_REQUEST_DOWNGRADE:
            assert(data_size == 0);
            do_request_downgrade(id, state);
            break;
        case IPC_MSG_SYNC_CONFIRM_UPGRADE:
            do_confirm_upgrade(id, state, data_size, data);
            break;
        case IPC_MSG_SYNC_CONFIRM_CLOSE:
            do_confirm_close(id);
            break;
        default:
            FATAL("unknown message: %d\n", code);
    }
}
