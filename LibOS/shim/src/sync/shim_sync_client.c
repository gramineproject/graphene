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
    } while(0)

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
        FATAL("waiting for event");
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
    assert(handle->server_req_state != SYNC_STATE_NONE);
    assert(handle->server_req_state < handle->cur_state);

    size_t data_size;
    if (handle->cur_state == SYNC_STATE_EXCLUSIVE) {
        data_size = handle->data_size;
    } else {
        data_size = 0;
    }
    if (ipc_sync_client_send(IPC_MSG_SYNC_CONFIRM_DOWNGRADE, handle->id, handle->server_req_state,
                             data_size, handle->buf) < 0)
        FATAL("sending CONFIRM_DOWNGRADE");
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

int shutdown_sync_client(void) {
    log_debug("Shutting down sync client\n");
    lock_client();
    while (g_client_handles) {
        struct sync_handle* handle = g_client_handles;
        unlock_client();
        sync_destroy(handle);
        lock_client();
    }
    unlock_client();
    return 0;
}

int sync_init(struct sync_handle* handle, uint64_t id, size_t buf_size) {
    int ret;

    assert(handle->id == 0);

    if (id == 0)
        id = sync_new_id();

    memset(handle, 0, sizeof(*handle));
    handle->id = id;
    handle->buf_size = buf_size;
    handle->data_size = 0;

    if (!(handle->buf = malloc(buf_size))) {
        ret = -ENOMEM;
        goto err;
    }

    if (!create_lock(&handle->use_lock)) {
        ret = -ENOMEM;
        goto err;
    }
    if (!create_lock(&handle->prop_lock)) {
        ret = -ENOMEM;
        goto err;
    }
    if ((ret = DkNotificationEventCreate(/*initialState=*/false, &handle->event)) < 0) {
        ret = pal_to_unix_errno(ret);
        goto err;
    }

    handle->n_waiters = 0;

    handle->cur_state = SYNC_STATE_CLOSED;
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
    free(handle->buf);
    if (lock_created(&handle->use_lock))
        destroy_lock(&handle->use_lock);
    if (lock_created(&handle->prop_lock))
        destroy_lock(&handle->prop_lock);
    if (handle->event)
        DkObjectClose(handle->event);
    return ret;
}

void sync_destroy(struct sync_handle* handle) {
    assert(handle->id != 0);

    lock(&handle->use_lock);
    lock(&handle->prop_lock);

    assert(!handle->used);
    assert(handle->n_waiters == 0);

    if (g_sync_enabled) {
        if (handle->cur_state != SYNC_STATE_CLOSED) {
            size_t data_size;
            if (handle->cur_state == SYNC_STATE_EXCLUSIVE) {
                data_size = handle->data_size;
            } else {
                data_size = 0;
            }

            if (ipc_sync_client_send(IPC_MSG_SYNC_REQUEST_CLOSE, handle->id,
                                     handle->cur_state, data_size, handle->buf) < 0) {
                FATAL("sending REQUEST_CLOSE");
            }
            while (handle->cur_state != SYNC_STATE_CLOSED)
                sync_wait(handle);
        }
    }

    lock_client();
    HASH_DELETE(hh, g_client_handles, handle);
    unlock_client();

    destroy_lock(&handle->use_lock);
    destroy_lock(&handle->prop_lock);
    DkObjectClose(handle->event);

    handle->id = 0;
}

void sync_lock(struct sync_handle* handle, int state) {
    assert(state == SYNC_STATE_SHARED || state == SYNC_STATE_EXCLUSIVE);

    lock(&handle->use_lock);
    if (!g_sync_enabled)
        return;

    lock(&handle->prop_lock);
    assert(!handle->used);
    handle->used = true;

    while (handle->cur_state < state) {
        if (handle->client_req_state < state) {
            if (ipc_sync_client_send(IPC_MSG_SYNC_REQUEST_UPGRADE, handle->id, state,
                                     /*data_size=*/0, /*data=*/NULL) < 0)
                FATAL("sending REQUEST_UPGRADE");
            handle->client_req_state = state;
        }
        sync_wait(handle);
    }

    unlock(&handle->prop_lock);
}

void sync_unlock(struct sync_handle* handle) {
    if (!g_sync_enabled) {
        unlock(&handle->use_lock);
        return;
    }

    lock(&handle->prop_lock);
    assert(handle->used);
    handle->used = false;
    if (handle->server_req_state < handle->cur_state && handle->server_req_state != SYNC_STATE_NONE)
        sync_downgrade(handle);
    unlock(&handle->prop_lock);
    unlock(&handle->use_lock);
}

static struct sync_handle* find_handle(uint64_t id) {
    struct sync_handle* handle = NULL;
    lock_client();
    HASH_FIND(hh, g_client_handles, &id, sizeof(id), handle);
    unlock_client();

    if (!handle)
        FATAL("message for unknown handle\n");
    return handle;
}

static void do_request_downgrade(uint64_t id, int state) {
    assert(g_sync_enabled);

    struct sync_handle* handle = find_handle(id);
    lock(&handle->prop_lock);
    if (handle->cur_state > state && (handle->server_req_state > state
                                      || handle->server_req_state == SYNC_STATE_NONE)) {
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
    if (handle->cur_state < state) {
        handle->cur_state = state;
        handle->client_req_state = SYNC_STATE_NONE;
        sync_notify(handle);
    }

    if (data_size > handle->buf_size)
        FATAL("handle buf_size too small\n");
    handle->data_size = data_size;
    memcpy(handle->buf, data, data_size);

    unlock(&handle->prop_lock);
}

static void do_confirm_close(uint64_t id) {
    assert(g_sync_enabled);

    struct sync_handle* handle = find_handle(id);
    lock(&handle->prop_lock);
    if (handle->cur_state != SYNC_STATE_CLOSED) {
        handle->cur_state = SYNC_STATE_CLOSED;
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
