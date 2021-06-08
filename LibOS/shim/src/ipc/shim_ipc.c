/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * This file provides functions for dealing with outgoing IPC connections, mainly sending IPC
 * messages (`shim_ipc_msg` and `shim_ipc_msg_with_ack`).
 */

#include <stdbool.h>

#include "assert.h"
#include "avl_tree.h"
#include "pal.h"
#include "shim_checkpoint.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_lock.h"
#include "shim_thread.h"
#include "shim_types.h"
#include "shim_utils.h"

struct shim_ipc_connection {
    struct avl_tree_node node;
    IDTYPE vmid;
    REFTYPE ref_count;
    PAL_HANDLE handle;
    /* This lock guards concurrent accesses to `handle`. If you need both this lock and
     * `g_ipc_connections_lock`, take the latter first. */
    struct shim_lock lock;
};

static bool ipc_connection_cmp(struct avl_tree_node* _a, struct avl_tree_node* _b) {
    struct shim_ipc_connection* a = container_of(_a, struct shim_ipc_connection, node);
    struct shim_ipc_connection* b = container_of(_b, struct shim_ipc_connection, node);
    return a->vmid <= b->vmid;
}

/* Tree of outgoing IPC connections, to be accessed only with `g_ipc_connections_lock` taken. */
static struct avl_tree g_ipc_connections = { .cmp = ipc_connection_cmp };
static struct shim_lock g_ipc_connections_lock;

static bool msg_with_ack_cmp(struct avl_tree_node* _a, struct avl_tree_node* _b) {
    struct shim_ipc_msg_with_ack* a = container_of(_a, struct shim_ipc_msg_with_ack, node);
    struct shim_ipc_msg_with_ack* b = container_of(_b, struct shim_ipc_msg_with_ack, node);
    return a->msg.header.seq <= b->msg.header.seq;
}

static struct avl_tree g_msg_with_ack_tree = { .cmp = msg_with_ack_cmp };
static struct shim_lock g_msg_with_ack_tree_lock;

IDTYPE g_self_vmid;
struct shim_ipc_ids g_process_ipc_ids;

int init_ipc(void) {
    if (!create_lock(&g_ipc_connections_lock)) {
        return -ENOMEM;
    }
    if (!create_lock(&g_msg_with_ack_tree_lock)) {
        return -ENOMEM;
    }

    int ret = 0;
    if ((ret = init_ns_ranges()) < 0)
        return ret;

    return 0;
}

static void get_ipc_connection(struct shim_ipc_connection* conn) {
    REF_INC(conn->ref_count);
}

static void put_ipc_connection(struct shim_ipc_connection* conn) {
    int64_t ref_count = REF_DEC(conn->ref_count);

    if (!ref_count) {
        DkObjectClose(conn->handle);
        destroy_lock(&conn->lock);
        free(conn);
    }
}

static struct shim_ipc_connection* node2conn(struct avl_tree_node* node) {
    if (!node) {
        return NULL;
    }
    return container_of(node, struct shim_ipc_connection, node);
}

static int ipc_connect(IDTYPE dest, struct shim_ipc_connection** conn_ptr) {
    struct shim_ipc_connection dummy = { .vmid = dest };
    int ret = 0;

    lock(&g_ipc_connections_lock);
    struct shim_ipc_connection* conn = node2conn(avl_tree_find(&g_ipc_connections, &dummy.node));
    if (!conn) {
        conn = calloc(1, sizeof(*conn));
        if (!conn) {
            ret = -ENOMEM;
            goto out;
        }
        if (!create_lock(&conn->lock)) {
            ret = -ENOMEM;
            goto out;
        }

        char uri[PIPE_URI_SIZE];
        if (vmid_to_uri(dest, uri, sizeof(uri)) < 0) {
            log_error("buffer for IPC pipe URI too small\n");
            BUG();
        }
        ret = DkStreamOpen(uri, 0, 0, 0, 0, &conn->handle);
        if (ret < 0) {
            ret = pal_to_unix_errno(ret);
            goto out;
        }
        ret = write_exact(conn->handle, &g_self_vmid, sizeof(g_self_vmid));
        if (ret < 0) {
            goto out;
        }

        conn->vmid = dest;
        REF_SET(conn->ref_count, 1);
        avl_tree_insert(&g_ipc_connections, &conn->node);
    }

    get_ipc_connection(conn);
    *conn_ptr = conn;
    conn = NULL;
    ret = 0;

out:
    if (conn) {
        if (lock_created(&conn->lock)) {
            destroy_lock(&conn->lock);
        }
        if (conn->handle) {
            DkObjectClose(conn->handle);
        }
        free(conn);
    }
    unlock(&g_ipc_connections_lock);
    return ret;
}

static void _remove_ipc_connection(struct shim_ipc_connection* conn) {
    avl_tree_delete(&g_ipc_connections, &conn->node);
    put_ipc_connection(conn);
}

static void remove_ipc_connection(struct shim_ipc_connection* conn) {
    lock(&g_ipc_connections_lock);
    _remove_ipc_connection(conn);
    unlock(&g_ipc_connections_lock);
}

int connect_to_process(IDTYPE dest) {
    struct shim_ipc_connection* conn = NULL;
    int ret = ipc_connect(dest, &conn);
    if (ret < 0) {
        return ret;
    }
    put_ipc_connection(conn);
    return 0;
}

void remove_outgoing_ipc_connection(IDTYPE dest) {
    struct shim_ipc_connection dummy = { .vmid = dest };
    lock(&g_ipc_connections_lock);
    struct shim_ipc_connection* conn = node2conn(avl_tree_find(&g_ipc_connections, &dummy.node));
    if (conn) {
        _remove_ipc_connection(conn);
    }
    unlock(&g_ipc_connections_lock);
}

void init_ipc_msg(struct shim_ipc_msg* msg, int code, size_t size) {
    msg->header.size = get_ipc_msg_size(size);
    msg->header.seq = 0;
    msg->header.code = code;
}

void init_ipc_msg_with_ack(struct shim_ipc_msg_with_ack* msg, int code, size_t size) {
    init_ipc_msg(&msg->msg, code, size);
    msg->thread = NULL;
    msg->retval = 0;
    msg->private = NULL;
}

static int send_ipc_message_to_conn(struct shim_ipc_msg* msg, struct shim_ipc_connection* conn) {
    log_debug("Sending ipc message to %u\n", conn->vmid);

    lock(&conn->lock);

    int ret = write_exact(conn->handle, msg,  msg->header.size);
    if (ret < 0) {
        log_error("Failed to send IPC msg to %u: %d\n", conn->vmid, ret);
        unlock(&conn->lock);
        remove_ipc_connection(conn);
        return ret;
    }

    unlock(&conn->lock);
    return 0;
}

int send_ipc_message(struct shim_ipc_msg* msg, IDTYPE dst) {
    struct shim_ipc_connection* conn = NULL;
    int ret = ipc_connect(dst, &conn);
    if (ret < 0) {
        return ret;
    }

    ret = send_ipc_message_to_conn(msg, conn);
    put_ipc_connection(conn);
    return ret;
}

void ipc_msg_response_handle(unsigned long seq,
                             void (*callback)(struct shim_ipc_msg_with_ack*, void*), void* data) {
    assert(seq);
    struct shim_ipc_msg_with_ack dummy = {
        .msg.header.seq = seq,
    };
    lock(&g_msg_with_ack_tree_lock);
    struct shim_ipc_msg_with_ack* msg = NULL;
    struct avl_tree_node* node = avl_tree_find(&g_msg_with_ack_tree, &dummy.node);
    if (node) {
        msg = container_of(node, struct shim_ipc_msg_with_ack, node);
    }
    callback(msg, data);
    unlock(&g_msg_with_ack_tree_lock);
}

int send_ipc_message_with_ack(struct shim_ipc_msg_with_ack* msg, IDTYPE dst, unsigned long* seq) {
    int ret = 0;

    assert(!msg->thread);
    msg->thread = get_cur_thread();
    get_thread(msg->thread);

    thread_prepare_wait();

    static unsigned long ipc_seq_counter = 0;
    msg->msg.header.seq = __atomic_add_fetch(&ipc_seq_counter, 1, __ATOMIC_RELAXED);

    lock(&g_msg_with_ack_tree_lock);
    avl_tree_insert(&g_msg_with_ack_tree, &msg->node);
    unlock(&g_msg_with_ack_tree_lock);

    ret = send_ipc_message(&msg->msg, dst);
    if (ret < 0)
        goto out;

    if (seq)
        *seq = msg->msg.header.seq;

    log_debug("Waiting for response (seq = %lu)\n", msg->msg.header.seq);

    /* TODO: this should be `wait_event` on a special purpose event embedded in `msg`. */
    do {
        ret = thread_wait(/*timeout_us=*/NULL, /*ignore_pending_signals=*/true);
        if (ret < 0 && ret != -EINTR)
            goto out;
    } while (ret == -EINTR);

    log_debug("Finished waiting for response (seq = %lu, ret = %d)\n", msg->msg.header.seq,
              msg->retval);
    ret = 0;

out:
    lock(&g_msg_with_ack_tree_lock);
    avl_tree_delete(&g_msg_with_ack_tree, &msg->node);
    unlock(&g_msg_with_ack_tree_lock);

    if (ret == 0) {
        ret = msg->retval;
    }

    assert(msg->thread == get_cur_thread());
    put_thread(msg->thread);
    msg->thread = NULL;

    return ret;
}

int request_leader_connect_back(void) {
    IDTYPE leader = g_process_ipc_ids.leader_vmid;
    assert(leader);

    size_t total_msg_size = get_ipc_msg_with_ack_size(0);
    struct shim_ipc_msg_with_ack* msg = __alloca(total_msg_size);
    init_ipc_msg_with_ack(msg, IPC_MSG_CONNBACK, total_msg_size);

    log_debug("sending IPC_MSG_CONNBACK message to %u\n", leader);

    return send_ipc_message_with_ack(msg, leader, NULL);
}

void wake_req_msg_thread(struct shim_ipc_msg_with_ack* req_msg, void* data) {
    __UNUSED(data);
    if (req_msg) {
        assert(req_msg->thread);
        thread_wakeup(req_msg->thread);
    }
}

int ipc_dummy_callback(IDTYPE src, void* data, unsigned long seq) {
    __UNUSED(src);
    __UNUSED(data);
    ipc_msg_response_handle(seq, wake_req_msg_thread, NULL);
    return 0;
}

int broadcast_ipc(struct shim_ipc_msg* msg, IDTYPE exclude_id) {
    lock(&g_ipc_connections_lock);
    struct shim_ipc_connection* conn = node2conn(avl_tree_first(&g_ipc_connections));

    int main_ret = 0;
    while (conn) {
        if (conn->vmid != exclude_id) {
            int ret = send_ipc_message_to_conn(msg, conn);
            if (!main_ret) {
                main_ret = ret;
            }
        }
        conn = node2conn(avl_tree_next(&conn->node));
    }

    unlock(&g_ipc_connections_lock);
    return main_ret;
}

BEGIN_CP_FUNC(process_ipc_ids) {
    __UNUSED(size);
    __UNUSED(objp);
    assert(size == sizeof(struct shim_ipc_ids));

    struct shim_ipc_ids* ipc_ids = (struct shim_ipc_ids*)obj;

    size_t off = ADD_CP_OFFSET(sizeof(*ipc_ids));
    ADD_CP_FUNC_ENTRY(off);

    *(struct shim_ipc_ids*)(base + off) = *ipc_ids;
}
END_CP_FUNC(process_ipc_ids)

BEGIN_RS_FUNC(process_ipc_ids) {
    __UNUSED(offset);
    __UNUSED(rebase);
    struct shim_ipc_ids* ipc_ids = (void*)(base + GET_CP_FUNC_ENTRY());

    g_process_ipc_ids = *ipc_ids;
}
END_RS_FUNC(process_ipc_ids)
