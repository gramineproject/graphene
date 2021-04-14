/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <stdalign.h>
#include <stdnoreturn.h>

#include "assert.h"
#include "cpu.h"
#include "list.h"
#include "pal.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_lock.h"
#include "shim_thread.h"
#include "shim_types.h"
#include "shim_utils.h"

#define LOG_PREFIX "IPC worker: "

DEFINE_LIST(shim_ipc_connection);
DEFINE_LISTP(shim_ipc_connection);
struct shim_ipc_connection {
    LIST_TYPE(shim_ipc_connection) list;
    PAL_HANDLE handle;
    IDTYPE vmid;
};

static LISTP_TYPE(shim_ipc_connection) g_ipc_connections;
static size_t g_ipc_connections_cnt = 0;

static struct shim_thread* g_worker_thread = NULL;
static AEVENTTYPE interrupt_event;
static int g_time_to_exit = 0;
static int g_clear_on_worker_exit = 1;
static PAL_HANDLE g_self_ipc_handle = NULL;

static int ipc_resp_callback(struct shim_ipc_msg* msg, IDTYPE src);
static int ipc_connect_back_callback(struct shim_ipc_msg* msg, IDTYPE src);

typedef int (*ipc_callback)(struct shim_ipc_msg* msg, IDTYPE src);
static ipc_callback ipc_callbacks[] = {
    [IPC_MSG_RESP]          = ipc_resp_callback,
    [IPC_MSG_CONNBACK]      = ipc_connect_back_callback,
    [IPC_MSG_DUMMY]         = ipc_dummy_callback,
    [IPC_MSG_CHILDEXIT]     = ipc_cld_exit_callback,
    [IPC_MSG_LEASE]         = ipc_lease_callback,
    [IPC_MSG_OFFER]         = ipc_offer_callback,
    [IPC_MSG_SUBLEASE]      = ipc_sublease_callback,
    [IPC_MSG_QUERY]         = ipc_query_callback,
    [IPC_MSG_QUERYALL]      = ipc_queryall_callback,
    [IPC_MSG_ANSWER]        = ipc_answer_callback,
    [IPC_MSG_PID_KILL]      = ipc_pid_kill_callback,
    [IPC_MSG_PID_GETSTATUS] = ipc_pid_getstatus_callback,
    [IPC_MSG_PID_RETSTATUS] = ipc_pid_retstatus_callback,
    [IPC_MSG_PID_GETMETA]   = ipc_pid_getmeta_callback,
    [IPC_MSG_PID_RETMETA]   = ipc_pid_retmeta_callback,
    [IPC_MSG_SYSV_FINDKEY]  = ipc_sysv_findkey_callback,
    [IPC_MSG_SYSV_TELLKEY]  = ipc_sysv_tellkey_callback,
    [IPC_MSG_SYSV_DELRES]   = ipc_sysv_delres_callback,
    [IPC_MSG_SYSV_MSGSND]   = ipc_sysv_msgsnd_callback,
    [IPC_MSG_SYSV_MSGRCV]   = ipc_sysv_msgrcv_callback,
    [IPC_MSG_SYSV_SEMOP]    = ipc_sysv_semop_callback,
    [IPC_MSG_SYSV_SEMCTL]   = ipc_sysv_semctl_callback,
    [IPC_MSG_SYSV_SEMRET]   = ipc_sysv_semret_callback,
};

static noreturn void ipc_leader_died_callback(void) {
    // TODO maybe just ignore it? this triggers often if parent does wait+exit
    log_error("IPC leader died\n");
    DkProcessExit(1);
}

static void disconnect_callbacks(struct shim_ipc_connection* conn) {
    if (g_process_ipc_ids.leader_id == conn->vmid) {
        ipc_leader_died_callback();
    }
    ipc_child_disconnect_callback(conn->vmid);

    // TODO: ipc_disconnect_msg_with_ack_callback(conn->vmid);
}

static int add_ipc_connection(PAL_HANDLE handle, IDTYPE id) {
    struct shim_ipc_connection* conn = malloc(sizeof(*conn));
    if (!conn) {
        return -ENOMEM;
    }

    conn->handle = handle;
    conn->vmid = id;

    LISTP_ADD(conn, &g_ipc_connections, list);
    g_ipc_connections_cnt++;
    return 0;
}

static void del_ipc_connection(struct shim_ipc_connection* conn) {
    LISTP_DEL(conn, &g_ipc_connections, list);
    g_ipc_connections_cnt--;

    DkObjectClose(conn->handle);

    free(conn);
}

static int send_ipc_response(IDTYPE dest, int ret, unsigned long seq) {
    ret = (ret == RESPONSE_CALLBACK) ? 0 : ret;

    size_t total_msg_size = get_ipc_msg_size(sizeof(struct shim_ipc_resp));
    struct shim_ipc_msg* resp_msg = __alloca(total_msg_size);
    init_ipc_msg(resp_msg, IPC_MSG_RESP, total_msg_size, dest);
    resp_msg->seq = seq;

    struct shim_ipc_resp* resp = (struct shim_ipc_resp*)resp_msg->msg;
    resp->retval = ret;

    return send_ipc_message(resp_msg, dest);
}

static void set_request_retval(struct shim_ipc_msg_with_ack* req_msg, void* data) {
    if (!req_msg) {
        log_error(LOG_PREFIX "got response to an unknown message\n");
        return;
    }

    req_msg->retval = (int)(long)data;
    thread_wakeup(req_msg->thread);
}

static int ipc_resp_callback(struct shim_ipc_msg* msg, IDTYPE src) {
    struct shim_ipc_resp* resp = (struct shim_ipc_resp*)&msg->msg;
    log_debug(LOG_PREFIX "got IPC msg response from %u: %d\n", msg->src, resp->retval);
    assert(src == msg->src);

    ipc_msg_response_handle(src, msg->seq, set_request_retval, (void*)(long)resp->retval);

    return 0;
}

static int ipc_connect_back_callback(struct shim_ipc_msg* orig_msg, IDTYPE src) {
    size_t total_msg_size = get_ipc_msg_size(0);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_DUMMY, total_msg_size, src);
    msg->seq = orig_msg->seq;

    return send_ipc_message(msg, src);
}

#define READAHEAD_SIZE (IPC_MSG_MINIMAL_SIZE + 0x20)
static int receive_ipc_messages(struct shim_ipc_connection* conn) {
    size_t size = 0;
    alignas(struct shim_ipc_msg) char buf[IPC_MSG_MINIMAL_SIZE + READAHEAD_SIZE];

    do {
        /* Receive at least the message header. */
        while (size < IPC_MSG_MINIMAL_SIZE) {
            size_t tmp_size = sizeof(buf) - size;
            int ret = DkStreamRead(conn->handle, /*offset=*/0, &tmp_size, buf + size, NULL, 0);
            if (ret < 0) {
                if (ret == -PAL_ERROR_INTERRUPTED || ret == -PAL_ERROR_TRYAGAIN) {
                    continue;
                }
                ret = pal_to_unix_errno(ret);
                log_error(LOG_PREFIX "receiving message header from %u failed: %d\n", conn->vmid,
                          ret);
                return ret;
            }
            if (tmp_size == 0) {
                log_error(LOG_PREFIX "receiving message from %u failed: remote closed early\n",
                          conn->vmid);
                return -ENODATA;
            }
            size += tmp_size;
        }

        size_t msg_size = ((struct shim_ipc_msg*)buf)->size;
        struct shim_ipc_msg* msg = malloc(msg_size);
        if (!msg) {
            return -ENOMEM;
        }

        if (msg_size <= size) {
            /* Already got the whole message (and possibly part of the next one). */
            memcpy(msg, buf, msg_size);
            memmove(buf, buf + msg_size, size - msg_size);
            size -= msg_size;
        } else {
            /* Need to get rest of the message. */
            memcpy(msg, buf, size);
            int ret = read_exact(conn->handle, (char*)msg + size, msg_size - size);
            if (ret < 0) {
                free(msg);
                log_error(LOG_PREFIX "receiving message from %u failed: %d\n", conn->vmid, ret);
                return ret;
            }
            size = 0;
        }

        log_debug(LOG_PREFIX "received IPC message from %u: code=%d size=%lu src=%u dst=%u seq=%lu"
                  "\n", conn->vmid, msg->code, msg->size, msg->src, msg->dst, msg->seq);

        assert(conn->vmid == msg->src);

        if (msg->code < ARRAY_SIZE(ipc_callbacks) && ipc_callbacks[msg->code]) {
            int ret = ipc_callbacks[msg->code](msg, conn->vmid);
            if ((ret < 0 || ret == RESPONSE_CALLBACK) && msg->seq) {
                ret = send_ipc_response(conn->vmid, ret, msg->seq);
                if (ret < 0) {
                    log_error(LOG_PREFIX "sending IPC msg response to %u failed: %d\n", conn->vmid,
                              ret);
                    free(msg);
                    return ret;
                }
            }
        }

        free(msg);
    } while (size > 0);

    return 0;
}
#undef READAHEAD_SIZE

static noreturn void ipc_worker_main(void) {
    // TODO: maybe global array - but would require copying on conn delete
    struct shim_ipc_connection** connections = NULL;
    PAL_HANDLE* handles = NULL;
    PAL_FLG* events = NULL;
    PAL_FLG* ret_events = NULL;
    size_t prev_items_cnt = 0;

    while (1) {
        if (__atomic_load_n(&g_time_to_exit, __ATOMIC_ACQUIRE)) {
            log_debug(LOG_PREFIX "exiting worker thread\n");

            free(connections);
            free(handles);
            free(events);
            free(ret_events);

            struct shim_thread* cur_thread = get_cur_thread();
            assert(g_worker_thread == cur_thread);
            assert(cur_thread->shim_tcb->tp == cur_thread);
            cur_thread->shim_tcb->tp = NULL;
            put_thread(cur_thread);

            DkThreadExit(&g_clear_on_worker_exit);
            /* Unreachable. */
        }

        /* Reserve 2 slots for `interrupt_event` and ``. */
        const size_t reserved_slots = 2;
        size_t items_cnt = g_ipc_connections_cnt + reserved_slots;
        if (items_cnt != prev_items_cnt) {
            free(connections);
            free(handles);
            free(events);
            free(ret_events);

            connections = malloc(items_cnt * sizeof(*connections));
            handles = malloc(items_cnt * sizeof(*handles));
            events = malloc(items_cnt * sizeof(*events));
            ret_events = malloc(items_cnt * sizeof(*ret_events));
            if (!connections || !handles || !events || !ret_events) {
                log_error(LOG_PREFIX "arrays allocation failed\n");
                goto out_die;
            }

            prev_items_cnt = items_cnt;
        }

        memset(ret_events, 0, items_cnt * sizeof(*ret_events));

        connections[0] = NULL;
        handles[0] = event_handle(&interrupt_event);
        events[0] = PAL_WAIT_READ;
        connections[1] = NULL;
        handles[1] = g_self_ipc_handle;
        events[1] = PAL_WAIT_READ;

        struct shim_ipc_connection* conn;
        size_t i = reserved_slots;
        LISTP_FOR_EACH_ENTRY(conn, &g_ipc_connections, list) {
            connections[i] = conn;
            handles[i] = conn->handle;
            events[i] = PAL_WAIT_READ;
            /* `ret_events[i]` already cleared. */
            i++;
        }

        int ret = DkStreamsWaitEvents(items_cnt, handles, events, ret_events, NO_TIMEOUT);
        if (ret < 0) {
            if (ret == -PAL_ERROR_INTERRUPTED) {
                /* Generally speaking IPC worker should not be interrupted, but this happens with
                 * SGX exitless feature. */
                continue;
            }
            ret = pal_to_unix_errno(ret);
            log_error(LOG_PREFIX "DkStreamsWaitEvents failed: %d\n", ret);
            goto out_die;
        }

        if (ret_events[0]) {
            /* `interrupt_event`. */
            if (ret_events[0] & ~PAL_WAIT_READ) {
                log_error(LOG_PREFIX "unexpected event (%d) on interrupt handle\n", ret_events[0]);
                goto out_die;
            }
            log_debug(LOG_PREFIX "interrupt requested\n");
            /* XXX: Currently `interrupt_event` is used only for exit notification, no need to
             * actually clear it. */
        }

        if (ret_events[1]) {
            /* New connection incoming. */
            if (ret_events[1] & ~PAL_WAIT_READ) {
                log_error(LOG_PREFIX "unexpected event (%d) on listening handle\n", ret_events[1]);
                goto out_die;
            }
            PAL_HANDLE new_handle = NULL;
            ret = DkStreamWaitForClient(g_self_ipc_handle, &new_handle);
            if (ret < 0) {
                ret = pal_to_unix_errno(ret);
                log_error(LOG_PREFIX "DkStreamWaitForClient failed: %d\n", ret);
                goto out_die;
            }
            IDTYPE new_id = 0;
            ret = read_exact(new_handle, &new_id, sizeof(new_id));
            if (ret < 0) {
                // TODO: maybe just die here?
                log_error(LOG_PREFIX "receiving id failed: %d\n", ret);
                DkObjectClose(new_handle);
            } else {
                ret = add_ipc_connection(new_handle, new_id);
                if (ret < 0) {
                    log_error(LOG_PREFIX "add_ipc_connection failed: %d\n", ret);
                    goto out_die;
                }
            }
        }

        for (i = reserved_slots; i < items_cnt; i++) {
            conn = connections[i];
            if (ret_events[i] & PAL_WAIT_READ) {
                // TODO: what to do on errors? die or just delete connection?
                receive_ipc_messages(conn);
            }
            if (ret_events[i] & PAL_WAIT_ERROR) {
                disconnect_callbacks(conn);
                del_ipc_connection(conn);
            }
        }
    }

out_die:
    DkProcessExit(1);
}

static void ipc_worker_wrapper(void* arg) {
    __UNUSED(arg);
    assert(g_worker_thread);

    shim_tcb_init();
    set_cur_thread(g_worker_thread);

    log_setprefix(shim_get_tcb());

    // TODO; curently we have PAL provided stack = 64 pages

    log_debug("IPC worker started\n");
    ipc_worker_main();
    /* Unreachable. */
}

static int init_self_ipc_handle(void) {
    char uri[PIPE_URI_SIZE];
    return create_pipe(NULL, uri, sizeof(uri), &g_self_ipc_handle, NULL,
                       /*use_vmid_for_name=*/true);
}

static int create_ipc_worker(void) {
    int ret = init_self_ipc_handle();
    if (ret < 0) {
        return ret;
    }

    g_worker_thread = get_new_internal_thread();
    if (!g_worker_thread) {
        return -ENOMEM;
    }

    PAL_HANDLE handle = NULL;
    ret = DkThreadCreate(ipc_worker_wrapper, NULL, &handle);
    if (ret < 0) {
        put_thread(g_worker_thread);
        g_worker_thread = NULL;
        return pal_to_unix_errno(ret);
    }

    g_worker_thread->pal_handle = handle;

    return 0;
}

int init_ipc_worker(void) {
    int ret = create_event(&interrupt_event);
    if (ret < 0) {
        return ret;
    }

    enable_locking();
    return create_ipc_worker();
}

void terminate_ipc_worker(void) {
    __atomic_store_n(&g_time_to_exit, 1, __ATOMIC_SEQ_CST);
    set_event(&interrupt_event, 1);

    while (__atomic_load_n(&g_clear_on_worker_exit, __ATOMIC_RELAXED)) {
        CPU_RELAX();
    }

    put_thread(g_worker_thread);
    g_worker_thread = NULL;
    DkObjectClose(g_self_ipc_handle);
    g_self_ipc_handle = NULL;
}