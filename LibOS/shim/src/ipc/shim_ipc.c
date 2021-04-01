/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains code to maintain generic bookkeeping of IPC: operations on shim_ipc_msg
 * (one-way IPC messages), shim_ipc_msg_with_ack (IPC messages with acknowledgement).
 */

#include "list.h"
#include "pal.h"
#include "pal_error.h"
#include "shim_checkpoint.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_lock.h"
#include "shim_thread.h"
#include "shim_types.h"
#include "shim_utils.h"

struct shim_process_ipc_info g_process_ipc_info;

int init_ipc(void) {
    int ret = 0;

    if ((ret = init_ipc_ports()) < 0)
        return ret;
    if ((ret = init_ns_ranges()) < 0)
        return ret;
    if ((ret = init_ns_sysv()) < 0)
        return ret;

    return 0;
}

void init_ipc_msg(struct shim_ipc_msg* msg, int code, size_t size, IDTYPE dest) {
    msg->code = code;
    msg->size = get_ipc_msg_size(size);
    msg->src  = g_process_ipc_info.vmid;
    msg->dst  = dest;
    msg->seq  = 0;
}

void init_ipc_msg_with_ack(struct shim_ipc_msg_with_ack* msg, int code, size_t size, IDTYPE dest) {
    init_ipc_msg(&msg->msg, code, size, dest);
    msg->thread = NULL;
    INIT_LIST_HEAD(msg, list);
    msg->retval  = 0;
    msg->private = NULL;
}

int send_ipc_message(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    assert(msg->size >= IPC_MSG_MINIMAL_SIZE);

    msg->src = g_process_ipc_info.vmid;
    log_debug("Sending ipc message to port %p (handle %p)\n", port, port->pal_handle);

    size_t total_bytes = msg->size;
    size_t bytes       = 0;

    do {
        size_t size = total_bytes - bytes;
        int ret = DkStreamWrite(port->pal_handle, 0, &size, (void*)msg + bytes, NULL);

        if (ret < 0 || size == 0) {
            if (ret == -PAL_ERROR_INTERRUPTED || ret == -PAL_ERROR_TRYAGAIN) {
                continue;
            }
            if (ret == 0) {
                assert(size == 0);
                ret = -EINVAL;
            } else {
                ret = pal_to_unix_errno(ret);
            }

            log_debug("Port %p (handle %p) was removed during sending\n", port, port->pal_handle);
            del_ipc_port_fini(port);
            return ret;
        }

        bytes += size;
    } while (bytes < total_bytes);

    return 0;
}

struct shim_ipc_msg_with_ack* pop_ipc_msg_with_ack(struct shim_ipc_port* port, unsigned long seq) {
    struct shim_ipc_msg_with_ack* found = NULL;

    lock(&port->msgs_lock);
    struct shim_ipc_msg_with_ack* tmp;
    LISTP_FOR_EACH_ENTRY(tmp, &port->msgs, list) {
        if (tmp->msg.seq == seq) {
            found = tmp;
            LISTP_DEL_INIT(tmp, &port->msgs, list);
            break;
        }
    }
    unlock(&port->msgs_lock);

    return found;
}

int send_ipc_message_with_ack(struct shim_ipc_msg_with_ack* msg, struct shim_ipc_port* port,
                              unsigned long* seq, void* private_data) {
    int ret = 0;

    struct shim_thread* thread = get_cur_thread();
    assert(thread);

    /* prepare thread which will send the message for waiting for response
     * (this also acquires reference to the thread) */
    if (!msg->thread)
        thread_setwait(&msg->thread, thread);

    static struct atomic_int ipc_seq_counter;
    msg->msg.seq = __atomic_add_fetch(&ipc_seq_counter.counter, 1, __ATOMIC_SEQ_CST);

    /* save the message to list of port msgs together with its private data */
    lock(&port->msgs_lock);
    msg->private = private_data;
    LISTP_ADD_TAIL(msg, &port->msgs, list);
    unlock(&port->msgs_lock);

    ret = send_ipc_message(&msg->msg, port);
    if (ret < 0)
        goto out;

    if (seq)
        *seq = msg->msg.seq;

    log_debug("Waiting for response (seq = %lu)\n", msg->msg.seq);

    /* force thread which will send the message to wait for response;
     * ignore unrelated interrupts but fail on actual errors */
    do {
        ret = thread_sleep(NO_TIMEOUT, /*ignore_pending_signals=*/true);
        if (ret < 0 && ret != -EINTR && ret != -EAGAIN)
            goto out;
    } while (ret != 0);

    log_debug("Finished waiting for response (seq = %lu, ret = %d)\n", msg->msg.seq, msg->retval);
    ret = msg->retval;
out:
    lock(&port->msgs_lock);
    if (!LIST_EMPTY(msg, list))
        LISTP_DEL_INIT(msg, &port->msgs, list);
    unlock(&port->msgs_lock);

    if (msg->thread) {
        /* put reference to the thread acquired earlier */
        put_thread(msg->thread);
        msg->thread = NULL;
    }

    return ret;
}

BEGIN_CP_FUNC(process_ipc_data) {
    __UNUSED(size);
    __UNUSED(objp);
    assert(size == sizeof(struct shim_ipc_cp_data));

    struct shim_ipc_cp_data* ipc_cp_data = (struct shim_ipc_cp_data*)obj;

    size_t off = ADD_CP_OFFSET(sizeof(*ipc_cp_data));
    ADD_CP_FUNC_ENTRY(off);

    *(struct shim_ipc_cp_data*)(base + off) = *ipc_cp_data;
}
END_CP_FUNC(process_ipc_data)

BEGIN_RS_FUNC(process_ipc_data) {
    __UNUSED(offset);
    __UNUSED(rebase);
    struct shim_ipc_cp_data* ipc_cp_data = (void*)(base + GET_CP_FUNC_ENTRY());

    g_process_ipc_info.ipc_cp_data = *ipc_cp_data;
}
END_RS_FUNC(process_ipc_data)
