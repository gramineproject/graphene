/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains code to create an IPC helper thread inside library OS and maintain bookkeeping
 * of IPC ports.
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
#include "shim_utils.h"

#define IPC_HELPER_STACK_SIZE (g_pal_alloc_align * 4)

static struct shim_lock ipc_port_mgr_lock;

#define SYSTEM_LOCK()   lock(&ipc_port_mgr_lock)
#define SYSTEM_UNLOCK() unlock(&ipc_port_mgr_lock)
#define SYSTEM_LOCKED() locked(&ipc_port_mgr_lock)

#define PORT_MGR_ALLOC 32
#define OBJ_TYPE       struct shim_ipc_port
#include "memmgr.h"
static MEM_MGR port_mgr;

DEFINE_LISTP(shim_ipc_port);
static LISTP_TYPE(shim_ipc_port) port_list;

static enum { HELPER_NOTALIVE, HELPER_STOPPED, HELPER_ALIVE } ipc_helper_state = HELPER_NOTALIVE;

static struct shim_thread* ipc_helper_thread;
static struct shim_lock ipc_helper_lock;

static AEVENTTYPE install_new_event;
static AEVENTTYPE helper_stopped_event;

static int create_ipc_helper(void);
static int ipc_resp_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

typedef int (*ipc_callback)(struct shim_ipc_msg* msg, struct shim_ipc_port* port);

static ipc_callback ipc_callbacks[] = {
    [IPC_MSG_RESP]          = &ipc_resp_callback,
    [IPC_MSG_CHILDEXIT]     = &ipc_cld_exit_callback,
    [IPC_MSG_FINDNS]        = &ipc_findns_callback,
    [IPC_MSG_TELLNS]        = &ipc_tellns_callback,
    [IPC_MSG_LEASE]         = &ipc_lease_callback,
    [IPC_MSG_OFFER]         = &ipc_offer_callback,
    [IPC_MSG_RENEW]         = &ipc_renew_callback,
    [IPC_MSG_SUBLEASE]      = &ipc_sublease_callback,
    [IPC_MSG_QUERY]         = &ipc_query_callback,
    [IPC_MSG_QUERYALL]      = &ipc_queryall_callback,
    [IPC_MSG_ANSWER]        = &ipc_answer_callback,
    [IPC_MSG_PID_KILL]      = &ipc_pid_kill_callback,
    [IPC_MSG_PID_GETSTATUS] = &ipc_pid_getstatus_callback,
    [IPC_MSG_PID_RETSTATUS] = &ipc_pid_retstatus_callback,
    [IPC_MSG_PID_GETMETA]   = &ipc_pid_getmeta_callback,
    [IPC_MSG_PID_RETMETA]   = &ipc_pid_retmeta_callback,
    [IPC_MSG_SYSV_FINDKEY]  = &ipc_sysv_findkey_callback,
    [IPC_MSG_SYSV_TELLKEY]  = &ipc_sysv_tellkey_callback,
    [IPC_MSG_SYSV_DELRES]   = &ipc_sysv_delres_callback,
    [IPC_MSG_SYSV_MOVRES]   = &ipc_sysv_movres_callback,
    [IPC_MSG_SYSV_MSGSND]   = &ipc_sysv_msgsnd_callback,
    [IPC_MSG_SYSV_MSGRCV]   = &ipc_sysv_msgrcv_callback,
    [IPC_MSG_SYSV_SEMOP]    = &ipc_sysv_semop_callback,
    [IPC_MSG_SYSV_SEMCTL]   = &ipc_sysv_semctl_callback,
    [IPC_MSG_SYSV_SEMRET]   = &ipc_sysv_semret_callback,
};

static int init_self_ipc_port(void) {
    lock(&g_process_ipc_info.lock);

    if (!g_process_ipc_info.self) {
        /* very first process or clone/fork case: create IPC port from scratch */
        g_process_ipc_info.self = create_ipc_info_and_port(/*use_vmid_as_port_name=*/true);
        if (!g_process_ipc_info.self) {
            unlock(&g_process_ipc_info.lock);
            return -EACCES;
        }
    } else {
        /* execve case: inherited IPC port from parent process */
        assert(g_process_ipc_info.self->pal_handle && !qstrempty(&g_process_ipc_info.self->uri));

        add_ipc_port_by_id(g_process_ipc_info.self->vmid, g_process_ipc_info.self->pal_handle,
                           IPC_PORT_LISTENING, /*fini=*/NULL, &g_process_ipc_info.self->port);
    }

    unlock(&g_process_ipc_info.lock);
    return 0;
}

static int init_parent_ipc_port(void) {
    if (!PAL_CB(parent_process) || !g_process_ipc_info.parent) {
        /* no parent process, no sense in creating parent IPC port */
        return 0;
    }

    lock(&g_process_ipc_info.lock);
    assert(g_process_ipc_info.parent && g_process_ipc_info.parent->vmid);

    /* for execve case, my parent is the parent of my parent (current process transparently inherits
     * the "real" parent through already opened pal_handle on "temporary" parent's
     * g_process_ipc_info.parent) */
    if (!g_process_ipc_info.parent->pal_handle) {
        /* for clone/fork case, parent is connected on parent_process */
        g_process_ipc_info.parent->pal_handle = PAL_CB(parent_process);
    }

    add_ipc_port_by_id(g_process_ipc_info.parent->vmid, g_process_ipc_info.parent->pal_handle,
                       IPC_PORT_CONNECTION | IPC_PORT_DIRECTPARENT, /*fini=*/NULL,
                       &g_process_ipc_info.parent->port);

    unlock(&g_process_ipc_info.lock);
    return 0;
}

static int init_ns_ipc_port(void) {
    if (!g_process_ipc_info.ns) {
        /* no NS info from parent process, no sense in creating NS IPC port */
        return 0;
    }

    if (!g_process_ipc_info.ns->pal_handle && qstrempty(&g_process_ipc_info.ns->uri)) {
        /* there is no connection to NS leader via PAL handle and there is no URI to find NS leader:
         * do not create NS IPC port now, it will be created on-demand during NS leader lookup */
        return 0;
    }

    lock(&g_process_ipc_info.lock);

    if (!g_process_ipc_info.ns->pal_handle) {
        debug("Reconnecting IPC port %s\n", qstrgetstr(&g_process_ipc_info.ns->uri));
        g_process_ipc_info.ns->pal_handle = DkStreamOpen(qstrgetstr(&g_process_ipc_info.ns->uri),
                                                         0, 0, 0, 0);
        if (!g_process_ipc_info.ns->pal_handle) {
            unlock(&g_process_ipc_info.lock);
            return -PAL_ERRNO();
        }
    }

    add_ipc_port_by_id(g_process_ipc_info.ns->vmid, g_process_ipc_info.ns->pal_handle,
                       IPC_PORT_CONNECTION, /*fini=*/NULL, &g_process_ipc_info.ns->port);

    unlock(&g_process_ipc_info.lock);
    return 0;
}

int init_ipc_ports(void) {
    if (!create_lock(&ipc_port_mgr_lock)) {
        return -ENOMEM;
    }

    if (!(port_mgr = create_mem_mgr(init_align_up(PORT_MGR_ALLOC))))
        return -ENOMEM;

    int ret;
    if ((ret = init_self_ipc_port()) < 0)
        return ret;
    if ((ret = init_parent_ipc_port()) < 0)
        return ret;
    if ((ret = init_ns_ipc_port()) < 0)
        return ret;

    return 0;
}

int init_ipc_helper(void) {
    if (!create_lock(&ipc_helper_lock)) {
        return -ENOMEM;
    }

    int ret = create_event(&install_new_event);
    if (ret < 0) {
        return ret;
    }
    ret = create_event(&helper_stopped_event);
    if (ret < 0) {
        return ret;
    }

    /* some IPC ports were already added before this point, so spawn IPC helper thread (and enable
     * locking mechanisms if not done already since we are going in multi-threaded mode) */
    enable_locking();
    lock(&ipc_helper_lock);
    ret = create_ipc_helper();
    unlock(&ipc_helper_lock);

    return ret;
}

static struct shim_ipc_port* __create_ipc_port(PAL_HANDLE hdl) {
    struct shim_ipc_port* port =
        get_mem_obj_from_mgr_enlarge(port_mgr, size_align_up(PORT_MGR_ALLOC));
    if (!port)
        return NULL;

    memset(port, 0, sizeof(struct shim_ipc_port));
    port->pal_handle = hdl;
    INIT_LIST_HEAD(port, list);
    INIT_LISTP(&port->msgs);
    REF_SET(port->ref_count, 1);
    if (!create_lock(&port->msgs_lock)) {
        free_mem_obj_to_mgr(port_mgr, port);
        return NULL;
    }
    return port;
}

static void __free_ipc_port(struct shim_ipc_port* port) {
    assert(locked(&ipc_helper_lock));

    if (port->pal_handle) {
        DkObjectClose(port->pal_handle);
        port->pal_handle = NULL;
    }

    destroy_lock(&port->msgs_lock);
    free_mem_obj_to_mgr(port_mgr, port);
}

static void __get_ipc_port(struct shim_ipc_port* port) {
    REF_INC(port->ref_count);
}

static void __put_ipc_port(struct shim_ipc_port* port) {
    assert(locked(&ipc_helper_lock));

    int ref_count = REF_DEC(port->ref_count);
    if (!ref_count)
        __free_ipc_port(port);
}

void get_ipc_port(struct shim_ipc_port* port) {
    /* no need to grab ipc_helper_lock because __get_ipc_port() does not touch global state */
    __get_ipc_port(port);
}

void put_ipc_port(struct shim_ipc_port* port) {
    /* this is atomic so we don't grab lock in common case of ref_count > 0 */
    int ref_count = REF_DEC(port->ref_count);

    if (!ref_count) {
        lock(&ipc_helper_lock);
        __free_ipc_port(port);
        unlock(&ipc_helper_lock);
    }
}

static void __add_ipc_port(struct shim_ipc_port* port, IDTYPE vmid, IDTYPE type, port_fini fini) {
    assert(locked(&ipc_helper_lock));

    port->type |= type;
    if (vmid && !port->vmid)
        port->vmid = vmid;

    /* find empty slot in fini callbacks and register callback */
    if (fini) {
        bool found_empty_slot = false;
        __UNUSED(found_empty_slot);
        for (int i = 0; i < MAX_IPC_PORT_FINI_CB; i++)
            if (!port->fini[i] || port->fini[i] == fini) {
                port->fini[i]    = fini;
                found_empty_slot = true;
                break;
            }
        assert(found_empty_slot);
    }

    /* add to port list if not there already */
    if (LIST_EMPTY(port, list)) {
        __get_ipc_port(port);
        LISTP_ADD(port, &port_list, list);
    }

    /* wake up IPC helper thread so that it picks up added port */
    if (ipc_helper_state == HELPER_ALIVE)
        set_event(&install_new_event, 1);
}

static void __del_ipc_port(struct shim_ipc_port* port) {
    assert(locked(&ipc_helper_lock));

    debug("Deleting port %p (handle %p) of process %u\n", port, port->pal_handle,
          port->vmid & 0xFFFF);

    DkStreamDelete(port->pal_handle, 0);
    LISTP_DEL_INIT(port, &port_list, list);

    /* Check for pending messages on port (threads might be blocking for responses) */
    lock(&port->msgs_lock);
    struct shim_ipc_msg_with_ack* msg;
    struct shim_ipc_msg_with_ack* tmp;
    LISTP_FOR_EACH_ENTRY_SAFE(msg, tmp, &port->msgs, list) {
        LISTP_DEL_INIT(msg, &port->msgs, list);
        msg->retval = -ECONNRESET;
        if (msg->thread) {
            debug("Deleted pending message on port %p, wake up blocking thread %d\n", port,
                  msg->thread->tid);
            thread_wakeup(msg->thread);
        }
    }
    unlock(&port->msgs_lock);

    __put_ipc_port(port);

    /* wake up IPC helper thread so that it forgets about deleted port */
    if (ipc_helper_state == HELPER_ALIVE)
        set_event(&install_new_event, 1);
}

void add_ipc_port(struct shim_ipc_port* port, IDTYPE vmid, IDTYPE type, port_fini fini) {
    debug("Adding port %p (handle %p) for process %u (type=%04x)\n", port, port->pal_handle,
          port->vmid & 0xFFFF, type);

    lock(&ipc_helper_lock);
    __add_ipc_port(port, vmid, type, fini);
    unlock(&ipc_helper_lock);
}

void add_ipc_port_by_id(IDTYPE vmid, PAL_HANDLE hdl, IDTYPE type, port_fini fini,
                        struct shim_ipc_port** portptr) {
    debug("Adding port (handle %p) for process %u (type %04x)\n", hdl, vmid & 0xFFFF, type);

    struct shim_ipc_port* port = NULL;
    if (portptr)
        *portptr = NULL;

    assert(hdl);
    lock(&ipc_helper_lock);

    /* check if port with this PAL handle already exists, then we only need to update its vmid,
     * type, and fini callback */
    struct shim_ipc_port* tmp;
    LISTP_FOR_EACH_ENTRY(tmp, &port_list, list) {
        if (tmp->pal_handle == hdl) {
            port = tmp;
            break;
        }
    }

    if (!port) {
        /* port does not yet exist, create it */
        port = __create_ipc_port(hdl);
        if (!port) {
            debug("Failed to create IPC port for handle %p\n", hdl);
            goto out;
        }
    }

    /* add/update port */
    __add_ipc_port(port, vmid, type, fini);

    if (portptr) {
        *portptr = port;
    } else {
        __put_ipc_port(port);
    }

out:
    unlock(&ipc_helper_lock);
}

void del_ipc_port_fini(struct shim_ipc_port* port) {
    lock(&ipc_helper_lock);

    if (LIST_EMPTY(port, list)) {
        unlock(&ipc_helper_lock);
        return;
    }

    /* prevent __del_ipc_port() from freeing port since we need it for fini callbacks */
    __get_ipc_port(port);
    __del_ipc_port(port);

    unlock(&ipc_helper_lock);

    for (int i = 0; i < MAX_IPC_PORT_FINI_CB; i++)
        if (port->fini[i]) {
            (port->fini[i])(port, port->vmid);
            port->fini[i] = NULL;
        }

    put_ipc_port(port);
}

void del_all_ipc_ports(void) {
    lock(&ipc_helper_lock);

    struct shim_ipc_port* port;
    struct shim_ipc_port* tmp;
    LISTP_FOR_EACH_ENTRY_SAFE(port, tmp, &port_list, list) {
        __del_ipc_port(port);
    }

    unlock(&ipc_helper_lock);
}

struct shim_ipc_port* lookup_ipc_port(IDTYPE vmid, IDTYPE type) {
    struct shim_ipc_port* port = NULL;

    assert(vmid && type);
    lock(&ipc_helper_lock);

    struct shim_ipc_port* tmp;
    LISTP_FOR_EACH_ENTRY(tmp, &port_list, list) {
        if (tmp->vmid == vmid && (tmp->type & type)) {
            debug("Found port %p (handle %p) for process %u (type %04x)\n", tmp, tmp->pal_handle,
                  tmp->vmid & 0xFFFF, tmp->type);
            port = tmp;
            __get_ipc_port(port);
            break;
        }
    }

    unlock(&ipc_helper_lock);
    return port;
}

#define PORTS_ON_STACK_CNT 32

int broadcast_ipc(struct shim_ipc_msg* msg, int target_type, struct shim_ipc_port* exclude_port) {
    int ret;
    struct shim_ipc_port* port;
    struct shim_ipc_port** target_ports;
    size_t target_ports_cnt = 0;

    assert(target_type);
    lock(&ipc_helper_lock);

    /* Collect all ports with appropriate types. In common case, stack-allocated array of
     * PORTS_ON_STACK_CNT ports is enough. If there are more ports, we will allocate a bigger array
     * on the heap and collect all ports again. */
    struct shim_ipc_port* target_ports_stack[PORTS_ON_STACK_CNT];
    LISTP_FOR_EACH_ENTRY(port, &port_list, list) {
        if (port == exclude_port)
            continue;
        if (port->type & target_type) {
            if (target_ports_cnt < PORTS_ON_STACK_CNT)
                target_ports_stack[target_ports_cnt] = port;
            target_ports_cnt++;
        }
    }
    target_ports = target_ports_stack;

    if (target_ports_cnt > PORTS_ON_STACK_CNT) {
        /* Rare case when there are more than PORTS_ON_STACK_CNT ports. Allocate big-enough array on
         * the heap and collect all ports again. */
        size_t cnt = 0;
        struct shim_ipc_port** target_ports_heap =
            malloc(sizeof(struct shim_ipc_port*) * target_ports_cnt);
        if (!target_ports_heap) {
            unlock(&ipc_helper_lock);
            debug("Allocation of target_ports_heap failed\n");
            return -ENOMEM;
        }

        LISTP_FOR_EACH_ENTRY(port, &port_list, list) {
            if (port == exclude_port)
                continue;
            if (port->type & target_type)
                target_ports_heap[cnt++] = port;
        }
        target_ports = target_ports_heap;
        assert(cnt == target_ports_cnt);
    }

    for (size_t i = 0; i < target_ports_cnt; i++)
        __get_ipc_port(target_ports[i]);

    unlock(&ipc_helper_lock);

    /* send msg to each collected port (note that ports cannot be freed in meantime) */
    for (size_t i = 0; i < target_ports_cnt; i++) {
        port = target_ports[i];

        debug("Broadcast to port %p (handle %p) for process %u (type %x, target %x)\n", port,
              port->pal_handle, port->vmid & 0xFFFF, port->type, target_type);

        msg->dst = port->vmid;
        ret = send_ipc_message(msg, port);
        if (ret < 0) {
            debug("Broadcast to port %p (handle %p) for process %u failed (errno = %d)!\n", port,
                  port->pal_handle, port->vmid & 0xFFFF, ret);
            goto out;
        }
    }

    ret = 0;
out:
    for (size_t i = 0; i < target_ports_cnt; i++)
        put_ipc_port(target_ports[i]);
    if (target_ports != target_ports_stack)
        free(target_ports);
    return ret;
}

static int ipc_resp_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_resp* resp = (struct shim_ipc_resp*)&msg->msg;
    debug("IPC callback from %u: IPC_MSG_RESP(%d)\n", msg->src & 0xFFFF, resp->retval);

    if (!msg->seq)
        return resp->retval;

    /* find a corresponding request msg for this response msg */
    struct shim_ipc_msg_with_ack* req_msg = pop_ipc_msg_with_ack(port, msg->seq);

    /* if some thread is waiting for response, wake it with response retval */
    if (req_msg) {
        req_msg->retval = resp->retval;
        if (req_msg->thread)
            thread_wakeup(req_msg->thread);
        return 0;
    }

    return resp->retval;
}

int send_response_ipc_message(struct shim_ipc_port* port, IDTYPE dest, int ret, unsigned long seq) {
    ret = (ret == RESPONSE_CALLBACK) ? 0 : ret;

    /* create IPC_MSG_RESP msg to send to dest, with sequence number seq, and in-body retval ret */
    size_t total_msg_size = get_ipc_msg_size(sizeof(struct shim_ipc_resp));
    struct shim_ipc_msg* resp_msg = __alloca(total_msg_size);
    init_ipc_msg(resp_msg, IPC_MSG_RESP, total_msg_size, dest);
    resp_msg->seq = seq;

    struct shim_ipc_resp* resp = (struct shim_ipc_resp*)resp_msg->msg;
    resp->retval = ret;

    debug("IPC send to %u: IPC_MSG_RESP(%d)\n", resp_msg->dst & 0xFFFF, ret);
    return send_ipc_message(resp_msg, port);
}

static int receive_ipc_message(struct shim_ipc_port* port) {
    int ret;
    size_t readahead = IPC_MSG_MINIMAL_SIZE * 2;
    size_t bufsize = IPC_MSG_MINIMAL_SIZE + readahead;

    struct shim_ipc_msg* msg = malloc(bufsize);
    if (!msg) {
        return -ENOMEM;
    }
    size_t expected_size = IPC_MSG_MINIMAL_SIZE;
    size_t bytes = 0;

    do {
        while (bytes < expected_size) {
            /* grow msg buffer to accommodate bigger messages */
            if (expected_size + readahead > bufsize) {
                while (expected_size + readahead > bufsize)
                    bufsize *= 2;
                void* tmp_buf = malloc(bufsize);
                if (!tmp_buf) {
                    ret = -ENOMEM;
                    goto out;
                }
                memcpy(tmp_buf, msg, bytes);
                free(msg);
                msg = tmp_buf;
            }

            PAL_NUM read =
                DkStreamRead(port->pal_handle, /*offset=*/0, expected_size - bytes + readahead,
                             (void*)msg + bytes, NULL, 0);

            if (read == PAL_STREAM_ERROR) {
                if (PAL_ERRNO() == EINTR || PAL_ERRNO() == EAGAIN || PAL_ERRNO() == EWOULDBLOCK)
                    continue;

                debug("Port %p (handle %p) closed while receiving IPC message\n", port,
                      port->pal_handle);
                del_ipc_port_fini(port);
                ret = -PAL_ERRNO();
                goto out;
            }

            bytes += read;

            /* extract actual msg size from msg header and continue reading msg body */
            if (bytes >= IPC_MSG_MINIMAL_SIZE)
                expected_size = msg->size;
        }

        debug(
            "Received IPC message from port %p (handle %p): code=%d size=%lu "
            "src=%u dst=%u seq=%lx\n",
            port, port->pal_handle, msg->code, msg->size, msg->src & 0xFFFF, msg->dst & 0xFFFF,
            msg->seq);

        /* skip messages coming from myself (in case of broadcast) */
        if (msg->src != g_process_ipc_info.vmid) {
            if (msg->code < IPC_MSG_CODE_BOUND && ipc_callbacks[msg->code]) {
                /* invoke callback to this msg */
                ret = (*ipc_callbacks[msg->code])(msg, port);
                if ((ret < 0 || ret == RESPONSE_CALLBACK) && msg->seq) {
                    /* send IPC_MSG_RESP message to sender of this msg */
                    ret = send_response_ipc_message(port, msg->src, ret, msg->seq);
                    if (ret < 0) {
                        debug("Sending IPC_MSG_RESP msg on port %p (handle %p) to %u failed\n",
                              port, port->pal_handle, msg->src & 0xFFFF);
                        ret = -PAL_ERRNO();
                        goto out;
                    }
                }
            }
        }

        bytes -= expected_size; /* one message was received and handled */

        if (bytes > 0) {
            /* we may have started reading the next message, move this message to beginning of msg
             * buffer and reset expected size */
            memmove(msg, (void*)msg + expected_size, bytes);
            expected_size = IPC_MSG_MINIMAL_SIZE;
            if (bytes >= IPC_MSG_MINIMAL_SIZE)
                expected_size = msg->size;
        }
    } while (bytes > 0);

    ret = 0;
out:
    free(msg);
    return ret;
}

int pause_ipc_helper(void) {
    bool needs_wait = false;

    lock(&ipc_helper_lock);
    if (ipc_helper_state == HELPER_ALIVE) {
        ipc_helper_state = HELPER_STOPPED;

        int ret = clear_event(&helper_stopped_event);
        if (ret < 0) {
            unlock(&ipc_helper_lock);
            return ret;
        }
        needs_wait = true;

        /* Wake up the helper thread, so that it notices `ipc_helper_state` change. */
        ret = set_event(&install_new_event, 1);
        if (ret < 0) {
            unlock(&ipc_helper_lock);
            return ret;
        }
    }
    unlock(&ipc_helper_lock);

    if (needs_wait) {
        /* Wait until the helper thread notices the stop event. */
        return wait_event(&helper_stopped_event);
    }

    return 0;
}

int resume_ipc_helper(void) {
    int ret = 0;
    lock(&ipc_helper_lock);
    if (ipc_helper_state == HELPER_STOPPED) {
        ipc_helper_state = HELPER_ALIVE;
        ret = set_event(&install_new_event, 1);
    }
    unlock(&ipc_helper_lock);
    return ret;
}

/* Main routine of the IPC helper thread. IPC helper thread is spawned when the first IPC port is
 * added and is terminated only when the whole Graphene application terminates. IPC helper thread
 * runs in an endless loop and waits on port events (either the addition/removal of ports or actual
 * port events: acceptance of new client or receiving/sending messages). In particular, IPC helper
 * thread calls receive_ipc_message() if a message arrives on port.
 *
 * Other threads add and remove IPC ports via add_ipc_xxx() and del_ipc_xxx() functions. These ports
 * are added to port_list which the IPC helper thread consults before each DkStreamsWaitEvents().
 *
 * Note that ports are copied from global port_list to local object_list. This is because ports may
 * be removed from port_list by other threads while IPC helper thread is waiting on
 * DkStreamsWaitEvents(). For this reason IPC thread also get references to all current ports and
 * puts them after handling all ports in object_list.
 *
 * Previous implementation went to great lengths to keep changes to the list of current ports to a
 * minimum (instead of repopulating the list before each wait like in current code). Unfortunately,
 * this resulted in undue complexity. Current implementation should perform fine for usual case of
 * <100 IPC ports and with IPC helper thread always running in background on its own core.
 */
noreturn static void shim_ipc_helper(void* dummy) {
    __UNUSED(dummy);
    struct shim_thread* self = get_cur_thread();

    /* Initialize two lists:
     * - `ports` collects IPC port objects and is the main list we process here
     * - `pals` collects PAL handles of IPC port objects; always contains install_new_event */
    size_t ports_cnt = 0;
    size_t ports_max_cnt = 32;
    struct shim_ipc_port** ports = malloc(sizeof(*ports) * ports_max_cnt);
    if (!ports) {
        debug("shim_ipc_helper: allocation of ports failed\n");
        goto out_err;
    }
    PAL_HANDLE* pals = malloc(sizeof(*pals) * (1 + ports_max_cnt));
    if (!pals) {
        debug("shim_ipc_helper: allocation of pals failed\n");
        goto out_err;
    }

    /* allocate one memory region to hold two PAL_FLG arrays: events and revents */
    PAL_FLG* pal_events = malloc(sizeof(*pal_events) * (1 + ports_max_cnt) * 2);
    if (!pal_events) {
        debug("shim_ipc_helper: allocation of pal_events failed\n");
        goto out_err;
    }
    PAL_FLG* ret_events = pal_events + 1 + ports_max_cnt;

    PAL_HANDLE install_new_event_pal = event_handle(&install_new_event);
    pals[0]       = install_new_event_pal;
    pal_events[0] = PAL_WAIT_READ;
    ret_events[0] = 0;

    while (true) {
        lock(&ipc_helper_lock);

        if (clear_event(&install_new_event) < 0) {
            goto out_err_unlock;
        }

        if (ipc_helper_state == HELPER_NOTALIVE) {
            ipc_helper_thread = NULL;
            unlock(&ipc_helper_lock);
            break;
        } else if (ipc_helper_state == HELPER_STOPPED) {
            if (set_event(&helper_stopped_event, 1) < 0) {
                goto out_err_unlock;
            }
            unlock(&ipc_helper_lock);
            if (wait_event(&install_new_event) < 0) {
                goto out_err;
            }
            continue;
        }

        /* iterate through all known ports from `port_list` to repopulate `ports` */
        ports_cnt = 0;
        struct shim_ipc_port* port;
        struct shim_ipc_port* tmp;
        LISTP_FOR_EACH_ENTRY_SAFE(port, tmp, &port_list, list) {
            /* get port reference so it is not freed while we wait on/handle it */
            __get_ipc_port(port);

            if (ports_cnt == ports_max_cnt) {
                /* grow `ports` and `pals` to accommodate more objects */
                struct shim_ipc_port** tmp_ports = malloc(sizeof(*tmp_ports) * ports_max_cnt * 2);
                if (!tmp_ports) {
                    debug("shim_ipc_helper: allocation of tmp_ports failed\n");
                    goto out_err_unlock;
                }
                PAL_HANDLE* tmp_pals = malloc(sizeof(*tmp_pals) * (1 + ports_max_cnt * 2));
                if (!tmp_pals) {
                    debug("shim_ipc_helper: allocation of tmp_pals failed\n");
                    goto out_err_unlock;
                }
                PAL_FLG* tmp_pal_events = malloc(sizeof(*tmp_pal_events) * (2 + ports_max_cnt * 4));
                if (!tmp_pal_events) {
                    debug("shim_ipc_helper: allocation of tmp_pal_events failed\n");
                    goto out_err_unlock;
                }
                PAL_FLG* tmp_ret_events = tmp_pal_events + 1 + ports_max_cnt * 2;

                memcpy(tmp_ports, ports, sizeof(*tmp_ports) * ports_max_cnt);
                memcpy(tmp_pals, pals, sizeof(*tmp_pals) * (1 + ports_max_cnt));
                memcpy(tmp_pal_events, pal_events, sizeof(*tmp_pal_events) * (1 + ports_max_cnt));
                memcpy(tmp_ret_events, ret_events, sizeof(*tmp_ret_events) * (1 + ports_max_cnt));

                ports_max_cnt *= 2;

                free(ports);
                free(pals);
                free(pal_events);

                ports      = tmp_ports;
                pals       = tmp_pals;
                pal_events = tmp_pal_events;
                ret_events = tmp_ret_events;
            }

            /* re-add this port to ports/pals/events */
            ports[ports_cnt]          = port;
            pals[ports_cnt + 1]       = port->pal_handle;
            pal_events[ports_cnt + 1] = PAL_WAIT_READ;
            ret_events[ports_cnt + 1] = 0;
            ports_cnt++;

            debug("Listening to process %u on port %p (handle %p, type %04x)\n",
                  port->vmid & 0xFFFF, port, port->pal_handle, port->type);
        }

        unlock(&ipc_helper_lock);

        /* wait on collected ports' PAL handles + install_new_event_pal */
        PAL_BOL polled = DkStreamsWaitEvents(ports_cnt + 1, pals, pal_events, ret_events,
                                             NO_TIMEOUT);

        for (size_t i = 0; polled && i < ports_cnt + 1; i++) {
            if (ret_events[i]) {
                if (pals[i] == install_new_event_pal) {
                    /* some thread wants to install new event; this event is found in `ports` */
                    debug("New IPC event was requested (port was added/removed)\n");
                    continue;
                }

                /* it is not install_new_event handle, so must be one of ports */
                assert(i > 0);
                struct shim_ipc_port* polled_port = ports[i - 1];
                assert(polled_port);

                if (polled_port->type & IPC_PORT_LISTENING) {
                    /* listening port: accept client, create port, and add it to port list */
                    PAL_HANDLE client = DkStreamWaitForClient(polled_port->pal_handle);
                    if (client) {
                        IDTYPE client_type = (polled_port->type & ~IPC_PORT_LISTENING) |
                                             IPC_PORT_CONNECTION;
                        add_ipc_port_by_id(polled_port->vmid, client, client_type, NULL, NULL);
                    } else {
                        debug("Port %p (handle %p) was removed during accepting client\n",
                              polled_port, polled_port->pal_handle);
                        del_ipc_port_fini(polled_port);
                    }
                } else {
                    PAL_STREAM_ATTR attr;
                    if (DkStreamAttributesQueryByHandle(polled_port->pal_handle, &attr)) {
                        /* can read on this port, so receive messages */
                        if (attr.readable) {
                            /* NOTE: IPC helper thread does not handle failures currently */
                            receive_ipc_message(polled_port);
                        }
                        if (attr.disconnected) {
                            debug("Port %p (handle %p) disconnected\n", polled_port,
                                  polled_port->pal_handle);
                            del_ipc_port_fini(polled_port);
                        }
                    } else {
                        debug("Port %p (handle %p) was removed during attr querying\n", polled_port,
                              polled_port->pal_handle);
                        del_ipc_port_fini(polled_port);
                    }
                }
            }
        }

        /* done handling ports; put their references so they can be freed */
        for (size_t i = 0; i < ports_cnt; i++)
            put_ipc_port(ports[i]);
    }

    free(ports);
    free(pals);
    free(pal_events);

    __disable_preempt(self->shim_tcb);
    put_thread(self);
    debug("IPC helper thread terminated\n");

    DkThreadExit(/*clear_child_tid=*/NULL);
    /* UNREACHABLE */

out_err_unlock:
    unlock(&ipc_helper_lock);
out_err:
    debug("Terminating the process due to a fatal error in ipc helper\n");
    put_thread(self);
    DkProcessExit(1);
}

static void shim_ipc_helper_prepare(void* arg) {
    struct shim_thread* self = (struct shim_thread*)arg;
    if (!arg)
        return;

    shim_tcb_init();
    set_cur_thread(self);
    update_tls_base(0);

    struct debug_buf debug_buf;
    (void)debug_setbuf(shim_get_tcb(), &debug_buf);

#ifdef DEBUG
    lock(&ipc_helper_lock);
    assert(self == ipc_helper_thread);
    unlock(&ipc_helper_lock);
#endif // DEBUG

    void* stack = allocate_stack(IPC_HELPER_STACK_SIZE, g_pal_alloc_align, false);

    if (!stack) {
        put_thread(self);
        DkThreadExit(/*clear_child_tid=*/NULL);
        /* UNREACHABLE */
    }

    debug("IPC helper thread started\n");

    /* swap stack to be sure we don't drain the small stack PAL provides */
    self->stack_top = stack + IPC_HELPER_STACK_SIZE;
    self->stack     = stack;
    __SWITCH_STACK(self->stack_top, shim_ipc_helper, NULL);
    /* UNREACHABLE */
}

/* this should be called with the ipc_helper_lock held */
static int create_ipc_helper(void) {
    assert(locked(&ipc_helper_lock));
    assert(ipc_helper_state == HELPER_NOTALIVE);

    struct shim_thread* new = get_new_internal_thread();
    if (!new)
        return -ENOMEM;

    ipc_helper_thread = new;
    ipc_helper_state  = HELPER_ALIVE;

    PAL_HANDLE handle = DkThreadCreate(shim_ipc_helper_prepare, new);

    if (!handle) {
        int ret = -PAL_ERRNO(); /* put_thread() may overwrite errno */
        ipc_helper_thread = NULL;
        ipc_helper_state  = HELPER_NOTALIVE;
        put_thread(new);
        return ret;
    }

    new->pal_handle = handle;
    return 0;
}

/* On success, the reference to ipc helper thread is returned with refcount incremented. It is the
 * responsibility of caller to wait for ipc helper's exit and then release the final reference to
 * free related resources (it is problematic for the thread itself to release its own resources e.g.
 * stack).
 */
struct shim_thread* terminate_ipc_helper(void) {
    /* First check if thread is alive. */
    lock(&ipc_helper_lock);
    if (ipc_helper_state == HELPER_NOTALIVE) {
        unlock(&ipc_helper_lock);
        return NULL;
    }
    unlock(&ipc_helper_lock);

    /* NOTE: Graphene doesn't have an abstraction of a queue of pending signals between
     * communicating processes (instead all communication is done over streams). Thus, app code like
     * this (found in e.g. Lmbench's bw_unix):
     *     kill(child, SIGKILL);
     *     exit(0);
     * results in a data race between the SIGKILL message sent over IPC stream and the parent
     * process exiting. In the worst case, the parent will exit before the SIGKILL message goes
     * through the host-OS stream, the host OS will close the stream, and the message will never be
     * seen by child. To prevent such cases, we simply wait for a bit before exiting.
     */
    debug("Waiting for 0.5s for all in-flight IPC messages to reach their destinations\n");
    DkThreadDelayExecution(500000); /* in microseconds */

    lock(&ipc_helper_lock);
    if (ipc_helper_state == HELPER_NOTALIVE) {
        unlock(&ipc_helper_lock);
        return NULL;
    }

    struct shim_thread* ret = ipc_helper_thread;
    if (ret)
        get_thread(ret);
    ipc_helper_state = HELPER_NOTALIVE;

    /* force wake up of ipc helper thread so that it exits */
    set_event(&install_new_event, 1);

    unlock(&ipc_helper_lock);
    return ret;
}
