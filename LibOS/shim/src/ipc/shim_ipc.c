/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains code to maintain generic bookkeeping of IPC: operations on shim_ipc_msg
 * (one-way IPC messages), shim_ipc_msg_with_ack (IPC messages with acknowledgement), shim_ipc_info
 * (IPC ports of process).
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

static struct shim_lock ipc_info_mgr_lock;

#define SYSTEM_LOCK()   lock(&ipc_info_mgr_lock)
#define SYSTEM_UNLOCK() unlock(&ipc_info_mgr_lock)
#define SYSTEM_LOCKED() locked(&ipc_info_mgr_lock)

#define IPC_INFO_MGR_ALLOC 32
#define OBJ_TYPE           struct shim_ipc_info
#include "memmgr.h"
static MEM_MGR ipc_info_mgr;

struct shim_lock ipc_info_lock;

struct shim_process_ipc_info g_process_ipc_info;

#define CLIENT_HASH_BITLEN 6
#define CLIENT_HASH_NUM    (1 << CLIENT_HASH_BITLEN)
#define CLIENT_HASH_MASK   (CLIENT_HASH_NUM - 1)
#define CLIENT_HASH(vmid)  ((vmid)&CLIENT_HASH_MASK)
DEFINE_LISTP(shim_ipc_info);
static LISTP_TYPE(shim_ipc_info) info_hlist[CLIENT_HASH_NUM];

int init_ipc(void) {
    int ret = 0;

    if (!create_lock(&ipc_info_lock)
        || !create_lock(&g_process_ipc_info.lock)
        || !create_lock(&ipc_info_mgr_lock)) {
        return -ENOMEM;
    }

    if (!(ipc_info_mgr = create_mem_mgr(init_align_up(IPC_INFO_MGR_ALLOC))))
        return -ENOMEM;

    if ((ret = init_ipc_ports()) < 0)
        return ret;
    if ((ret = init_ns_ranges()) < 0)
        return ret;
    if ((ret = init_ns_sysv()) < 0)
        return ret;

    return 0;
}

static struct shim_ipc_info* __create_ipc_info(IDTYPE vmid, const char* uri, size_t len) {
    assert(locked(&ipc_info_lock));

    struct shim_ipc_info* info =
        get_mem_obj_from_mgr_enlarge(ipc_info_mgr, size_align_up(IPC_INFO_MGR_ALLOC));
    if (!info)
        return NULL;

    memset(info, 0, sizeof(struct shim_ipc_info));
    info->vmid = vmid;
    if (uri)
        qstrsetstr(&info->uri, uri, len);
    REF_SET(info->ref_count, 1);
    INIT_LIST_HEAD(info, hlist);
    return info;
}

static void __free_ipc_info(struct shim_ipc_info* info) {
    assert(locked(&ipc_info_lock));

    if (info->pal_handle) {
        DkObjectClose(info->pal_handle);
        info->pal_handle = NULL;
    }
    if (info->port)
        put_ipc_port(info->port);
    qstrfree(&info->uri);
    free_mem_obj_to_mgr(ipc_info_mgr, info);
}

static void __get_ipc_info(struct shim_ipc_info* info) {
    REF_INC(info->ref_count);
}

static void __put_ipc_info(struct shim_ipc_info* info) {
    assert(locked(&ipc_info_lock));

    int ref_count = REF_DEC(info->ref_count);
    if (!ref_count)
        __free_ipc_info(info);
}

void get_ipc_info(struct shim_ipc_info* info) {
    /* no need to grab ipc_info_lock because __get_ipc_info() does not touch global state */
    __get_ipc_info(info);
}

void put_ipc_info(struct shim_ipc_info* info) {
    /* this is atomic so we don't grab lock in common case of ref_count > 0 */
    int ref_count = REF_DEC(info->ref_count);

    if (!ref_count) {
        lock(&ipc_info_lock);
        __free_ipc_info(info);
        unlock(&ipc_info_lock);
    }
}

struct shim_ipc_info* create_ipc_info(IDTYPE vmid, const char* uri, size_t len) {
    lock(&ipc_info_lock);
    struct shim_ipc_info* info = __create_ipc_info(vmid, uri, len);
    unlock(&ipc_info_lock);
    return info;
}

struct shim_ipc_info* create_ipc_info_in_list(IDTYPE vmid, const char* uri, size_t len) {
    assert(vmid);

    struct shim_ipc_info* info;
    lock(&ipc_info_lock);

    /* check if info with this vmid & uri already exists and return it */
    LISTP_TYPE(shim_ipc_info)* info_bucket = &info_hlist[CLIENT_HASH(vmid)];
    LISTP_FOR_EACH_ENTRY(info, info_bucket, hlist) {
        if (info->vmid == vmid && !qstrcmpstr(&info->uri, uri, len)) {
            get_ipc_info(info);
            unlock(&ipc_info_lock);
            return info;
        }
    }

    /* otherwise create new info and return it */
    info = __create_ipc_info(vmid, uri, len);
    if (info) {
        LISTP_ADD(info, info_bucket, hlist);
        get_ipc_info(info);
    }

    unlock(&ipc_info_lock);
    return info;
}

void put_ipc_info_in_list(struct shim_ipc_info* info) {
    LISTP_TYPE(shim_ipc_info)* info_bucket = &info_hlist[CLIENT_HASH(info->vmid)];

    lock(&ipc_info_lock);
    __put_ipc_info(info);
    if (REF_GET(info->ref_count) == 1) {
        LISTP_DEL_INIT(info, info_bucket, hlist);
        __put_ipc_info(info);
    }
    unlock(&ipc_info_lock);
}

struct shim_ipc_info* lookup_ipc_info(IDTYPE vmid) {
    assert(vmid);
    lock(&ipc_info_lock);

    struct shim_ipc_info* info;
    LISTP_TYPE(shim_ipc_info)* info_bucket = &info_hlist[CLIENT_HASH(vmid)];
    LISTP_FOR_EACH_ENTRY(info, info_bucket, hlist) {
        if (info->vmid == vmid && !qstrempty(&info->uri)) {
            __get_ipc_info(info);
            unlock(&ipc_info_lock);
            return info;
        }
    }

    unlock(&ipc_info_lock);
    return NULL;
}

struct shim_process_ipc_info* create_process_ipc_info(void) {
    struct shim_process_ipc_info* new_process_ipc_info = calloc(1, sizeof(*new_process_ipc_info));
    if (!new_process_ipc_info)
        return NULL;

    lock(&g_process_ipc_info.lock);

    /* current process must have been initialized with info on its own IPC info */
    assert(g_process_ipc_info.self);

    /* new process after clone/fork has new identity but inherits parent  */
    new_process_ipc_info->vmid   = 0;
    new_process_ipc_info->self   = NULL;
    new_process_ipc_info->parent = create_ipc_info(g_process_ipc_info.self->vmid,
                                                   qstrgetstr(&g_process_ipc_info.self->uri),
                                                   g_process_ipc_info.self->uri.len);
    if (!new_process_ipc_info->parent)
        goto fail;

    /* new process inherits the same namespace leader */
    if (g_process_ipc_info.ns) {
        new_process_ipc_info->ns = create_ipc_info(g_process_ipc_info.ns->vmid,
                                                   qstrgetstr(&g_process_ipc_info.ns->uri),
                                                   g_process_ipc_info.ns->uri.len);
        if (!new_process_ipc_info->ns)
            goto fail;
    }

    unlock(&g_process_ipc_info.lock);
    return new_process_ipc_info;

fail:
    unlock(&g_process_ipc_info.lock);
    free_process_ipc_info(new_process_ipc_info);
    return NULL;
}

void free_process_ipc_info(struct shim_process_ipc_info* process_ipc_info) {
    if (process_ipc_info->self)
        put_ipc_info(process_ipc_info->self);
    if (process_ipc_info->parent)
        put_ipc_info(process_ipc_info->parent);
    if (process_ipc_info->ns)
        put_ipc_info(process_ipc_info->ns);
    free(process_ipc_info);
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
    debug("Sending ipc message to port %p (handle %p)\n", port, port->pal_handle);

    size_t total_bytes = msg->size;
    size_t bytes       = 0;

    do {
        PAL_NUM ret =
            DkStreamWrite(port->pal_handle, 0, total_bytes - bytes, (void*)msg + bytes, NULL);

        if (ret == PAL_STREAM_ERROR) {
            if (PAL_ERRNO() == EINTR || PAL_ERRNO() == EAGAIN || PAL_ERRNO() == EWOULDBLOCK)
                continue;

            debug("Port %p (handle %p) was removed during sending\n", port, port->pal_handle);
            del_ipc_port_fini(port);
            return -PAL_ERRNO();
        }

        bytes += ret;
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

    debug("Waiting for response (seq = %lu)\n", msg->msg.seq);

    /* force thread which will send the message to wait for response;
     * ignore unrelated interrupts but fail on actual errors */
    do {
        ret = thread_sleep(NO_TIMEOUT);
        if (ret < 0 && ret != -EINTR && ret != -EAGAIN)
            goto out;
    } while (ret != 0);

    debug("Finished waiting for response (seq = %lu, ret = %d)\n", msg->msg.seq, msg->retval);
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

struct shim_ipc_info* create_ipc_info_and_port(bool use_vmid_as_port_name) {
    assert(locked(&g_process_ipc_info.lock));

    struct shim_ipc_info* info = create_ipc_info(g_process_ipc_info.vmid, NULL, 0);
    if (!info)
        return NULL;

    /* pipe for g_process_ipc_info.self is of format "pipe:<g_process_ipc_info.vmid>", others with
     * random name */
    char uri[PIPE_URI_SIZE];
    if (create_pipe(NULL, uri, PIPE_URI_SIZE, &info->pal_handle, &info->uri,
                    use_vmid_as_port_name) < 0) {
        put_ipc_info(info);
        return NULL;
    }

    add_ipc_port_by_id(g_process_ipc_info.vmid, info->pal_handle, IPC_PORT_LISTENING, NULL,
                       &info->port);

    return info;
}

int get_ipc_info_cur_process(struct shim_ipc_info** info) {
    lock(&g_process_ipc_info.lock);

    if (!g_process_ipc_info.self) {
        g_process_ipc_info.self = create_ipc_info_and_port(/*use_vmid_as_port_name=*/true);
        if (!g_process_ipc_info.self) {
            unlock(&g_process_ipc_info.lock);
            return -EACCES;
        }
    }

    get_ipc_info(g_process_ipc_info.self);
    *info = g_process_ipc_info.self;

    unlock(&g_process_ipc_info.lock);
    return 0;
}

BEGIN_CP_FUNC(ipc_info) {
    __UNUSED(size);
    assert(size == sizeof(struct shim_ipc_info));

    struct shim_ipc_info* info     = (struct shim_ipc_info*)obj;
    struct shim_ipc_info* new_info = NULL;

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_ipc_info));
        ADD_TO_CP_MAP(obj, off);

        new_info = (struct shim_ipc_info*)(base + off);
        *new_info = *info;
        REF_SET(new_info->ref_count, 0);

        /* call qstr-specific checkpointing function for new_info->uri */
        DO_CP_IN_MEMBER(qstr, new_info, uri);

        if (info->pal_handle) {
            struct shim_palhdl_entry* entry;
            /* call palhdl-specific checkpointing function to checkpoint
             * info->pal_handle and return created object in entry */
            DO_CP(palhdl, info->pal_handle, &entry);
            /* info's PAL handle will be re-opened with new URI during
             * palhdl restore (see checkpoint.c) */
            entry->uri     = &new_info->uri;
            entry->phandle = &new_info->pal_handle;
        }
    } else {
        /* already checkpointed */
        new_info = (struct shim_ipc_info*)(base + off);
    }

    if (new_info && objp)
        *objp = (void*)new_info;
}
END_CP_FUNC_NO_RS(ipc_info)

BEGIN_CP_FUNC(process_ipc_info) {
    __UNUSED(size);
    assert(size == sizeof(struct shim_process_ipc_info));

    struct shim_process_ipc_info* process_ipc_info     = (struct shim_process_ipc_info*)obj;
    struct shim_process_ipc_info* new_process_ipc_info = NULL;

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(*new_process_ipc_info));
        ADD_TO_CP_MAP(obj, off);

        new_process_ipc_info = (struct shim_process_ipc_info*)(base + off);
        *new_process_ipc_info = *process_ipc_info;

        /* call ipc_info-specific checkpointing functions for new_process_ipc_info's self, parent
         * and ns infos */
        if (process_ipc_info->self)
            DO_CP_MEMBER(ipc_info, process_ipc_info, new_process_ipc_info, self);
        if (process_ipc_info->parent)
            DO_CP_MEMBER(ipc_info, process_ipc_info, new_process_ipc_info, parent);
        if (process_ipc_info->ns)
            DO_CP_MEMBER(ipc_info, process_ipc_info, new_process_ipc_info, ns);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        /* already checkpointed */
        new_process_ipc_info = (struct shim_process_ipc_info*)(base + off);
    }

    if (objp)
        *objp = (void*)new_process_ipc_info;
}
END_CP_FUNC(process_ipc_info)

BEGIN_RS_FUNC(process_ipc_info) {
    __UNUSED(offset);
    struct shim_process_ipc_info* process_ipc_info = (void*)(base + GET_CP_FUNC_ENTRY());

    assert(process_ipc_info->vmid == 0);
    /* forces to pick up new host-OS vmid */
    process_ipc_info->vmid = g_process_ipc_info.vmid;

    CP_REBASE(process_ipc_info->self);
    CP_REBASE(process_ipc_info->parent);
    CP_REBASE(process_ipc_info->ns);

    if (process_ipc_info->self) {
        process_ipc_info->self->vmid = process_ipc_info->vmid;
        get_ipc_info(process_ipc_info->self);
    }
    if (process_ipc_info->parent)
        get_ipc_info(process_ipc_info->parent);
    if (process_ipc_info->ns)
        get_ipc_info(process_ipc_info->ns);

    g_process_ipc_info = *process_ipc_info;
    // this lock will be created in init_ipc
    clear_lock(&g_process_ipc_info.lock);

    DEBUG_RS("vmid=%u,uri=%s,parent=%u(%s)", process_ipc_info->vmid,
             process_ipc_info->self ? qstrgetstr(&process_ipc_info->self->uri) : "",
             process_ipc_info->parent ? process_ipc_info->parent->vmid : 0,
             process_ipc_info->parent ? qstrgetstr(&process_ipc_info->parent->uri) : "");
}
END_RS_FUNC(process_ipc_info)
