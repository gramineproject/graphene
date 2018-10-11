/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_ipc.c
 *
 * This file contains codes to maintain generic bookkeeping of IPC.
 */

#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_ipc.h>
#include <shim_checkpoint.h>
#include <shim_unistd.h>
#include <shim_profile.h>

#include <pal.h>
#include <pal_error.h>
#include <list.h>

#define ipc_info_mgr_ALLOC  32
#define PAGE_SIZE           allocsize

#define OBJ_TYPE struct shim_ipc_info
#include "memmgr.h"

static MEM_MGR ipc_info_mgr;

LOCKTYPE ipc_info_lock;

struct shim_process cur_process;

DEFINE_PROFILE_CATAGORY(ipc, );
DEFINE_PROFILE_OCCURENCE(syscall_use_ipc, ipc);

//#define DEBUG_REF

int init_ipc_ports (void);
int init_ns_pid    (void);
int init_ns_sysv   (void);

int init_ipc (void)
{
    int ret = 0;

    create_lock(ipc_info_lock);

    if (!(ipc_info_mgr = create_mem_mgr(init_align_up(ipc_info_mgr_ALLOC))))
        return -ENOMEM;

    if ((ret = init_ipc_ports()) < 0)
        return ret;

    if ((ret = init_ns_pid()) < 0)
        return ret;

    if ((ret = init_ns_sysv()) < 0)
        return ret;

    return 0;
}

int prepare_ns_leaders (void)
{
    int ret = 0;
    if ((ret = prepare_pid_leader()) < 0)
        return ret;
    if ((ret = prepare_sysv_leader()) < 0)
        return ret;
    return 0;
}

static struct shim_ipc_info * __get_new_ipc_info (IDTYPE vmid, const char * uri,
                                                  size_t len)
{
    struct shim_ipc_info * info =
                get_mem_obj_from_mgr_enlarge(ipc_info_mgr,
                                             size_align_up(ipc_info_mgr_ALLOC));
    if (!info)
        return NULL;

    memset(info, 0, sizeof(struct shim_ipc_info));
    if (vmid)
        info->vmid = vmid;
    if (uri)
        qstrsetstr(&info->uri, uri, len);
    REF_SET(info->ref_count, 1);
    INIT_LIST_HEAD(info, hlist);
    return info;
}

struct shim_ipc_info * get_new_ipc_info (IDTYPE vmid, const char * uri,
                                         size_t len)
{
    lock(ipc_info_lock);
    struct shim_ipc_info * info = __get_new_ipc_info(vmid, uri, len);
    unlock(ipc_info_lock);
    return info;
}

static void __get_ipc_info (struct shim_ipc_info * info)
{
#ifdef DEBUG_REF
    int ref_count = REF_INC(info->ref_count);

    debug("get port %p (vmid %u uri %s, ref_count = %d)\n", info,
          info->vmid, qstrgetstr(&info->uri), ref_count);
#else
    REF_INC(info->ref_count);
#endif
}

void get_ipc_info (struct shim_ipc_info * info)
{
    __get_ipc_info(info);
}

static void unset_ipc_info (struct shim_ipc_info * info)
{
    qstrfree(&info->uri);

    if (info->port)
        put_ipc_port(info->port);

    if (info->pal_handle)
        DkObjectClose(info->pal_handle);
}

static void __put_ipc_info (struct shim_ipc_info * info)
{
    int ref_count = REF_DEC(info->ref_count);

#ifdef DEBUG_REF
    debug("put port %p (vmid %u uri %s, ref_count = %d)\n", info,
          info->vmid, qstrgetstr(&info->uri), ref_count);
#endif

    if (ref_count)
        return;

    unset_ipc_info(info);
    free_mem_obj_to_mgr(ipc_info_mgr, info);
}

void put_ipc_info (struct shim_ipc_info * info)
{
    int ref_count = REF_DEC(info->ref_count);

#ifdef DEBUG_REF
    debug("put port %p (vmid %u uri %s, ref_count = %d)\n", info,
          info->vmid, qstrgetstr(&info->uri), ref_count);
#endif

    if (ref_count)
        return;

    unset_ipc_info(info);
    lock(ipc_info_lock);
    free_mem_obj_to_mgr(ipc_info_mgr, info);
    unlock(ipc_info_lock);
}

#define CLIENT_HASH_LEN     6
#define CLIENT_HASH_NUM     (1 << CLIENT_HASH_LEN)
#define CLIENT_HASH_MASK    (CLIENT_HASH_NUM - 1)
#define CLIENT_HASH(vmid)   ((vmid) & CLIENT_HASH_MASK)

/* Links to shim_ipc_info->hlist */
DEFINE_LISTP(shim_ipc_info);
static LISTP_TYPE(shim_ipc_info) client_table [CLIENT_HASH_NUM];

struct shim_ipc_info *
lookup_and_alloc_client (IDTYPE vmid, const char * uri)
{
    struct shim_ipc_info * p;
    LISTP_TYPE(shim_ipc_info) *head = client_table + CLIENT_HASH(vmid);
    size_t len = strlen(uri);

    assert(vmid);

    lock(ipc_info_lock);
    listp_for_each_entry(p, head, hlist)
        if (p->vmid == vmid && !qstrcmpstr(&p->uri, uri, len)) {
            get_ipc_info(p);
            unlock(ipc_info_lock);
            return p;
        }

    p = __get_new_ipc_info(vmid, uri, len);
    if (p) {
        listp_add(p, head, hlist);
        get_ipc_info(p);
    }
    unlock(ipc_info_lock);
    return p;
}

void put_client (struct shim_ipc_info * info)
{
    lock(ipc_info_lock);
    /* Look up the hash */
    LISTP_TYPE(shim_ipc_info) *head = client_table + CLIENT_HASH(info->vmid);
    __put_ipc_info(info);
    if (REF_GET(info->ref_count) == 1) {
        listp_del_init(info, head, hlist);
        __put_ipc_info(info);
    }
    unlock(ipc_info_lock);
}

struct shim_ipc_info * discover_client (struct shim_ipc_port * port,
                                        IDTYPE vmid)
{
    struct shim_ipc_info * p;
    LISTP_TYPE(shim_ipc_info) * head = client_table + CLIENT_HASH(vmid);

    assert(vmid);

    lock(ipc_info_lock);
    listp_for_each_entry(p, head, hlist)
        if (p->vmid == vmid && !qstrempty(&p->uri)) {
            __get_ipc_info(p);
            unlock(ipc_info_lock);
            return p;
        }
    unlock(ipc_info_lock);
    return NULL;

    if (!ipc_finduri_send(port, vmid, &p))
        return p;

    return NULL;
}

struct shim_process * create_new_process (bool inherit_parent)
{
    struct shim_process * new_process = calloc(1, sizeof(struct shim_process));
    if (!new_process)
        return NULL;

    new_process->parent = get_new_ipc_info(cur_process.vmid, NULL, 0);

    if (!inherit_parent)
        return new_process;

    lock(cur_process.lock);

    if (cur_process.self)
        qstrcopy(&new_process->parent->uri, &cur_process.self->uri);

    for (int i = 0 ; i < TOTAL_NS ; i++)
        if (cur_process.ns[i])
            new_process->ns[i] =
                get_new_ipc_info(cur_process.ns[i]->vmid,
                                 qstrgetstr(&cur_process.ns[i]->uri),
                                 cur_process.ns[i]->uri.len);

    unlock(cur_process.lock);
    return new_process;
}

void destroy_process (struct shim_process * proc)
{
    if (proc->self)
        put_ipc_info(proc->self);

    if (proc->parent)
        put_ipc_info(proc->parent);

    for (int i = 0 ; i < TOTAL_NS ; i++)
        if (proc->ns[i])
            put_ipc_info(proc->ns[i]);

    free(proc);
}

int __init_ipc_msg (struct shim_ipc_msg * msg, int code, int size, IDTYPE dest)
{
    msg->code = code;
    msg->size = IPC_MSG_SIZE(size);
    msg->src = cur_process.vmid;
    msg->dst = dest;
    msg->seq = 0;
    return 0;
}

struct shim_ipc_msg * create_ipc_msg (int code, int size, IDTYPE dest)
{
    struct shim_ipc_msg * msg = malloc(IPC_MSG_SIZE(size));

    if (msg && __init_ipc_msg(msg, code, size, dest)) {
        free(msg);
        msg = NULL;
    }

    return msg;
}

int __init_ipc_msg_duplex (struct shim_ipc_msg_obj * msg, int code, int size,
                           IDTYPE dest)
{
    __init_ipc_msg(&msg->msg, code, size, dest);
    msg->thread = NULL;
    INIT_LIST_HEAD(msg, list);
    msg->retval = 0;
    msg->private = NULL;
    return 0;
}

struct shim_ipc_msg_obj *
create_ipc_msg_duplex (int code, int size, IDTYPE dest)
{
    struct shim_ipc_msg_obj * msg = malloc(IPC_MSGOBJ_SIZE(size));

    if (msg && __init_ipc_msg_duplex(msg, code, size, dest)) {
        free(msg);
        msg = NULL;
    }

    return msg;
}

int __init_ipc_resp_msg (struct shim_ipc_msg * resp, int ret,
                         unsigned long seq)
{
    struct shim_ipc_resp * resp_in = (struct shim_ipc_resp *) resp->msg;
    resp->seq = seq;
    resp_in->retval = ret;
    return 0;
}

struct shim_ipc_msg *
create_ipc_resp_msg (int ret, IDTYPE dest, unsigned long seq)
{
    struct shim_ipc_msg * resp =
            create_ipc_msg(IPC_RESP, sizeof(struct shim_ipc_resp), dest);

    if (resp && __init_ipc_resp_msg(resp, ret, seq)) {
        free(resp);
        resp = NULL;
    }

    return resp;
}

int send_ipc_message (struct shim_ipc_msg * msg, struct shim_ipc_port * port)
{
    assert(msg->size >= IPC_MSG_MINIMAL_SIZE);
    msg->src = cur_process.vmid;

    debug("send ipc message to port %p (handle %p)\n", port,
          port->pal_handle);

    int ret = DkStreamWrite(port->pal_handle, 0, msg->size, msg, NULL);

    if (ret == 0 && PAL_NATIVE_ERRNO) {
        debug("port %p (handle %p) is removed at sending\n", port,
              port->pal_handle);

        del_ipc_port_fini(port, -ECHILD);
        return -PAL_ERRNO;
    }

    return 0;
}

int close_ipc_message_duplex (struct shim_ipc_msg_obj * msg,
                              struct shim_ipc_port * port)
{
    if (port) {
        // Check if the message is pending on the port for response. If so,
        // remove the message from the list.
        lock(port->msgs_lock);
        if (!list_empty(msg, list))
            listp_del_init(msg, &port->msgs, list);
        unlock(port->msgs_lock);
    }

    if (msg->thread) {
        put_thread(msg->thread);
        msg->thread = NULL;
    }

    return 0;
}

static struct atomic_int ipc_seq_counter;

int send_ipc_message_duplex (struct shim_ipc_msg_obj * msg,
                             struct shim_ipc_port * port, bool save,
                             void * private_data)
{
    atomic_inc(&ipc_seq_counter);
    msg->msg.seq = atomic_read(&ipc_seq_counter);

    if (save) {
        lock(port->msgs_lock);
        msg->private = private_data;
        listp_add_tail(msg, &port->msgs, list);
        unlock(port->msgs_lock);
    }

    int ret = send_ipc_message(&msg->msg, port);

    if (ret < 0) {
        if (save)
            close_ipc_message_duplex(msg, port);
        return ret;
    }

    return 0;
}

struct shim_ipc_msg_obj * find_ipc_msg_duplex (struct shim_ipc_port * port,
                                               unsigned long seq)
{
    struct shim_ipc_msg_obj * tmp, * found = NULL;
    lock(port->msgs_lock);
    listp_for_each_entry(tmp, &port->msgs, list)
        if (tmp->msg.seq == seq) {
            found = tmp;
            listp_del_init(tmp, &port->msgs, list);
            break;
        }
    unlock(port->msgs_lock);
    return found;
}

/* for convenience */
int do_ipc_duplex (struct shim_ipc_msg_obj * msg,
                   struct shim_ipc_port * port, unsigned long * seq,
                   void * private_data)
{
    int ret = 0;
    struct shim_thread * thread = get_cur_thread();
    assert(thread);

    if (!msg->thread)
        thread_setwait(&msg->thread, thread);

    ret = send_ipc_message_duplex(msg, port, true, private_data);

    if (seq)
        *seq = (ret < 0) ? 0 : msg->msg.seq;

    if (ret < 0)
        goto out;

    debug("wait for response (seq = %lu)\n", msg->msg.seq);
    thread_sleep(NO_TIMEOUT);

    ret = msg->retval;
out:
    close_ipc_message_duplex(msg, port);
    return ret;
}

struct shim_ipc_info * create_ipc_port (IDTYPE vmid, bool listen)
{
    struct shim_ipc_info * proc = get_new_ipc_info(vmid, NULL, 0);
    if (!proc)
        return NULL;

    char uri[PIPE_URI_SIZE];
    if (create_pipe(NULL, uri, PIPE_URI_SIZE, &proc->pal_handle,
                    &proc->uri) < 0) {
        put_ipc_info(proc);
        return NULL;
    }

    if (listen)
        add_ipc_port_by_id(0, proc->pal_handle, IPC_PORT_SERVER,
                           NULL, &proc->port);
    return proc;
}

int create_ipc_location (struct shim_ipc_info ** info)
{
    lock(cur_process.lock);
    int ret = -EACCES;

    if (cur_process.self)
        goto success;

    cur_process.self = create_ipc_port(cur_process.vmid, true);
    if (!cur_process.self)
        goto out;

success:
    get_ipc_info(cur_process.self);
    *info = cur_process.self;
    ret = 0;
out:
    unlock(cur_process.lock);
    return ret;
}

DEFINE_PROFILE_INTERVAL(ipc_finduri_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_finduri_callback, ipc);

int ipc_finduri_send (struct shim_ipc_port * port, IDTYPE dest,
                      struct shim_ipc_info ** info)
{
    BEGIN_PROFILE_INTERVAL();
    int ret;
    struct shim_ipc_msg_obj * msg = create_ipc_msg_duplex_on_stack(
                                        IPC_FINDURI, 0, dest);

    debug("ipc send to %u: IPC_FINDURI\n", dest);

    ret = do_ipc_duplex(msg, port, NULL, info);
    SAVE_PROFILE_INTERVAL(ipc_finduri_send);
    return ret;
}

int ipc_finduri_callback (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    int ret = 0;

    debug("ipc callback from %u: IPC_FINDURI\n", msg->src);

    struct shim_ipc_info * info;

    if ((ret = create_ipc_location(&info)) < 0)
        goto out;

    ret = ipc_telluri_send(port, msg->src, info);
out:
    SAVE_PROFILE_INTERVAL(ipc_finduri_callback);
    return ret;
}

DEFINE_PROFILE_INTERVAL(ipc_telluri_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_telluri_callback, ipc);

int ipc_telluri_send (struct shim_ipc_port * port, IDTYPE dest,
                      struct shim_ipc_info * info)
{
    BEGIN_PROFILE_INTERVAL();
    int ret;
    struct shim_ipc_msg * msg = create_ipc_msg_on_stack(
                                        IPC_TELLURI,
                                        info->uri.len, dest);
    struct shim_ipc_telluri * msgin =
                (struct shim_ipc_telluri *) &msg->msg;

    if (qstrempty(&info->uri)) {
        ret = -ENOENT;
        return ret;
    }

    memcpy(msgin->uri, qstrgetstr(&info->uri), info->uri.len + 1);

    debug("ipc send to %u: IPC_TELLURI(%s)\n", dest,
          qstrgetstr(&info->uri));

    ret = send_ipc_message(msg, port);
    SAVE_PROFILE_INTERVAL(ipc_telluri_send);
    return ret;
}

int ipc_telluri_callback (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    int ret = 0;
    struct shim_ipc_telluri * msgin =
                (struct shim_ipc_telluri *) &msg->msg;

    debug("ipc callback from %u: IPC_TELLURI(%s)\n", msg->src, msgin->uri);

    struct shim_ipc_info * info =
            lookup_and_alloc_client(msg->src, msgin->uri);

    struct shim_ipc_msg_obj * obj = find_ipc_msg_duplex(port, msg->seq);

    if (obj) {
        if (info) {
            if (obj->private)
                *(struct shim_ipc_info **) obj->private = info;
            obj->retval = 0;
        } else {
            obj->retval = -ENOMEM;
        }

        if (obj->thread)
            thread_wakeup(obj->thread);
    }

    SAVE_PROFILE_INTERVAL(ipc_telluri_callback);
    return ret;
}

DEFINE_PROFILE_INTERVAL(ipc_checkpoint_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_checkpoint_callback, ipc);

int ipc_checkpoint_send (const char * cpdir, IDTYPE cpsession)
{
    BEGIN_PROFILE_INTERVAL();
    int ret;
    int len = strlen(cpdir);

    struct shim_ipc_msg * msg = create_ipc_msg_on_stack(
                                        IPC_CHECKPOINT,
                                        sizeof(struct shim_ipc_checkpoint)
                                        + len, 0);
    struct shim_ipc_checkpoint * msgin =
                    (struct shim_ipc_checkpoint *) &msg->msg;

    msgin->cpsession = cpsession;
    memcpy(&msgin->cpdir, cpdir, len + 1);

    debug("ipc broadcast to all: IPC_CHECKPOINT(%u, %s)\n",
          cpsession, cpdir);

    ret = broadcast_ipc(msg, NULL, 0, IPC_PORT_DIRCLD|IPC_PORT_DIRPRT);
    SAVE_PROFILE_INTERVAL(ipc_checkpoint_send);
    return ret;
}

int ipc_checkpoint_callback (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    int ret = 0;
    struct shim_ipc_checkpoint * msgin =
                (struct shim_ipc_checkpoint *) msg->msg;

    debug("ipc callback form %u: IPC_CHECKPOINT(%u, %s)\n", msg->src,
          msgin->cpsession, msgin->cpdir);

    ret = create_checkpoint(msgin->cpdir, &msgin->cpsession);
    if (ret < 0)
        goto out;

    kill_all_threads(NULL, msgin->cpsession, SIGCP);
    broadcast_ipc(msg, &port, 1, IPC_PORT_DIRPRT|IPC_PORT_DIRCLD);
out:
    SAVE_PROFILE_INTERVAL(ipc_checkpoint_callback);
    return ret;
}

BEGIN_CP_FUNC(ipc_info)
{
    assert(size == sizeof(struct shim_ipc_info));

    struct shim_ipc_info * port = (struct shim_ipc_info *) obj;
    struct shim_ipc_info * new_port = NULL;

    ptr_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_ipc_info));

        new_port = (struct shim_ipc_info *) (base + off);
        memcpy(new_port, port, sizeof(struct shim_ipc_info));
        REF_SET(new_port->ref_count, 0);

        DO_CP_IN_MEMBER(qstr, new_port, uri);

        if (port->pal_handle &&
            port->pal_handle != IPC_FORCE_RECONNECT) {
            struct shim_palhdl_entry * entry;
            DO_CP(palhdl, port->pal_handle, &entry);
            entry->uri = &new_port->uri;
            entry->phandle = &new_port->pal_handle;
        }
    } else {
        new_port = (struct shim_ipc_info *) (base + off);
    }

    if (new_port && objp)
        *objp = (void *) new_port;
}
END_CP_FUNC_NO_RS(ipc_info)

BEGIN_CP_FUNC(process)
{
    assert(size == sizeof(struct shim_process));

    struct shim_process * proc = (struct shim_process *) obj;
    struct shim_process * new_proc = NULL;

    ptr_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_process));
        ADD_TO_CP_MAP(obj, off);

        new_proc = (struct shim_process *) (base + off);
        memcpy(new_proc, proc, sizeof(struct shim_process));

        if (proc->self)
            DO_CP_MEMBER(ipc_info, proc, new_proc, self);

        if (proc->parent)
            DO_CP_MEMBER(ipc_info, proc, new_proc, parent);

        for (int i = 0 ; i < TOTAL_NS ; i++)
            if (proc->ns[i])
                DO_CP_MEMBER(ipc_info, proc, new_proc, ns[i]);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_proc = (struct shim_process *) (base + off);
    }

    if (objp)
        *objp = (void *) new_proc;
}
END_CP_FUNC(process)

BEGIN_RS_FUNC(process)
{
    struct shim_process * proc = (void *) (base + GET_CP_FUNC_ENTRY());

    CP_REBASE(proc->self);
    CP_REBASE(proc->parent);
    CP_REBASE(proc->ns);

    if (proc->self) {
        proc->self->vmid = cur_process.vmid;
        get_ipc_info(proc->self);
    }

    if (proc->parent)
        get_ipc_info(proc->parent);

    for (int i = 0 ; i < TOTAL_NS ; i++)
        if (proc->ns[i])
            get_ipc_info(proc->ns[i]);

    proc->vmid = cur_process.vmid;
    memcpy(&cur_process, proc, sizeof(struct shim_process));
    create_lock(cur_process.lock);

    DEBUG_RS("vmid=%u,uri=%s,parent=%u(%s)", proc->vmid,
             proc->self ? qstrgetstr(&proc->self->uri) : "",
             proc->parent ? proc->parent->vmid : 0,
             proc->parent ? qstrgetstr(&proc->parent->uri) : "");
}
END_RS_FUNC(process)
