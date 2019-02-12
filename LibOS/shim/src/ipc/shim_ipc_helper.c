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
 * shim_ipc_helper.c
 *
 * This file contains codes to create a IPC helper thread inside library OS
 * and maintain bookkeeping of IPC ports.
 */

#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_ipc.h>
#include <shim_checkpoint.h>
#include <shim_profile.h>

#include <pal.h>
#include <pal_error.h>
#include <list.h>

#define PORT_MGR_ALLOC  32
#define PAGE_SIZE       allocsize

#define OBJ_TYPE struct shim_ipc_port
#include "memmgr.h"

static MEM_MGR port_mgr;
/* This points to a list of shim_ipc_port objects (by the list field) */
DEFINE_LISTP(shim_ipc_port);
static LISTP_TYPE(shim_ipc_port) pobj_list;

#define PID_HASH_LEN   6
#define PID_HASH_NUM   (1 << PID_HASH_LEN)
#define PID_HASH_MASK  (PID_HASH_NUM - 1)
#define PID_HASH(pid)  ((pid) & PID_HASH_MASK)

/* This points to a list of shim_ipc_port objects (by the hlist field) */
static LISTP_TYPE(shim_ipc_port) ipc_port_pool [PID_HASH_NUM];

/* This variable can be read without the ipc_helper_lock held, but
 * should be modified with the ipc_helper_lock held (and in some cases,
 * the value should be re-checked after acquiring the lock. 
 * For reads in a loop without the lock, some caution should be taken to 
 * use compiler barriers to ensure that a stale value isn't cached.
 */
static enum {
    HELPER_UNINITIALIZED, HELPER_DELAYED, HELPER_NOTALIVE,
    HELPER_ALIVE, HELPER_HANDEDOVER,
} ipc_helper_state;

static struct shim_thread *  ipc_helper_thread;
static bool                  ipc_helper_update;
static AEVENTTYPE            ipc_helper_event;

#define IN_HELPER() \
    (ipc_helper_thread && ipc_helper_thread == get_cur_thread())

static LOCKTYPE ipc_helper_lock;

static struct shim_ipc_port * broadcast_port;

//#define DEBUG_REF

static int init_ipc_port (struct shim_ipc_info * info, PAL_HANDLE hdl, int type)
{
    if (!info)
        return 0;

    if (info->pal_handle == IPC_FORCE_RECONNECT) {
        info->pal_handle = NULL;
        if (!hdl && !qstrempty(&info->uri)) {
            debug("try reconnect port %s\n", qstrgetstr(&info->uri));

            hdl = DkStreamOpen(qstrgetstr(&info->uri),
                               0, 0, 0, 0);
            if (!hdl)
                return -PAL_ERRNO;
        }
        info->pal_handle = hdl;
    }

    if (!info->pal_handle)
        info->pal_handle = hdl;

    if (info->pal_handle)
        add_ipc_port_by_id(info->vmid == cur_process.vmid ? 0 : info->vmid,
                           info->pal_handle, type, NULL, &info->port);
    return 0;
}

static void ipc_broadcast_exit (struct shim_ipc_port * port, IDTYPE vmid,
                                unsigned exitcode)
{
    if (port == broadcast_port) {
        master_lock();
        broadcast_port = NULL;
        put_ipc_port(port);
        master_unlock();
    }
}

int init_ipc_ports (void)
{
    int ret = 0;

    if (!(port_mgr = create_mem_mgr(init_align_up(PORT_MGR_ALLOC))))
        return -ENOMEM;

    if ((ret = init_ipc_port(cur_process.self, NULL, IPC_PORT_SERVER)) < 0)
        return ret;

    if (PAL_CB(parent_process) &&
        (ret = init_ipc_port(cur_process.parent, PAL_CB(parent_process),
                             IPC_PORT_DIRPRT|IPC_PORT_LISTEN)) < 0)
        return ret;

    if ((ret = init_ipc_port(cur_process.ns[PID_NS], NULL,
                             IPC_PORT_PIDLDR|IPC_PORT_LISTEN)) < 0)
        return ret;

    if ((ret = init_ipc_port(cur_process.ns[SYSV_NS], NULL,
                             IPC_PORT_SYSVLDR|IPC_PORT_LISTEN)) < 0)
        return ret;

    if (PAL_CB(broadcast_stream))
        add_ipc_port_by_id(0, PAL_CB(broadcast_stream), IPC_PORT_LISTEN,
                           &ipc_broadcast_exit, &broadcast_port);

    return 0;
}


static int create_ipc_helper (void);

/* This function should be called as part of init, before locks or atomics are
 * required */
int init_ipc_helper (void)
{
    bool need_helper = (ipc_helper_state == HELPER_DELAYED);
    ipc_helper_state = HELPER_NOTALIVE;
    create_lock(ipc_helper_lock);
    create_event(&ipc_helper_event);
    if (need_helper) {
        /*
         * we are enabling multi-threading, must turn on threading
         * before grabbing any lock
         */
        enable_locking();

        /* Go ahead and lock the ipc helper lock here, for consistency */
        lock(ipc_helper_lock);
        create_ipc_helper();
        unlock(ipc_helper_lock);
    }
    return 0;
}

static void __get_ipc_port (struct shim_ipc_port * pobj)
{
#ifdef DEBUG_REF
    int ref_count = REF_INC(pobj->ref_count);

    debug("get ipc_port %p (handle %p, ref_count = %d)\n", pobj,
          pobj->pal_handle, ref_count);
#else
    REF_INC(pobj->ref_count);
#endif
}

static void __free_ipc_port (struct shim_ipc_port * pobj)
{
    if (pobj->pal_handle) {
        DkObjectClose(pobj->pal_handle);
        pobj->pal_handle = NULL;
    }

    destroy_lock(pobj->msgs_lock);
    free_mem_obj_to_mgr(port_mgr, pobj);
}

static void __put_ipc_port (struct shim_ipc_port * pobj)
{
    int ref_count = REF_DEC(pobj->ref_count);

#ifdef DEBUG_REF
    debug("put ipc port %p (handle %p, ref_count = %d)\n", pobj,
          pobj->pal_handle, ref_count);
#endif

    if (!ref_count)
        __free_ipc_port(pobj);
}

/* This should be called with the ipc_helper_lock held */
static inline void restart_ipc_helper (bool need_create)
{
    switch (ipc_helper_state) {
        case HELPER_UNINITIALIZED:
            ipc_helper_state = HELPER_DELAYED;
        case HELPER_DELAYED:
            return;
        case HELPER_NOTALIVE:
            if (need_create)
                create_ipc_helper();
            return;
        case HELPER_ALIVE:
            if (IN_HELPER()) {
                ipc_helper_update = true;
                return;
            }
            debug("set ipc helper restart\n");
            set_event(&ipc_helper_event, 1);
            return;
        case HELPER_HANDEDOVER:
            ipc_helper_update = true;
            return;
    }
}

static bool __add_ipc_port (struct shim_ipc_port * port, IDTYPE vmid,
                            int type, port_fini fini)
{
    bool need_restart = false;
    assert(vmid != cur_process.vmid);

    if (vmid && !port->info.vmid) {
        port->info.vmid = vmid;
        port->update = true;
    }

    if (port->info.vmid && list_empty(port, hlist)) {
        LISTP_TYPE(shim_ipc_port) * head = &ipc_port_pool[PID_HASH(vmid)];
        __get_ipc_port(port);
        listp_add(port, head, hlist);
    }

    if (!(port->info.type & IPC_PORT_IFPOLL) && (type & IPC_PORT_IFPOLL))
        need_restart = true;

    if ((port->info.type & type) != type) {
        port->info.type |= type;
        port->update = true;
    }

    if (fini && (type & ~IPC_PORT_IFPOLL)) {
        port_fini * cb = port->fini;
        for ( ; cb < port->fini + MAX_IPC_PORT_FINI_CB ; cb++)
            if (!*cb || *cb == fini)
                break;

        assert(cb < port->fini + MAX_IPC_PORT_FINI_CB);
        *cb = fini;
    }

    if (need_restart) {
        if (list_empty(port, list)) {
            __get_ipc_port(port);
            listp_add(port, &pobj_list, list);
            port->recent = true;
        } else {
            if (!port->recent) {
                listp_del_init(port, &pobj_list, list);
                listp_add(port, &pobj_list, list);
                port->recent = true;
            }
        }
        return true;
    } else {
        if (list_empty(port, list)) {
            __get_ipc_port(port);
            listp_add_tail(port, &pobj_list, list);
        }
        return false;
    }
}

void add_ipc_port (struct shim_ipc_port * port, IDTYPE vmid, int type,
                   port_fini fini)
{
    debug("adding port %p (handle %p) for process %u (type=%04x)\n",
          port, port->pal_handle, port->info.vmid, type);

    lock(ipc_helper_lock);
    bool need_restart = __add_ipc_port(port, vmid, type, fini);
    if (need_restart)
        restart_ipc_helper(true);

    unlock(ipc_helper_lock);
}

static struct shim_ipc_port * __get_new_ipc_port (PAL_HANDLE hdl)
{
    struct shim_ipc_port * port =
                get_mem_obj_from_mgr_enlarge(port_mgr,
                                             size_align_up(PORT_MGR_ALLOC));

    if (!port) {
        debug("failed to allocate shim_ipc_port\n");
        return NULL;
    }

    memset(port, 0, sizeof(struct shim_ipc_port));
    port->pal_handle = hdl;
    port->update = true;
    INIT_LIST_HEAD(port, hlist);
    INIT_LIST_HEAD(port, list);
    INIT_LISTP(&port->msgs);
    REF_SET(port->ref_count, 1);
    create_lock(port->msgs_lock);
    return port;
}

void add_ipc_port_by_id (IDTYPE vmid, PAL_HANDLE hdl, int type,
                         port_fini fini, struct shim_ipc_port ** portptr)
{
    debug("adding port (handle %p) for process %u (type %04x)\n",
          hdl, vmid, type);

    assert(!!hdl && PAL_GET_TYPE(hdl));
    lock(ipc_helper_lock);

    LISTP_TYPE(shim_ipc_port) * head = vmid ? &ipc_port_pool[PID_HASH(vmid)] : NULL;
    struct shim_ipc_port * tmp, * port = NULL;

    if (vmid)
        listp_for_each_entry(tmp, head, hlist)
            if (tmp->info.vmid == vmid && tmp->pal_handle == hdl) {
                port = tmp;
                __get_ipc_port(port);
                break;
            }

    if (!port)
        listp_for_each_entry(tmp, &pobj_list, list)
            if (tmp->pal_handle == hdl) {
                port = tmp;
                __get_ipc_port(port);
                break;
            }

    if (!port && !(port = __get_new_ipc_port(hdl))) {
        *portptr = NULL;
        goto out;
    }

    bool need_restart = __add_ipc_port(port, vmid, type, fini);
    assert(!list_empty(port, list));
    assert(!vmid || !list_empty(port, hlist));

    if (portptr)
        *portptr = port;
    else
        __put_ipc_port(port);

    if (need_restart)
        restart_ipc_helper(true);

out:
    unlock(ipc_helper_lock);
}

static bool __del_ipc_port (struct shim_ipc_port * port, int type)
{
    debug("deleting port %p (handle %p) for process %u\n",
          port, port->pal_handle, port->info.vmid);

    __get_ipc_port(port); // Prevent the object from being freed during deletion
    assert(!list_empty(port, list)); // Never delete a port twice

    bool need_restart = false;
    type = type ? (type & port->info.type) : port->info.type;

    if ((type & IPC_PORT_KEEPALIVE) ^
        (port->info.type & IPC_PORT_KEEPALIVE))
        need_restart = true;

    /* if the port still have other usage, we will not remove the port */
    if (port->info.type & ~(type|IPC_PORT_IFPOLL|IPC_PORT_KEEPALIVE)) {
        debug("masking port %p (handle %p): type %x->%x\n",
              port, port->pal_handle, port->info.type, port->info.type & ~type);
        port->info.type &= ~type;
        goto out;
    }

    // Prevent further usage of the PAL handle
    DkStreamDelete(port->pal_handle, 0);

    if (port->info.type & IPC_PORT_IFPOLL)
        need_restart = true;

    // Officially delete the port
    listp_del_init(port, &pobj_list, list);
    port->info.type &= IPC_PORT_IFPOLL;
    __put_ipc_port(port);

    if (!list_empty(port, hlist)) {
        // Re-fetch head pointer
        LISTP_TYPE(shim_ipc_port) * head = &ipc_port_pool[PID_HASH(port->info.vmid)];
        listp_del_init(port, head, hlist);
        __put_ipc_port(port);
    }

    // Need to check if there are any pending messages on the port, which means
    // some threads might be blocking for responses.
    lock(port->msgs_lock);
    struct shim_ipc_msg_obj * msg, * n;
    listp_for_each_entry_safe(msg, n, &port->msgs, list) {
        listp_del_init(msg, &port->msgs, list);
        msg->retval = -ECONNRESET;
        if (msg->thread) {
            debug("wake up thread %d\n", msg->thread->tid);
            thread_wakeup(msg->thread);
        }
    }
    unlock(port->msgs_lock);

out:
    port->update = true;
    __put_ipc_port(port); // Free the object if ref_count is 0
    return need_restart;
}

void del_ipc_port (struct shim_ipc_port * port, int type)
{
    lock(ipc_helper_lock);

    // If the port is already deleted, don't delete it again.
    if (list_empty(port, list)) {
        unlock(ipc_helper_lock);
        return;
    }

    bool need_restart = __del_ipc_port(port, type);

    if (need_restart)
        restart_ipc_helper(false);

    unlock(ipc_helper_lock);
}

void del_ipc_port_by_id (IDTYPE vmid, int type)
{
    LISTP_TYPE(shim_ipc_port) * head = &ipc_port_pool[PID_HASH(vmid)];
    struct shim_ipc_port * port, *n;
    bool need_restart = false;

    lock(ipc_helper_lock);

    listp_for_each_entry_safe(port, n, head, hlist) {
        if (list_empty(port, list))
            continue;

        debug("port %p (handle %p) for process %u in list %p\n",
              port, port->pal_handle, port->info.vmid, head);

        if (port->info.vmid == vmid && __del_ipc_port(port, type))
            need_restart = true;
    }

    if (need_restart)
        restart_ipc_helper(false);

    unlock(ipc_helper_lock);
}

void del_ipc_port_fini (struct shim_ipc_port * port, unsigned int exitcode)
{
    port_fini fini[MAX_IPC_PORT_FINI_CB];
    int nfini = 0;
    assert(REF_GET(port->ref_count) > 0);
    lock(ipc_helper_lock);

    // If the port is already deleted, don't delete it again.
    if (list_empty(port, list)) {
        unlock(ipc_helper_lock);
        return;
    }

    IDTYPE vmid = port->info.vmid;
    for (int i = 0 ; i < MAX_IPC_PORT_FINI_CB ; i++)
        if (port->fini[i]) {
            fini[nfini++] = port->fini[i];
            port->fini[i] = NULL;
        }

    bool need_restart = __del_ipc_port(port, 0);

    if (need_restart)
        restart_ipc_helper(false);

    unlock(ipc_helper_lock);

    for (int i = 0 ; i < nfini ; i++)
        (fini[i])(port, vmid, exitcode);
}

static struct shim_ipc_port * __lookup_ipc_port (IDTYPE vmid, int type)
{
    LISTP_TYPE(shim_ipc_port) * head = &ipc_port_pool[PID_HASH(vmid)];
    struct shim_ipc_port * tmp;

    listp_for_each_entry(tmp, head, hlist)
        if (tmp->info.vmid == vmid && (!type || tmp->info.type & type)) {
            debug("found port %p (handle %p) for process %u (type %04x)\n",
                  tmp, tmp->pal_handle, tmp->info.vmid, tmp->info.type);
            __get_ipc_port(tmp);
            return tmp;
        }

    return NULL;
}

struct shim_ipc_port * lookup_ipc_port (IDTYPE vmid, int type)
{
    lock(ipc_helper_lock);
    struct shim_ipc_port * port = __lookup_ipc_port(vmid, type);
    if (port) {
        assert(!list_empty(port, list));
        assert(!vmid || !list_empty(port, hlist));
    }
    unlock(ipc_helper_lock);
    return port;
}

void get_ipc_port (struct shim_ipc_port * port)
{
    // No need to grab ipc_helper_lock because __get_ipc_port() is atomic.
    __get_ipc_port(port);
}

void put_ipc_port (struct shim_ipc_port * port)
{
    int ref_count = REF_DEC(port->ref_count);

#ifdef DEBUG_REF
    debug("put ipc port %p (handle %p, ref_count = %d)\n", port,
          port->pal_handle, ref_count);
#endif

    if (!ref_count) {
        lock(ipc_helper_lock); // Need to grab the lock
        __free_ipc_port(port);
        unlock(ipc_helper_lock);
    }
}

void del_all_ipc_ports (int type)
{
    struct shim_ipc_port * pobj, * n;
    bool need_restart = false;

    lock(ipc_helper_lock);

    listp_for_each_entry_safe(pobj, n, &pobj_list, list) {
        if (__del_ipc_port(pobj, type))
            need_restart = true;
    }

    if (need_restart)
        restart_ipc_helper(false);

    unlock(ipc_helper_lock);
}

int broadcast_ipc (struct shim_ipc_msg * msg, struct shim_ipc_port ** exclude,
                   int exsize, int target_type)
{
    struct shim_ipc_port ** exend = exclude + exsize, ** ex;
    struct shim_ipc_port * pobj;

    if (!target_type && broadcast_port) {
        for (ex = exclude ; ex < exend && *ex != broadcast_port ; ex++);
        if (ex != exend)
            return 0;

        debug("send to broadcast stream\n");
        int ret = send_ipc_message(msg, broadcast_port);
        if (!ret)
            return 0;
    }

    lock(ipc_helper_lock);

    int ntargets = 0;
    listp_for_each_entry(pobj, &pobj_list, list) {
        debug("found port %p (handle %p) for process %u (type %04x)\n", pobj,
              pobj->pal_handle, pobj->info.vmid, pobj->info.type);
        if (pobj->info.type & target_type)
            ntargets++;
    }

    struct shim_ipc_port ** targets = __alloca(sizeof(struct shim_ipc_port *)
                                               * ntargets);
    int i = 0;
    listp_for_each_entry(pobj, &pobj_list, list)
        if (pobj->info.type & target_type) {
            get_ipc_port(pobj);
            targets[i++] = pobj;
        }

    unlock(ipc_helper_lock);

    for (i = 0 ; i < ntargets ; i++) {
        pobj = targets[i];

        debug("broadcast to port %p (handle %p) for process %u "
              "(type %x, target %x)\n",
              pobj, pobj->pal_handle, pobj->info.vmid,
              pobj->info.type, target_type);

        if (exsize) {
            for (ex = exclude ; ex < exend && *ex != pobj ; ex++);
            if (ex != exend)
                continue;
        }

        msg->dst = pobj->info.vmid;

        /* has to be assigned, so shim_send_ipc_message will not try
           to grab ipc_helper_lock */
        send_ipc_message(msg, pobj);
        put_ipc_port(pobj);
    }

    return 0;
}

static int ipc_resp_callback (IPC_CALLBACK_ARGS)
{
    struct shim_ipc_resp * msgin = (struct shim_ipc_resp *) &msg->msg;

    debug("ipc callback from %u: IPC_RESP(%d)\n", msg->src, msgin->retval);

    if (!msg->seq)
        return msgin->retval;

    struct shim_ipc_msg_obj * obj = find_ipc_msg_duplex(port, msg->seq);

    if (obj) {
        obj->retval = msgin->retval;
        if (obj->thread)
            thread_wakeup(obj->thread);
        return 0;
    }

    return msgin->retval;
}

static ipc_callback ipc_callbacks [IPC_CODE_NUM] = {
    /* RESP             */  &ipc_resp_callback,
    /* FINDURI          */  &ipc_finduri_callback,
    /* TELLURI          */  &ipc_telluri_callback,
    /* CHECKPOINT       */  &ipc_checkpoint_callback,

    /* parents and children */
    /* CLD_EXIT         */  &ipc_cld_exit_callback,
    /* CLD_JOIN         */  &ipc_cld_join_callback,
#ifdef PROFILE
    /* CLD_PROFILE      */  &ipc_cld_profile_callback,
#endif

    /* pid namespace */
    IPC_NS_CALLBACKS(pid)
    /* PID_KILL         */  &ipc_pid_kill_callback,
    /* PID_GETSTATUS    */  &ipc_pid_getstatus_callback,
    /* PID_RETSTATUS    */  &ipc_pid_retstatus_callback,
    /* PID_GETMETA      */  &ipc_pid_getmeta_callback,
    /* PID_RETMETA      */  &ipc_pid_retmeta_callback,
    /* PID_NOP          */  &ipc_pid_nop_callback,
    /* PID_SENDRPC      */  &ipc_pid_sendrpc_callback,

    /* sysv namespace */
    IPC_NS_CALLBACKS(sysv)
    IPC_NS_KEY_CALLBACKS(sysv)
    /* SYSV_DELRES      */  &ipc_sysv_delres_callback,
    /* SYSV_MOVRES      */  &ipc_sysv_movres_callback,
    /* SYSV_MSGSND      */  &ipc_sysv_msgsnd_callback,
    /* SYSV_MSGRCV      */  &ipc_sysv_msgrcv_callback,
    /* SYSV_MSGMOV      */  &ipc_sysv_msgmov_callback,
    /* SYSV_SEMOP       */  &ipc_sysv_semop_callback,
    /* SYSV_SEMCTL      */  &ipc_sysv_semctl_callback,
    /* SYSV_SEMRET      */  &ipc_sysv_semret_callback,
    /* SYSV_SEMMOV      */  &ipc_sysv_semmov_callback,
};

int __response_ipc_message (struct shim_ipc_port * port, IDTYPE dest,
                            int ret, unsigned long seq)
{
    struct shim_ipc_msg * resp = create_ipc_resp_msg_on_stack(ret, dest, seq);

    ret = (ret == RESPONSE_CALLBACK) ? 0 : ret;
    debug("ipc send to %u: IPC_RESP(%d)\n", resp->dst, ret);

    struct shim_ipc_resp * msgin = (struct shim_ipc_resp *) &resp->msg;
    msgin->retval = ret;
    return send_ipc_message(resp, port);
}

/* not only ipc helper thread can receive messsage, anyone can
   receive message if they have acquired (locked) the port */
int receive_ipc_message (struct shim_ipc_port * port, unsigned long seq,
                         struct shim_ipc_msg ** msgptr)
{
    int readahead = IPC_MSG_READAHEAD;
    int bufsize = IPC_MSG_MINIMAL_SIZE + readahead;
    struct shim_ipc_msg * msg = __alloca(bufsize);
    int expected_size;
    int bytes = 0, ret = 0;

    do {
        expected_size = IPC_MSG_MINIMAL_SIZE;
        while (bytes < expected_size) {
retry_read:
            if (expected_size + readahead > bufsize) {
                while (expected_size + readahead > bufsize)
                    bufsize *= 2;
                void * new_buff = __alloca(bufsize);
                memcpy(new_buff, msg, bytes);
                msg = new_buff;
            }

            if (!(ret = DkStreamRead(port->pal_handle, 0,
                                     expected_size - bytes + readahead,
                                     (void *) msg + bytes, NULL, 0)))
                break;

            bytes += ret;
        }

        if (!bytes) {
            if (PAL_NATIVE_ERRNO) {
                debug("port %p (handle %p) is removed at reading\n",
                      port, port->pal_handle);
                del_ipc_port_fini(port, -ECHILD);
                ret = -PAL_ERRNO;
            }

            break;
        }

        debug("receive a message from port %p (handle %p): "
              "code=%d size=%d src=%u dst=%u seq=%lx\n",
              port, port->pal_handle,
              msg->code, msg->size, msg->src, msg->dst, msg->seq);

        expected_size = msg->size;
        if (bytes < expected_size)
            goto retry_read;

        if (msgptr && (!seq || msg->seq == seq)) {
            struct shim_ipc_msg * retmsg;
            if (*msgptr) {
                if (msg->size > (*msgptr)->size)
                    msg->size = (*msgptr)->size;
                retmsg = *msgptr;
            } else {
                *msgptr = retmsg = malloc(msg->size);
            }

            memcpy(retmsg, msg, msg->size);
            return 0;
        }

        /* skip if the message comes from myself (it's possible because
           of the broadcast channel */
        if (msg->src == cur_process.vmid)
            goto next;

        ipc_callback callback = ipc_callbacks[msg->code];

        if (callback) {
            ret = (*callback) (msg, port);
            if ((ret < 0 || ret == RESPONSE_CALLBACK) && msg->seq)
                /* only helper thread sends back response */
                ret = __response_ipc_message(port, msg->src, ret, msg->seq);
        }

next:
        if ((bytes -= expected_size) > 0)
            memmove(msg, (void *) msg + expected_size, bytes);

    } while (bytes > 0 || (seq && msg->seq != seq));

    if (msgptr)
        *msgptr = NULL;

    return ret;
}

#define IPC_HELPER_STACK_SIZE       (allocsize * 4)
#define IPC_HELPER_LIST_INIT_SIZE   32

static void shim_ipc_helper (void * arg)
{
    /* set ipc helper thread */
    struct shim_thread * self = (struct shim_thread *) arg;
    if (!arg)
        return;

    __libc_tcb_t tcb;
    allocate_tls(&tcb, false, self);
    debug_setbuf(&tcb.shim_tcb, true);
    debug("set tcb to %p\n", &tcb);

    lock(ipc_helper_lock);
    bool notme = (self != ipc_helper_thread);
    unlock(ipc_helper_lock);

    if (notme) {
        put_thread(self);
        DkThreadExit();
        return;
    }

    debug("ipc helper thread started\n");

    void * stack = allocate_stack(IPC_HELPER_STACK_SIZE, allocsize, false);

    if (!stack)
        goto end;

    self->stack_top = stack + IPC_HELPER_STACK_SIZE;
    self->stack = stack;
    switch_stack(stack + IPC_HELPER_STACK_SIZE);
    self = get_cur_thread();
    stack = self->stack;

    int port_num = 0, port_size = IPC_HELPER_LIST_INIT_SIZE;
    struct shim_ipc_port ** local_pobjs = stack, * pobj;
    PAL_HANDLE * local_ports;
    PAL_HANDLE ipc_event_handle = event_handle(&ipc_helper_event);

    int nalive = 0;
    PAL_HANDLE polled = NULL;
    int count = -1;

    local_ports = (PAL_HANDLE *) (local_pobjs + port_size);
    local_ports[0] = ipc_event_handle;

    goto update_status;

    /* The compiler should be careful not to cache the ipc_helper_state or
     * else ths loop could fail to terminate on update.  Use a compiler
     * barrier to force a re-read after sleeping. */
    while ((ipc_helper_state == HELPER_ALIVE) ||
           nalive) {
        /* do a global poll on all the ports */
        polled = DkObjectsWaitAny(port_num + 1, local_ports, NO_TIMEOUT);
        barrier();

        if (!polled)
            continue;

        /* before we locking pobj list, at least we can look at the returned
           port if it is the ipc helper event */
        if (polled == ipc_event_handle) {
            clear_event(&ipc_helper_event);
update_status:
            barrier();
            if (ipc_helper_state == HELPER_NOTALIVE)
                goto end;
            else
                goto update_list;
        }

        pobj = NULL;
        count = -1;
        for (int i = 0 ; i < port_num ; i++)
            if (polled == local_pobjs[i]->pal_handle) {
                pobj = local_pobjs[i];
                count = i;
                break;
            }

        if (!pobj)
            continue;

        /* if the polled port is a server port, accept a client and add it
           to the port list */
        if (pobj->private.type & IPC_PORT_SERVER) {
            PAL_HANDLE cli = DkStreamWaitForClient(polled);
            if (cli) {
                int type = (pobj->private.type & ~IPC_PORT_SERVER) |
                           IPC_PORT_LISTEN;
                add_ipc_port_by_id(pobj->private.vmid, cli, type,
                                   NULL, NULL);
            } else {
                debug("port %p (handle %p) is removed at accepting\n",
                      pobj, polled);
                del_ipc_port_fini(pobj, -ECHILD);
            }
            polled = NULL;
            count = -1;
            goto update_list;
        }

        PAL_STREAM_ATTR attr;
        if (!DkStreamAttributesQuerybyHandle(polled, &attr)) {
            debug("port %p (handle %p) is removed at querying\n",
                  pobj, polled);
            del_ipc_port_fini(pobj, -PAL_ERRNO);
            goto update_list;
        }

        if (attr.readable)
            receive_ipc_message(pobj, 0, NULL);

        if (attr.disconnected) {
            debug("port %p (handle %p) is disconnected\n",
                  pobj, polled);
            del_ipc_port_fini(pobj, -ECONNRESET);
            goto update_list;
        }

        if (!ipc_helper_update)
            continue;
update_list:
        ipc_helper_update = false;
        lock(ipc_helper_lock);

        int compact = 0;
        /* first walk though all the polling ports and remove the one
           being deleted. */
        for (int i = 0 ; i < port_num ; i++) {
            struct shim_ipc_port * pobj = local_pobjs[i];

            // If the port is removed from the list or intended to be deleted,
            // remove the port from the polling array
            if (list_empty(pobj, list)) {
                if (polled == pobj->pal_handle) {
                    polled = NULL;
                    count = -1;
                }
                local_pobjs[i] = NULL;
                if (pobj->private.type & IPC_PORT_KEEPALIVE)
                    nalive--;
                __put_ipc_port(pobj);
                compact++;
                continue;
            }

            if (pobj->update) {
                if (pobj->info.type & IPC_PORT_KEEPALIVE) {
                    if (!(pobj->private.type & IPC_PORT_KEEPALIVE))
                        nalive--;
                } else {
                    if (pobj->private.type & IPC_PORT_KEEPALIVE)
                        nalive++;
                }
                pobj->private = pobj->info;
                pobj->update = false;
            }

            if (compact) {
                if (polled == pobj->pal_handle)
                    count -= compact;
                local_pobjs[i - compact] = pobj;
                local_ports[i - compact + 1] = pobj->pal_handle;
            }
        }
        port_num -= compact;

        listp_for_each_entry(pobj, &pobj_list, list) {
            /* we only update among recently updated ports */
            if (!pobj->recent)
                break;

            if (pobj->update) {
                pobj->private = pobj->info;
                pobj->update = false;
            }

            assert(pobj->private.type & IPC_PORT_IFPOLL);

            if (port_num == port_size) {
                port_size *= 2;
                memmove(local_pobjs + port_size,
                        local_ports,
                        (port_num + 1) * sizeof(PAL_HANDLE));
                local_ports = (PAL_HANDLE *) (local_pobjs + port_size);
            }

            pobj->recent = false;
            __get_ipc_port(pobj);
            local_pobjs[port_num] = pobj;
            local_ports[port_num + 1] = pobj->pal_handle;
            port_num++;

            if (pobj->private.type & IPC_PORT_KEEPALIVE)
                nalive++;

            debug("listen to process %u on port %p (handle %p, type %04x)\n",
                  pobj->private.vmid,
                  pobj,
                  pobj->pal_handle,
                  pobj->private.type);
        }

        unlock(ipc_helper_lock);
    }

    for (int i = 0 ; i < port_num ; i++) {
        struct shim_ipc_port * pobj = local_pobjs[i];
        __put_ipc_port(pobj);
    }

end:
    /* DP: Put our handle map reference */
    if (self->handle_map)
        put_handle_map(self->handle_map);

    /* shim_clean ultimately calls del_all_ipc_ports(), which reacquires the
     * helper lock.  Err on the side of caution by adding a barrier to ensure 
     * reading the latest ipc helper state.       
     */
    barrier();
    if (ipc_helper_state == HELPER_HANDEDOVER) {
        debug("ipc helper thread is the last thread, process exiting\n");
        shim_terminate(); // Same as shim_clean(), but this is the official termination function
    }

    lock(ipc_helper_lock);
    ipc_helper_state = HELPER_NOTALIVE;
    ipc_helper_thread = NULL;
    unlock(ipc_helper_lock);
    put_thread(self);
    debug("ipc helper thread terminated\n");

    DkThreadExit();
}

/* This function shoudl be called with the ipc_helper_lock held */
static int create_ipc_helper (void)
{
    int ret = 0;

    /* If we are holding the lock, no barrier is needed here, as 
     * the lock (and new function) form an implicit barrier, and
     * any "recent" changes should have come from this thread */
    if (ipc_helper_state == HELPER_ALIVE)
        return 0;

    struct shim_thread * new = get_new_internal_thread();
    if (!new)
        return -ENOMEM;

    ipc_helper_thread = new;
    ipc_helper_state = HELPER_ALIVE;

    PAL_HANDLE handle = thread_create(shim_ipc_helper, new, 0);

    if (!handle) {
        ret = -PAL_ERRNO;
        ipc_helper_thread = NULL;
        ipc_helper_state = HELPER_NOTALIVE;
        put_thread(new);
        return ret;
    }

    new->pal_handle = handle;
    return 0;
}

/*
 * on success, the reference to the helper thread is returned with
 * reference count incremented.
 * The caller is responsible to wait for the IPC helper thread to exit
 * and release the final reference to free related resources.
 * It's problematic for the thread itself to release its resources which it's
 * using. For example stack.
 * So defer releasing it after its exit and make the releasing the caller
 * responsibility.
 */
int exit_with_ipc_helper (bool handover, struct shim_thread ** ret)
{
    *ret = NULL;
    if (IN_HELPER() || ipc_helper_state != HELPER_ALIVE)
        return 0;

    lock(ipc_helper_lock);
    if (handover) {
        handover = false;
        struct shim_ipc_port * pobj;
        listp_for_each_entry(pobj, &pobj_list, list)
            if (pobj->info.type & IPC_PORT_KEEPALIVE) {
                handover = true;
                break;
            }
    }

    int new_state = HELPER_NOTALIVE;
    if (handover) {
        debug("handing over to ipc helper\n");
        new_state = HELPER_HANDEDOVER;
    } else {
        debug("exiting ipc helper\n");
    }

    ipc_helper_state = new_state;
    if (ipc_helper_thread != NULL) {
        get_thread(ipc_helper_thread);
        *ret = ipc_helper_thread;
    }
    unlock(ipc_helper_lock);

    set_event(&ipc_helper_event, 1);

    if (new_state != HELPER_NOTALIVE) {
        return -EAGAIN;
    } else {
        /* We could get here via a signal handler invoked during
         * receive_ipc_message. Let that complete so that whoever
         * generated the signal doesn't hang waiting for IPC_RESP. */
        int loops = 0;
        while (ipc_helper_thread != NULL && loops++ < 2000) {
            barrier();
            DkThreadDelayExecution(1000);
        }
        if (ipc_helper_thread != NULL) {
            debug("timed out waiting for ipc helper to exit\n");
        }
        return 0;
    }
}

int terminate_ipc_helper (void)
{
    lock(ipc_helper_lock);

    struct shim_thread * thread = ipc_helper_thread;
    if (!thread) {
        unlock(ipc_helper_lock);
        return -ESRCH;
    }

    debug("terminating ipc helper\n");
    ipc_helper_state = HELPER_NOTALIVE;
    set_event(&ipc_helper_event, 1);
    unlock(ipc_helper_lock);
    return 0;
}
