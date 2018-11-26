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
 * shim_ipc_pid.c
 *
 * This file contains functions and callbacks to handle IPC of PID namespace.
 */

#include <shim_internal.h>
#include <shim_thread.h>
#include <shim_fs.h>
#include <shim_ipc.h>
#include <shim_checkpoint.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>

#define PID_RANGE_SIZE      32
#define PID_LEASE_TIME      1000

#define NS      pid
#define NS_CAP  PID

#include "shim_ipc_nsimpl.h"

static int thread_add_subrange (struct shim_thread * thread, void * arg,
                                bool * unlocked)
{
    if (!thread->in_vm)
        return 0;

    struct shim_ipc_info * info = (struct shim_ipc_info *) arg;

    add_pid_subrange(thread->tid, info->vmid,
                     qstrgetstr(&info->uri), &thread->tid_lease);
    return 0;
}

int init_ns_pid (void)
{
    struct shim_ipc_info * info;
    int ret = 0;

    init_namespace();

    if ((ret = create_ipc_location(&info)) < 0)
        return ret;

    walk_thread_list(&thread_add_subrange, info, false);
    return 0;
}

int broadcast_signal (IDTYPE sender, int signum)
{
    BEGIN_PROFILE_INTERVAL();
    int ret;

    struct shim_ipc_msg * msg = create_ipc_msg_on_stack(
                                        IPC_PID_KILL,
                                        sizeof(struct shim_ipc_pid_kill), 0);
    struct shim_ipc_pid_kill * msgin =
                    (struct shim_ipc_pid_kill *) &msg->msg;

    msgin->sender = sender;
    msgin->id     = 0;
    msgin->type   = KILL_ALL;
    msgin->signum = signum;

    debug("ipc send to %u: IPC_PID_KILL(%u, %d, %u, %d)\n", 0,
          sender, KILL_ALL, 0, signum);

    ret = broadcast_ipc(msg, NULL, 0, IPC_PORT_DIRCLD|IPC_PORT_DIRPRT);
    SAVE_PROFILE_INTERVAL(ipc_pid_kill_send);
    return ret;
}

int ipc_pid_kill_send (IDTYPE sender, IDTYPE id, enum kill_type type,
                       int signum)
{
    BEGIN_PROFILE_INTERVAL();
    IDTYPE dest;
    struct shim_ipc_port * port = NULL;
    int ret;

    if ((ret = connect_owner(id, &port, &dest)) < 0)
        goto out;

    struct shim_ipc_msg_obj * msg = create_ipc_msg_duplex_on_stack(
                                        IPC_PID_KILL,
                                        sizeof(struct shim_ipc_pid_kill),
                                        dest);
    struct shim_ipc_pid_kill * msgin =
                    (struct shim_ipc_pid_kill *) &msg->msg.msg;

    msgin->sender = sender;
    msgin->id     = id;
    msgin->type   = type;
    msgin->signum = signum;

    debug("ipc send to %u: IPC_PID_KILL(%u, %d, %u, %d)\n", dest,
          sender, type, id, signum);

    ret = do_ipc_duplex(msg, port, NULL, NULL);
    put_ipc_port(port);
out:
    SAVE_PROFILE_INTERVAL(ipc_pid_kill_send);
    return ret;
}

DEFINE_PROFILE_INTERVAL(ipc_pid_kill_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_pid_kill_callback, ipc);

int ipc_pid_kill_callback (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    struct shim_ipc_pid_kill * msgin =
            (struct shim_ipc_pid_kill *) msg->msg;

    debug("ipc callback from %u: IPC_PID_KILL(%u, %u, %d)\n",
          msg->src, msgin->sender, msgin->id, msgin->signum);

    int ret = 0;

    switch (msgin->type) {
        case KILL_THREAD:
            ret = do_kill_thread(msgin->sender, 0, msgin->id, msgin->signum,
                                 true);
            break;
        case KILL_PROCESS:
            ret = do_kill_proc(msgin->sender, msgin->id, msgin->signum, true);
            break;
        case KILL_PGROUP:
            ret = do_kill_pgroup(msgin->sender, msgin->id, msgin->signum,
                                 true);
            break;
        case KILL_ALL:
            broadcast_ipc(msg, &port, 1, IPC_PORT_DIRPRT|IPC_PORT_DIRCLD);
            kill_all_threads(NULL, msgin->sender, msgin->signum);
            break;
    }

    SAVE_PROFILE_INTERVAL(ipc_pid_kill_callback);
    return ret < 0 ? ret : RESPONSE_CALLBACK;
}

DEFINE_PROFILE_INTERVAL(ipc_pid_getstatus_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_pid_getstatus_callback, ipc);

int ipc_pid_getstatus_send (struct shim_ipc_port * port, IDTYPE dest,
                            int npids, IDTYPE * pids,
                            struct pid_status ** status)
{
    BEGIN_PROFILE_INTERVAL();
    int ret;

    struct shim_ipc_msg_obj * msg = create_ipc_msg_duplex_on_stack(
                                        IPC_PID_GETSTATUS,
                                        sizeof(struct shim_ipc_pid_getstatus) +
                                        sizeof(IDTYPE) * npids,
                                        dest);
    struct shim_ipc_pid_getstatus * msgin =
                    (struct shim_ipc_pid_getstatus *) &msg->msg.msg;

    msgin->npids = npids;
    memcpy(msgin->pids, pids, sizeof(IDTYPE) * npids);

    debug("ipc send to %u: IPC_PID_GETSTATUS(%d, [%u, ...])\n", dest,
          npids, pids[0]);

    ret = do_ipc_duplex(msg, port, NULL, status);

    SAVE_PROFILE_INTERVAL(ipc_pid_getstatus_send);
    return ret;
}

int ipc_pid_getstatus_callback (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    struct shim_ipc_pid_getstatus * msgin =
                            (struct shim_ipc_pid_getstatus *) msg->msg;
    int ret = 0;

    debug("ipc callback from %u: IPC_PID_GETSTATUS(%d, [%u, ...])\n",
          msg->src, msgin->npids, msgin->pids[0]);

    struct thread_status {
        int npids;
        IDTYPE * pids;
        int nstatus;
        struct pid_status * status;
    };

    int check_thread (struct shim_thread * thread, void * arg,
                      bool * unlocked)
    {
        struct thread_status * status = (struct thread_status *) arg;

        for (int i = 0 ; i < status->npids ; i++)
            if (status->pids[i] == thread->tid &&
                thread->in_vm && thread->is_alive) {
                status->status[status->nstatus].pid  = thread->tid;
                status->status[status->nstatus].tgid = thread->tgid;
                status->status[status->nstatus].pgid = thread->pgid;
                status->nstatus++;
                return 1;
            }

        return 0;
    }

    struct thread_status status;
    status.npids = msgin->npids;
    status.pids = msgin->pids;
    status.nstatus = 0;
    status.status = __alloca(sizeof(struct pid_status) * msgin->npids);

    ret = walk_thread_list(&check_thread, &status, false);
    if (ret < 0 && ret != -ESRCH)
        goto out;

    ret = ipc_pid_retstatus_send(port, msg->src, status.nstatus, status.status,
                                 msg->seq);
out:
    SAVE_PROFILE_INTERVAL(ipc_pid_getstatus_callback);
    return ret;
}

DEFINE_PROFILE_INTERVAL(ipc_pid_retstatus_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_pid_retstatus_callback, ipc);

int ipc_pid_retstatus_send (struct shim_ipc_port * port, IDTYPE dest,
                            int nstatus, struct pid_status * status,
                            unsigned long seq)
{
    BEGIN_PROFILE_INTERVAL();
    int ret;

    struct shim_ipc_msg * msg = create_ipc_msg_on_stack(
                                        IPC_PID_RETSTATUS,
                                        sizeof(struct shim_ipc_pid_retstatus) +
                                        sizeof(struct pid_status) * nstatus,
                                        dest);
    struct shim_ipc_pid_retstatus * msgin =
                    (struct shim_ipc_pid_retstatus *) &msg->msg;

    msgin->nstatus  = nstatus;
    memcpy(msgin->status, status, sizeof(struct pid_status) * nstatus);
    msg->seq = seq;

    if (nstatus)
        debug("ipc send to %u: IPC_PID_RETSTATUS(%d, [%u, ...])\n", dest,
              nstatus, status[0].pid);
    else
        debug("ipc send to %u: IPC_PID_RETSTATUS(0, [])\n", dest);

    ret = send_ipc_message(msg, port);

    SAVE_PROFILE_INTERVAL(ipc_pid_retstatus_send);
    return ret;
}

int ipc_pid_retstatus_callback (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    struct shim_ipc_pid_retstatus * msgin =
                            (struct shim_ipc_pid_retstatus *) msg->msg;

    if (msgin->nstatus)
        debug("ipc callback from %u: IPC_PID_RETSTATUS(%d, [%u, ...])\n",
              msg->src, msgin->nstatus, msgin->status[0].pid);
    else
        debug("ipc callback from %u: IPC_PID_RETSTATUS(0, [])\n", msg->src);


    struct shim_ipc_msg_obj * obj = find_ipc_msg_duplex(port, msg->seq);
    if (obj) {
        struct pid_status ** status = (struct pid_status **) obj->private;

        if (status) {
            *status = malloc_copy(msgin->status, sizeof(struct pid_status) *
                                  msgin->nstatus);

            obj->retval = msgin->nstatus;
        }

        if (obj->thread)
            thread_wakeup(obj->thread);
    }

    SAVE_PROFILE_INTERVAL(ipc_pid_retstatus_callback);
    return 0;
}

int get_all_pid_status (struct pid_status ** status)
{
    /* run queryall unconditionally */
    ipc_pid_queryall_send();

    int bufsize = RANGE_SIZE;
    struct pid_status * status_buf = malloc(bufsize);
    int nstatus = 0;

    if (!bufsize)
        return -ENOMEM;

    LISTP_TYPE(range) * list = &offered_ranges;
    struct range * r;
    int ret;

    lock(range_map_lock);

retry:
    listp_for_each_entry (r, list, list) {
        struct subrange * s = NULL;
        struct shim_ipc_info * p;
        int off, idx;
        IDTYPE base;
        IDTYPE pids[RANGE_SIZE];
        struct pid_status * range_status;

next_range:
        idx = -1;
        off = r->offset;
        base = off * RANGE_SIZE + 1;

next_sub:
        if (idx == -1) {
            p = r->owner;
        } else {
            if (idx >= RANGE_SIZE)
                continue;
            if (!r->subranges)
                continue;
            s = r->subranges->map[idx];
            if (!s) {
                idx++;
                goto next_sub;
            }
            p = s->owner;
        }

        if (p->vmid == cur_process.vmid) {
            idx++;
            goto next_sub;
        }

        if (!p->port) {
            int type = IPC_PORT_PIDOWN|IPC_PORT_LISTEN;
            IDTYPE owner = p->vmid;
            char * uri = qstrtostr(&p->uri, true);
            struct shim_ipc_port * port = NULL;
            unlock(range_map_lock);

            PAL_HANDLE pal_handle = DkStreamOpen(uri, 0, 0, 0, 0);

            if (pal_handle)
                add_ipc_port_by_id(owner, pal_handle, type, NULL, &port);

            lock(range_map_lock);
            listp_for_each_entry(r, list, list)
                if (r->offset >= off)
                    break;
            /* DEP 5/15/17: I believe this is checking if the list is empty */
            //if (&r->list == list)
            if (listp_empty(list))
                break;
            if (r->offset > off)
                goto next_range;
            if (!port)
                continue;

            if (idx == -1) {
            } else {
                if (!r->subranges)
                    continue;
                s = r->subranges->map[idx];
                if (!s) {
                    idx++;
                    goto next_sub;
                }
                p = s->owner;
            }

            if (p->port)
                put_ipc_port(p->port);

            p->port = port;
        }

        if (idx == -1) {
            for (int i = 0 ; i < RANGE_SIZE ; i++)
                pids[i] = base + i;
        } else {
            pids[0] = base + idx;
        }

        ret = ipc_pid_getstatus_send(p->port, p->vmid,
                                     idx == -1 ? RANGE_SIZE : 1, pids,
                                     &range_status);

        if (ret > 0) {
            if (nstatus + ret > bufsize) {
                int newsize = bufsize * 2;

                while (nstatus + ret > newsize)
                    newsize *= 2;

                struct pid_status * new_buf = malloc(newsize);

                if (!new_buf) {
                    unlock(range_map_lock);
                    free(range_status);
                    free(status_buf);
                    return -ENOMEM;
                }

                memcpy(new_buf, status_buf,
                       sizeof(struct pid_status) * nstatus);

                free(status_buf);
                status_buf = new_buf;
                bufsize = newsize;
            }

            memcpy(status_buf + nstatus, range_status,
                   sizeof(struct pid_status) * ret);
            free(range_status);
            nstatus += ret;
        }

        idx++;
        goto next_sub;
    }

    if (list == &offered_ranges) {
        list = &owned_ranges;
        goto retry;
    }

    unlock(range_map_lock);

    if (!nstatus) {
        free(status_buf);
        return 0;
    }

    *status = status_buf;
    return nstatus;
}

DEFINE_PROFILE_INTERVAL(ipc_pid_getmeta_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_pid_getmeta_callback, ipc);

static const char * pid_meta_code_str[4] = { "CRED", "EXEC", "CWD", "ROOT", };

int ipc_pid_getmeta_send (IDTYPE pid, enum pid_meta_code code,
                          void ** data)
{
    BEGIN_PROFILE_INTERVAL();
    IDTYPE dest;
    struct shim_ipc_port * port = NULL;
    int ret;

    if ((ret = connect_owner(pid, &port, &dest)) < 0)
        goto out;

    struct shim_ipc_msg_obj * msg = create_ipc_msg_duplex_on_stack(
                                        IPC_PID_GETMETA,
                                        sizeof(struct shim_ipc_pid_getmeta),
                                        dest);
    struct shim_ipc_pid_getmeta * msgin =
                    (struct shim_ipc_pid_getmeta *) &msg->msg.msg;
    msgin->pid  = pid;
    msgin->code = code;

    debug("ipc send to %u: IPC_PID_GETMETA(%u, %s)\n", dest,
          pid, pid_meta_code_str[code]);

    ret = do_ipc_duplex(msg, port, NULL, data);
    put_ipc_port(port);
out:
    SAVE_PROFILE_INTERVAL(ipc_pid_getmeta_send);
    return ret;
}

int ipc_pid_getmeta_callback (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    struct shim_ipc_pid_getmeta * msgin =
                            (struct shim_ipc_pid_getmeta *) msg->msg;
    int ret = 0;

    debug("ipc callback from %u: IPC_PID_GETMETA(%u, %s)\n", msg->src,
          msgin->pid, pid_meta_code_str[msgin->code]);

    struct shim_thread * thread = lookup_thread(msgin->pid);
    void * data = NULL;
    int datasize = 0;

    if (!thread) {
        ret = -ESRCH;
        goto out;
    }

    lock(thread->lock);

    switch (msgin->code) {
        case PID_META_CRED:
            datasize = sizeof(IDTYPE) * 2;
            data = __alloca(datasize);
            ((IDTYPE *) data)[0] = thread->uid;
            ((IDTYPE *) data)[1] = thread->gid;
            break;
        case PID_META_EXEC:
            if (!thread->exec || !thread->exec->dentry) {
                ret = -ENOENT;
                break;
            }
            data = dentry_get_path(thread->exec->dentry, true, &datasize);
            break;
        case PID_META_CWD:
            if (!thread->cwd) {
                ret = -ENOENT;
                break;
            }
            data = dentry_get_path(thread->cwd, true, &datasize);
            break;
        case PID_META_ROOT:
            if (!thread->root) {
                ret = -ENOENT;
                break;
            }
            data = dentry_get_path(thread->root, true, &datasize);
            break;
        default:
            ret = -EINVAL;
            break;
    }

    unlock(thread->lock);
    put_thread(thread);

    if (ret < 0)
        goto out;

    ret = ipc_pid_retmeta_send(port, msg->src, msgin->pid, msgin->code,
                               data, datasize, msg->seq);
out:
    SAVE_PROFILE_INTERVAL(ipc_pid_getmeta_callback);
    return ret;
}

DEFINE_PROFILE_INTERVAL(ipc_pid_retmeta_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_pid_retmeta_callback, ipc);

int ipc_pid_retmeta_send (struct shim_ipc_port * port, IDTYPE dest,
                          IDTYPE pid, enum pid_meta_code code,
                          const void * data, int datasize,
                          unsigned long seq)
{
    BEGIN_PROFILE_INTERVAL();
    int ret;

    struct shim_ipc_msg * msg = create_ipc_msg_on_stack(
                                        IPC_PID_RETMETA,
                                        sizeof(struct shim_ipc_pid_retmeta) +
                                        datasize, dest);
    struct shim_ipc_pid_retmeta * msgin =
                    (struct shim_ipc_pid_retmeta *) &msg->msg;

    msgin->pid      = pid;
    msgin->code     = code;
    msgin->datasize = datasize;
    memcpy(msgin->data, data, datasize);
    msg->seq        = seq;

    debug("ipc send to %u: IPC_PID_RETMETA(%d, %s, %d)\n", dest,
          pid, pid_meta_code_str[code], datasize);

    ret = send_ipc_message(msg, port);

    SAVE_PROFILE_INTERVAL(ipc_pid_retmeta_send);
    return ret;
}

int ipc_pid_retmeta_callback (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    struct shim_ipc_pid_retmeta * msgin =
                            (struct shim_ipc_pid_retmeta *) msg->msg;

    debug("ipc callback from %u: IPC_PID_RETMETA(%u, %s, %d)\n", msg->src,
          msgin->pid, pid_meta_code_str[msgin->code], msgin->datasize);

    struct shim_ipc_msg_obj * obj = find_ipc_msg_duplex(port, msg->seq);
    if (obj) {
        void ** data = (void **) obj->private;

        if (data)
            *data = msgin->datasize ?
                    malloc_copy(msgin->data, msgin->datasize) : NULL;

        obj->retval = msgin->datasize;

        if (obj->thread)
            thread_wakeup(obj->thread);
    }

    SAVE_PROFILE_INTERVAL(ipc_pid_retmeta_callback);
    return 0;
}

int get_pid_port (IDTYPE pid, IDTYPE * dest, struct shim_ipc_port ** port)
{
    IDTYPE owner;
    int ret;

    if ((ret = connect_owner(pid, port, &owner)) < 0)
        return ret;

    if (dest)
        *dest = owner;

    return 0;
}

DEFINE_PROFILE_INTERVAL(ipc_pid_nop_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_pid_nop_callback, ipc);

int ipc_pid_nop_send (struct shim_ipc_port * port, IDTYPE dest, int count,
                      const void * buf, int len)
{
    BEGIN_PROFILE_INTERVAL();
    struct shim_ipc_msg_obj * msg = create_ipc_msg_duplex_on_stack(
                                        IPC_PID_NOP,
                                        sizeof(struct shim_ipc_pid_nop) +
                                        len, dest);
    struct shim_ipc_pid_nop * msgin =
                (struct shim_ipc_pid_nop *) &msg->msg.msg;

    msgin->count = count * 2;
    memcpy(msgin->payload, buf, len);

    debug("ipc send to %u: IPC_PID_NOP(%d)\n", dest, count * 2);

    SAVE_PROFILE_INTERVAL(ipc_pid_nop_send);

    return do_ipc_duplex(msg, port, NULL, NULL);
}

int ipc_pid_nop_callback (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    struct shim_ipc_pid_nop * msgin =
                        (struct shim_ipc_pid_nop *) &msg->msg;

    debug("ipc callback from %u: IPC_PID_NOP(%d)\n", msg->src,
          msgin->count);

    if (!(--msgin->count)) {
        struct shim_ipc_msg_obj * obj = find_ipc_msg_duplex(port, msg->seq);
        if (obj && obj->thread)
            thread_wakeup(obj->thread);

        SAVE_PROFILE_INTERVAL(ipc_pid_nop_callback);
        return 0;
    }

    SAVE_PROFILE_INTERVAL(ipc_pid_nop_callback);

    debug("ipc send to %u: IPC_PID_NOP(%d)\n", msg->src,
          msgin->count);

    int ret = send_ipc_message(msg, port);
    SAVE_PROFILE_INTERVAL(ipc_pid_nop_send);
    return ret;
}

DEFINE_PROFILE_INTERVAL(ipc_pid_sendrpc_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_pid_sendrpc_callback, ipc);

int ipc_pid_sendrpc_send (IDTYPE pid, IDTYPE sender, const void * buf,
                          int len)
{
    BEGIN_PROFILE_INTERVAL();
    int ret = 0;
    IDTYPE dest;
    struct shim_ipc_port * port = NULL;

    if ((ret = get_pid_port(pid, &dest, &port)) < 0)
        return ret;

    struct shim_ipc_msg * msg = create_ipc_msg_on_stack(
                                     IPC_PID_SENDRPC,
                                     sizeof(struct shim_ipc_pid_sendrpc) +
                                     len, dest);
    struct shim_ipc_pid_sendrpc * msgin =
                    (struct shim_ipc_pid_sendrpc *) &msg->msg;

    debug("ipc send to %u: IPC_PID_SENDPRC(%d)\n", dest, len);
    msgin->sender = sender;
    msgin->len = len;
    memcpy(msgin->payload, buf, len);

    ret = send_ipc_message(msg, port);
    put_ipc_port(port);
    SAVE_PROFILE_INTERVAL(ipc_pid_sendrpc_send);
    return ret;
}

DEFINE_LIST(rpcmsg);
struct rpcmsg {
    LIST_TYPE(rpcmsg) list;
    IDTYPE sender;
    int len;
    char payload[];
};

DEFINE_LIST(rpcreq);
struct rpcreq {
    LIST_TYPE(rpcreq) list;
    struct shim_thread * thread;
    IDTYPE sender;
    int len;
    void * buffer;
};

DEFINE_LISTP(rpcmsg);
DEFINE_LISTP(rpcreq);
static LISTP_TYPE(rpcmsg) rpc_msgs;
static LISTP_TYPE(rpcreq) rpc_reqs;
static LOCKTYPE rpc_queue_lock;

int get_rpc_msg (IDTYPE * sender, void * buf, int len)
{
    create_lock_runtime(&rpc_queue_lock);
    lock(rpc_queue_lock);

    if (!listp_empty(&rpc_msgs)) {
        struct rpcmsg * m = listp_first_entry(&rpc_msgs, struct rpcmsg, list);
        listp_del(m, &rpc_msgs, list);
        if (m->len < len)
            len = m->len;
        if (sender)
            *sender = m->sender;
        memcpy(buf, m->payload, len);
        unlock(rpc_queue_lock);
        return len;
    }

    struct rpcreq * r = malloc(sizeof(struct rpcreq));
    if (!r) {
        unlock(rpc_queue_lock);
        return -ENOMEM;
    }

    INIT_LIST_HEAD(r, list);
    r->sender = 0;
    r->len = len;
    r->buffer = buf;
    thread_setwait(&r->thread, NULL);
    listp_add_tail(r, &rpc_reqs, list);
    unlock(rpc_queue_lock);
    thread_sleep(NO_TIMEOUT);
    put_thread(r->thread);
    if (sender)
        *sender = r->sender;
    return r->len;
}

int ipc_pid_sendrpc_callback (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    int ret = 0;
    struct shim_ipc_pid_sendrpc * msgin =
                        (struct shim_ipc_pid_sendrpc *) msg->msg;

    debug("ipc callback from %u: IPC_PID_SENDPRC(%u, %d)\n", msg->src,
          msgin->sender, msgin->len);

    create_lock_runtime(&rpc_queue_lock);
    lock(rpc_queue_lock);

    if (!listp_empty(&rpc_reqs)) {
        struct rpcreq * r = listp_first_entry(&rpc_reqs, struct rpcreq, list);
        listp_del(r, &rpc_reqs, list);
        if (msgin->len < r->len)
            r->len = msgin->len;
        r->sender = msgin->sender;
        memcpy(r->buffer, msgin->payload, r->len);
        thread_wakeup(r->thread);
        goto out;
    }

    struct rpcmsg * m = malloc(sizeof(struct rpcmsg) + msgin->len);
    if (!m) {
        ret = -ENOMEM;
        goto out;
    }

    INIT_LIST_HEAD(m, list);
    m->sender = msgin->sender;
    m->len = msgin->len;
    memcpy(m->payload, msgin->payload, msgin->len);
    listp_add_tail(m, &rpc_msgs, list);
out:
    unlock(rpc_queue_lock);
    SAVE_PROFILE_INTERVAL(ipc_pid_sendrpc_callback);
    return ret;
}
