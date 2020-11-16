/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains functions and callbacks to handle IPC of PID namespace.
 */

#include <errno.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_checkpoint.h"
#include "shim_fs.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_thread.h"

int init_ns_pid(void) {
    struct shim_thread* cur_thread = get_cur_thread();
    /* This function should be called only in initialization (but after process and main thread are
     * initialized), so we should have only one thread, whose tid is equal to the process pid. */
    assert(cur_thread->tid == g_process.pid);

    struct shim_ipc_info* info = NULL;
    int ret = get_ipc_info_cur_process(&info);
    if (ret < 0) {
        return ret;
    }

    ret = add_ipc_subrange(cur_thread->tid, info->vmid, qstrgetstr(&info->uri));

    put_ipc_info(info);
    return ret;
}

// TODO: for KILL_THREAD we don't know which process has a thread with given id
int ipc_pid_kill_send(IDTYPE sender, IDTYPE target, enum kill_type type, int signum) {
    int ret;

    if (!signum) {
        /* if sig is 0, then no signal is sent, but error checking on kill()
         * is still performed (used to check for existence of processes) */
        ret = 0;
        goto out;
    }

    IDTYPE dest;
    struct shim_ipc_port* port;
    if (type == KILL_ALL) {
        dest = 0;
        port = NULL;
    } else {
        ret = connect_owner(target, &port, &dest);
        if (ret < 0)
            goto out;
    }

    size_t total_msg_size    = get_ipc_msg_size(sizeof(struct shim_ipc_pid_kill));
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_PID_KILL, total_msg_size, dest);

    struct shim_ipc_pid_kill* msgin = (struct shim_ipc_pid_kill*)&msg->msg;
    msgin->sender                   = sender;
    msgin->type                     = type;
    msgin->id                       = target;
    msgin->signum                   = signum;

    if (type == KILL_ALL) {
        debug("IPC broadcast: IPC_MSG_PID_KILL(%u, %d, %u, %d)\n", sender, type, target, signum);
        ret = broadcast_ipc(msg, IPC_PORT_DIRECTCHILD | IPC_PORT_DIRECTPARENT,
                            /*exclude_port=*/NULL);
    } else {
        debug("IPC send to %u: IPC_MSG_PID_KILL(%u, %d, %u, %d)\n", dest & 0xFFFF, sender, type,
              target, signum);
        ret = send_ipc_message(msg, port);
        put_ipc_port(port);
    }

out:
    return ret;
}

int ipc_pid_kill_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_pid_kill* msgin = (struct shim_ipc_pid_kill*)msg->msg;

    debug("IPC callback from %u: IPC_MSG_PID_KILL(%u, %d, %u, %d)\n", msg->src & 0xFFFF,
          msgin->sender, msgin->type, msgin->id, msgin->signum);

    int ret = 0;

    switch (msgin->type) {
        case KILL_THREAD:
            ret = do_kill_thread(msgin->sender, 0, msgin->id, msgin->signum, /*use_ipc=*/true);
            break;
        case KILL_PROCESS:
            ret = do_kill_proc(msgin->sender, msgin->id, msgin->signum, /*use_ipc=*/true);
            break;
        case KILL_PGROUP:
            ret = do_kill_pgroup(msgin->sender, msgin->id, msgin->signum);
            break;
        case KILL_ALL:
            broadcast_ipc(msg, IPC_PORT_DIRECTCHILD | IPC_PORT_DIRECTPARENT, port);
            ret = do_kill_proc(msgin->sender, msgin->id, msgin->signum, /*use_ipc=*/false);
            break;
    }
    return ret;
}

int ipc_pid_getstatus_send(struct shim_ipc_port* port, IDTYPE dest, int npids, IDTYPE* pids,
                           struct pid_status** status) {
    size_t total_msg_size =
        get_ipc_msg_with_ack_size(sizeof(struct shim_ipc_pid_getstatus) + sizeof(IDTYPE) * npids);
    struct shim_ipc_msg_with_ack* msg = __alloca(total_msg_size);
    init_ipc_msg_with_ack(msg, IPC_MSG_PID_GETSTATUS, total_msg_size, dest);

    struct shim_ipc_pid_getstatus* msgin = (struct shim_ipc_pid_getstatus*)&msg->msg.msg;
    msgin->npids                         = npids;
    memcpy(msgin->pids, pids, sizeof(IDTYPE) * npids);

    debug("ipc send to %u: IPC_MSG_PID_GETSTATUS(%d, [%u, ...])\n", dest, npids, pids[0]);

    return send_ipc_message_with_ack(msg, port, NULL, status);
}

struct thread_status {
    int npids;
    IDTYPE* pids;
    int nstatus;
    struct pid_status* status;
};

static int check_thread(struct shim_thread* thread, void* arg) {
    struct thread_status* status = (struct thread_status*)arg;
    int ret = 0;

    lock(&thread->lock);

    for (int i = 0; i < status->npids; i++)
        if (status->pids[i] == thread->tid) {
            status->status[status->nstatus].pid  = thread->tid;
            status->status[status->nstatus].tgid = g_process.pid;
            status->status[status->nstatus].pgid = __atomic_load_n(&g_process.pgid,
                                                                   __ATOMIC_ACQUIRE);
            status->nstatus++;
            ret = 1;
            goto out;
        }

out:
    unlock(&thread->lock);
    return ret;
}

int ipc_pid_getstatus_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_pid_getstatus* msgin = (struct shim_ipc_pid_getstatus*)msg->msg;
    int ret = 0;

    debug("ipc callback from %u: IPC_MSG_PID_GETSTATUS(%d, [%u, ...])\n", msg->src, msgin->npids,
          msgin->pids[0]);

    struct thread_status status;
    status.npids   = msgin->npids;
    status.pids    = msgin->pids;
    status.nstatus = 0;
    status.status  = __alloca(sizeof(struct pid_status) * msgin->npids);

    ret = walk_thread_list(&check_thread, &status, /*one_shot=*/false);
    if (ret < 0 && ret != -ESRCH)
        goto out;

    ret = ipc_pid_retstatus_send(port, msg->src, status.nstatus, status.status, msg->seq);
out:
    return ret;
}

int ipc_pid_retstatus_send(struct shim_ipc_port* port, IDTYPE dest, int nstatus,
                           struct pid_status* status, unsigned long seq) {
    size_t total_msg_size = get_ipc_msg_size(sizeof(struct shim_ipc_pid_retstatus) +
                                             sizeof(struct pid_status) * nstatus);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_PID_RETSTATUS, total_msg_size, dest);

    struct shim_ipc_pid_retstatus* msgin = (struct shim_ipc_pid_retstatus*)&msg->msg;

    msgin->nstatus = nstatus;
    memcpy(msgin->status, status, sizeof(struct pid_status) * nstatus);
    msg->seq = seq;

    if (nstatus)
        debug("ipc send to %u: IPC_MSG_PID_RETSTATUS(%d, [%u, ...])\n", dest, nstatus,
              status[0].pid);
    else
        debug("ipc send to %u: IPC_MSG_PID_RETSTATUS(0, [])\n", dest);

    return send_ipc_message(msg, port);
}

int ipc_pid_retstatus_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_pid_retstatus* msgin = (struct shim_ipc_pid_retstatus*)msg->msg;

    if (msgin->nstatus)
        debug("ipc callback from %u: IPC_MSG_PID_RETSTATUS(%d, [%u, ...])\n", msg->src,
              msgin->nstatus, msgin->status[0].pid);
    else
        debug("ipc callback from %u: IPC_MSG_PID_RETSTATUS(0, [])\n", msg->src);

    struct shim_ipc_msg_with_ack* obj = pop_ipc_msg_with_ack(port, msg->seq);
    if (obj) {
        struct pid_status** status = (struct pid_status**)obj->private;

        if (status) {
            *status = malloc_copy(msgin->status, sizeof(struct pid_status) * msgin->nstatus);

            obj->retval = msgin->nstatus;
        }

        if (obj->thread)
            thread_wakeup(obj->thread);
    }

    return 0;
}

static const char* pid_meta_code_str[4] = {
    "CRED",
    "EXEC",
    "CWD",
    "ROOT",
};

int ipc_pid_getmeta_send(IDTYPE pid, enum pid_meta_code code, void** data) {
    IDTYPE dest;
    struct shim_ipc_port* port = NULL;
    int ret;

    if ((ret = connect_owner(pid, &port, &dest)) < 0)
        goto out;

    size_t total_msg_size = get_ipc_msg_with_ack_size(sizeof(struct shim_ipc_pid_getmeta));
    struct shim_ipc_msg_with_ack* msg = __alloca(total_msg_size);
    init_ipc_msg_with_ack(msg, IPC_MSG_PID_GETMETA, total_msg_size, dest);

    struct shim_ipc_pid_getmeta* msgin = (struct shim_ipc_pid_getmeta*)&msg->msg.msg;
    msgin->pid  = pid;
    msgin->code = code;

    debug("ipc send to %u: IPC_MSG_PID_GETMETA(%u, %s)\n", dest, pid, pid_meta_code_str[code]);

    ret = send_ipc_message_with_ack(msg, port, NULL, data);
    put_ipc_port(port);
out:
    return ret;
}

int ipc_pid_getmeta_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_pid_getmeta* msgin = (struct shim_ipc_pid_getmeta*)msg->msg;
    int ret = 0;

    debug("ipc callback from %u: IPC_MSG_PID_GETMETA(%u, %s)\n", msg->src, msgin->pid,
          pid_meta_code_str[msgin->code]);

    struct shim_thread* thread = lookup_thread(msgin->pid);
    void* data                 = NULL;
    size_t datasize            = 0;
    size_t bufsize             = 0;

    if (!thread) {
        ret = -ESRCH;
        goto out;
    }

    switch (msgin->code) {
        case PID_META_CRED:
            lock(&thread->lock);
            bufsize            = sizeof(IDTYPE) * 2;
            data               = __alloca(bufsize);
            datasize           = bufsize;
            ((IDTYPE*)data)[0] = thread->uid;
            ((IDTYPE*)data)[1] = thread->gid;
            unlock(&thread->lock);
            break;
        case PID_META_EXEC:
            lock(&g_process.fs_lock);
            if (!g_process.exec || !g_process.exec->dentry) {
                unlock(&g_process.fs_lock);
                ret = -ENOENT;
                break;
            }
            bufsize = dentry_get_path_size(g_process.exec->dentry);
            data = __alloca(bufsize);
            datasize = bufsize - 1;
            dentry_get_path(g_process.exec->dentry, data);
            unlock(&g_process.fs_lock);
            break;
        case PID_META_CWD:
            lock(&g_process.fs_lock);
            if (!g_process.cwd) {
                unlock(&g_process.fs_lock);
                ret = -ENOENT;
                break;
            }
            bufsize = dentry_get_path_size(g_process.cwd);
            data = __alloca(bufsize);
            datasize = bufsize - 1;
            dentry_get_path(g_process.cwd, data);
            unlock(&g_process.fs_lock);
            break;
        case PID_META_ROOT:
            lock(&g_process.fs_lock);
            if (!g_process.root) {
                unlock(&g_process.fs_lock);
                ret = -ENOENT;
                break;
            }
            bufsize = dentry_get_path_size(g_process.root);
            data = __alloca(bufsize);
            datasize = bufsize - 1;
            dentry_get_path(g_process.root, data);
            unlock(&g_process.fs_lock);
            break;
        default:
            ret = -EINVAL;
            break;
    }

    put_thread(thread);

    if (ret < 0)
        goto out;

    ret = ipc_pid_retmeta_send(port, msg->src, msgin->pid, msgin->code, data, datasize, msg->seq);
out:
    return ret;
}

int ipc_pid_retmeta_send(struct shim_ipc_port* port, IDTYPE dest, IDTYPE pid,
                         enum pid_meta_code code, const void* data, int datasize,
                         unsigned long seq) {
    size_t total_msg_size    = get_ipc_msg_size(sizeof(struct shim_ipc_pid_retmeta) + datasize);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_PID_RETMETA, total_msg_size, dest);
    struct shim_ipc_pid_retmeta* msgin = (struct shim_ipc_pid_retmeta*)&msg->msg;

    msgin->pid      = pid;
    msgin->code     = code;
    msgin->datasize = datasize;
    memcpy(msgin->data, data, datasize);
    msg->seq = seq;

    debug("ipc send to %u: IPC_MSG_PID_RETMETA(%d, %s, %d)\n", dest, pid, pid_meta_code_str[code],
          datasize);

    return send_ipc_message(msg, port);
}

int ipc_pid_retmeta_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_pid_retmeta* msgin = (struct shim_ipc_pid_retmeta*)msg->msg;

    debug("ipc callback from %u: IPC_MSG_PID_RETMETA(%u, %s, %d)\n", msg->src, msgin->pid,
          pid_meta_code_str[msgin->code], msgin->datasize);

    struct shim_ipc_msg_with_ack* obj = pop_ipc_msg_with_ack(port, msg->seq);
    if (obj) {
        void** data = (void**)obj->private;

        if (data)
            *data = msgin->datasize ? malloc_copy(msgin->data, msgin->datasize) : NULL;

        obj->retval = msgin->datasize;

        if (obj->thread)
            thread_wakeup(obj->thread);
    }

    return 0;
}
