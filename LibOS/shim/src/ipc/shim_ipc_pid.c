/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

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

    return add_ipc_subrange(cur_thread->tid, g_self_vmid);
}

static int ipc_pid_kill_send(enum kill_type type, IDTYPE sender, IDTYPE dest_pid, IDTYPE target,
                             int sig) {
    int ret;

    IDTYPE dest = 0;
    if (type == KILL_ALL) {
        if (g_process_ipc_ids.leader_vmid) {
            dest = g_process_ipc_ids.leader_vmid;
        }
    } else {
        ret = find_owner(dest_pid, &dest);
        if (ret < 0) {
            return ret;
        }
    }

    struct shim_ipc_pid_kill msgin = {
        .sender = sender,
        .type = type,
        .id = target,
        .signum = sig,
    };

    size_t total_msg_size    = get_ipc_msg_size(sizeof(msgin));
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_PID_KILL, total_msg_size);
    memcpy(&msg->data, &msgin, sizeof(msgin));

    if (type == KILL_ALL && !g_process_ipc_ids.leader_vmid) {
        log_debug("IPC broadcast: IPC_MSG_PID_KILL(%u, %d, %u, %d)\n", sender, type, dest_pid, sig);
        ret = broadcast_ipc(msg, /*exclude_id=*/0);
    } else {
        log_debug("IPC send to %u: IPC_MSG_PID_KILL(%u, %d, %u, %d)\n", dest, sender, type,
                  dest_pid, sig);
        ret = send_ipc_message(msg, dest);
    }

    return ret;
}

int ipc_kill_process(IDTYPE sender, IDTYPE target, int sig) {
    return ipc_pid_kill_send(KILL_PROCESS, sender, target, target, sig);
}

int ipc_kill_thread(IDTYPE sender, IDTYPE dest_pid, IDTYPE target, int sig) {
    return ipc_pid_kill_send(KILL_THREAD, sender, dest_pid, target, sig);
}

int ipc_kill_pgroup(IDTYPE sender, IDTYPE pgid, int sig) {
    return ipc_pid_kill_send(KILL_PGROUP, sender, pgid, pgid, sig);
}

int ipc_kill_all(IDTYPE sender, int sig) {
    return ipc_pid_kill_send(KILL_ALL, sender, /*dest_pid=*/0, /*target=*/0, sig);
}

int ipc_pid_kill_callback(IDTYPE src, void* data, unsigned long seq) {
    __UNUSED(seq);
    struct shim_ipc_pid_kill* msgin = (struct shim_ipc_pid_kill*)data;

    log_debug("IPC callback from %u: IPC_MSG_PID_KILL(%u, %d, %u, %d)\n", src, msgin->sender,
              msgin->type, msgin->id, msgin->signum);

    if (msgin->signum == 0) {
        /* If signal number is 0, then no signal is sent, but process existence is still checked. */
        return 0;
    }

    int ret = 0;

    switch (msgin->type) {
        case KILL_THREAD:
            ret = do_kill_thread(msgin->sender, g_process.pid, msgin->id, msgin->signum);
            break;
        case KILL_PROCESS:
            assert(g_process.pid == msgin->id);
            ret = do_kill_proc(msgin->sender, msgin->id, msgin->signum);
            break;
        case KILL_PGROUP:
            ret = do_kill_pgroup(msgin->sender, msgin->id, msgin->signum);
            break;
        case KILL_ALL:
            if (!g_process_ipc_ids.leader_vmid) {
                size_t total_msg_size = get_ipc_msg_size(sizeof(*msgin));
                struct shim_ipc_msg* msg = __alloca(total_msg_size);
                init_ipc_msg(msg, IPC_MSG_PID_KILL, total_msg_size);
                memcpy(&msg->data, msgin, sizeof(*msgin));
                ret = broadcast_ipc(msg, src);
                if (ret < 0) {
                    break;
                }
            }
            ret = do_kill_proc(msgin->sender, g_process.pid, msgin->signum);
            break;
    }
    return ret;
}

int ipc_pid_getstatus_send(IDTYPE dest, int npids, IDTYPE* pids, struct pid_status** status) {
    struct shim_ipc_pid_getstatus msgin = {
        .npids = npids,
    };
    size_t total_msg_size = get_ipc_msg_with_ack_size(sizeof(msgin) + sizeof(IDTYPE) * npids);
    struct shim_ipc_msg_with_ack* msg = __alloca(total_msg_size);
    init_ipc_msg_with_ack(msg, IPC_MSG_PID_GETSTATUS, total_msg_size);
    msg->private = status;

    memcpy(&msg->msg.data, &msgin, sizeof(msgin));
    memcpy(&((struct shim_ipc_pid_getstatus*)&msg->msg.data)->pids, pids, sizeof(IDTYPE) * npids);

    log_debug("ipc send to %u: IPC_MSG_PID_GETSTATUS(%d, [%u, ...])\n", dest, npids, pids[0]);

    return send_ipc_message_with_ack(msg, dest, NULL);
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

int ipc_pid_getstatus_callback(IDTYPE src, void* data, unsigned long seq) {
    struct shim_ipc_pid_getstatus* msgin = (struct shim_ipc_pid_getstatus*)data;
    int ret = 0;

    log_debug("ipc callback from %u: IPC_MSG_PID_GETSTATUS(%d, [%u, ...])\n", src, msgin->npids,
              msgin->pids[0]);

    struct thread_status status;
    status.npids   = msgin->npids;
    status.pids    = msgin->pids;
    status.nstatus = 0;
    status.status  = __alloca(sizeof(struct pid_status) * msgin->npids);

    ret = walk_thread_list(&check_thread, &status, /*one_shot=*/false);
    if (ret < 0 && ret != -ESRCH)
        goto out;

    ret = ipc_pid_retstatus_send(src, status.nstatus, status.status, seq);
out:
    return ret;
}

int ipc_pid_retstatus_send(IDTYPE dest, int nstatus, struct pid_status* status, unsigned long seq) {
    struct shim_ipc_pid_retstatus msgin = {
        .nstatus = nstatus,
    };
    size_t total_msg_size = get_ipc_msg_size(sizeof(msgin) + sizeof(struct pid_status) * nstatus);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_PID_RETSTATUS, total_msg_size);
    msg->header.seq = seq;

    memcpy(&msg->data, &msgin, sizeof(msgin));
    memcpy(&((struct shim_ipc_pid_retstatus*)&msg->data)->status, status,
           sizeof(struct pid_status) * nstatus);

    if (nstatus)
        log_debug("ipc send to %u: IPC_MSG_PID_RETSTATUS(%d, [%u, ...])\n", dest, nstatus,
                  status[0].pid);
    else
        log_debug("ipc send to %u: IPC_MSG_PID_RETSTATUS(0, [])\n", dest);

    return send_ipc_message(msg, dest);
}

struct retstatus_args {
    struct pid_status* status;
    int retval;
};

static void set_msg_retstatus(struct shim_ipc_msg_with_ack* req_msg, void* _data) {
    if (!req_msg) {
        return;
    }

    struct retstatus_args* data = _data;

    struct pid_status** status = (struct pid_status**)req_msg->private;
    if (status) {
        *status = data->status;
        req_msg->retval = data->retval;
        data->status = NULL;
    }

    assert(req_msg->thread);
    thread_wakeup(req_msg->thread);
}

int ipc_pid_retstatus_callback(IDTYPE src, void* data, unsigned long seq) {
    struct shim_ipc_pid_retstatus* msgin = (struct shim_ipc_pid_retstatus*)data;

    if (msgin->nstatus) {
        log_debug("ipc callback from %u: IPC_MSG_PID_RETSTATUS(%d, [%u, ...])\n", src,
                  msgin->nstatus, msgin->status[0].pid);
    } else {
        log_debug("ipc callback from %u: IPC_MSG_PID_RETSTATUS(0, [])\n", src);
    }

    struct retstatus_args args = {
        .retval = msgin->nstatus
    };
    args.status = malloc_copy(msgin->status, sizeof(*args.status) * msgin->nstatus);
    if (!args.status) {
        args.retval = 0;
    }

    ipc_msg_response_handle(seq, set_msg_retstatus, &args);

    free(args.status);
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
    int ret;

    if ((ret = find_owner(pid, &dest)) < 0)
        return ret;

    struct shim_ipc_pid_getmeta msgin = {
        .pid = pid,
        .code = code,
    };
    size_t total_msg_size = get_ipc_msg_with_ack_size(sizeof(msgin));
    struct shim_ipc_msg_with_ack* msg = __alloca(total_msg_size);
    init_ipc_msg_with_ack(msg, IPC_MSG_PID_GETMETA, total_msg_size);
    msg->private = data;

    memcpy(&msg->msg.data, &msgin, sizeof(msgin));

    log_debug("ipc send to %u: IPC_MSG_PID_GETMETA(%u, %s)\n", dest, pid, pid_meta_code_str[code]);

    return send_ipc_message_with_ack(msg, dest, NULL);
}

int ipc_pid_getmeta_callback(IDTYPE src, void* msg_data, unsigned long seq) {
    struct shim_ipc_pid_getmeta* msgin = (struct shim_ipc_pid_getmeta*)msg_data;
    int ret = 0;

    log_debug("ipc callback from %u: IPC_MSG_PID_GETMETA(%u, %s)\n", src, msgin->pid,
              pid_meta_code_str[msgin->code]);

    struct shim_thread* thread = lookup_thread(msgin->pid);
    void* data = NULL;
    size_t datasize = 0;
    size_t bufsize = 0;

    if (!thread) {
        ret = -ESRCH;
        goto out;
    }

    switch (msgin->code) {
        case PID_META_CRED:
            lock(&thread->lock);
            bufsize = sizeof(IDTYPE) * 2;
            data = malloc(bufsize);
            if (!data) {
                ret = -ENOMEM;
                goto out;
            }
            datasize = bufsize;
            ((IDTYPE*)data)[0] = thread->uid;
            ((IDTYPE*)data)[1] = thread->gid;
            unlock(&thread->lock);
            break;
        case PID_META_EXEC:
        case PID_META_CWD:
        case PID_META_ROOT: {
            lock(&g_process.fs_lock);

            struct shim_dentry* dent = NULL;
            switch (msgin->code) {
               case PID_META_EXEC:
                   if (g_process.exec)
                       dent = g_process.exec->dentry;
                   break;
               case PID_META_CWD:
                   dent = g_process.cwd;
                   break;
               case PID_META_ROOT:
                   dent = g_process.root;
                   break;
               default:
                   break;
            }
            if (!dent) {
                unlock(&g_process.fs_lock);
                ret = -ENOENT;
                break;
            }
            if ((ret = dentry_abs_path(dent, (char**)&data, &bufsize)) < 0) {
                unlock(&g_process.fs_lock);
                goto out;
            }
            datasize = bufsize - 1;
            unlock(&g_process.fs_lock);
            break;
        }
        default:
            ret = -EINVAL;
            break;
    }

    put_thread(thread);

    if (ret < 0)
        goto out;

    ret = ipc_pid_retmeta_send(src, msgin->pid, msgin->code, data, datasize, seq);
out:
    free(data);
    return ret;
}

int ipc_pid_retmeta_send(IDTYPE dest, IDTYPE pid, enum pid_meta_code code, const void* data,
                         int datasize, unsigned long seq) {
    struct shim_ipc_pid_retmeta msgin = {
        .pid = pid,
        .code = code,
        .datasize = datasize,
    };
    size_t total_msg_size    = get_ipc_msg_size(sizeof(msgin) + datasize);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_PID_RETMETA, total_msg_size);
    msg->header.seq = seq;

    memcpy(&msg->data, &msgin, sizeof(msgin));
    memcpy(&((struct shim_ipc_pid_retmeta*)&msg->data)->data, data, datasize);

    log_debug("ipc send to %u: IPC_MSG_PID_RETMETA(%d, %s, %d)\n", dest, pid,
              pid_meta_code_str[code], datasize);

    return send_ipc_message(msg, dest);
}

struct retmeta_args {
    void* data;
    int retval;
};

static void set_msg_retmeta(struct shim_ipc_msg_with_ack* req_msg, void* _args) {
    if (!req_msg) {
        return;
    }

    struct retmeta_args* args = _args;

    void** data = (void**)req_msg->private;
    if (data) {
        *data = args->data;
        args->data = NULL;
    }
    req_msg->retval = args->retval;

    assert(req_msg->thread);
    thread_wakeup(req_msg->thread);
}

int ipc_pid_retmeta_callback(IDTYPE src, void* data, unsigned long seq) {
    struct shim_ipc_pid_retmeta* msgin = (struct shim_ipc_pid_retmeta*)data;

    log_debug("ipc callback from %u: IPC_MSG_PID_RETMETA(%u, %s, %d)\n", src, msgin->pid,
              pid_meta_code_str[msgin->code], msgin->datasize);

    struct retmeta_args args = {
        .retval = msgin->datasize,
    };
    if (msgin->datasize) {
        args.data = malloc_copy(msgin->data, msgin->datasize);
        if (!args.data) {
            args.retval = 0;
        }
    }

    ipc_msg_response_handle(seq, set_msg_retmeta, &args);

    free(args.data);
    return 0;
}
