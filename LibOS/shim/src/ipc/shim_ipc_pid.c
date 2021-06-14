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
        ret = ipc_broadcast(msg, /*exclude_id=*/0);
    } else {
        log_debug("IPC send to %u: IPC_MSG_PID_KILL(%u, %d, %u, %d)\n", dest, sender, type,
                  dest_pid, sig);

        void* resp = NULL;
        ret = ipc_send_msg_and_get_response(dest, msg, &resp);
        if (ret < 0) {
            /* During sending the message to destination process, it may have terminated and became
             * a zombie; kill shouldn't fail in this case. The below logic checks if the destination
             * process is _our_ zombie child -- this doesn't work for a case when the destination
             * process is not our child (the logic will just loop couple times and return error).
             * We assume that the latter case doesn't happen in real applications. */
            int wait_iter = 3;
            while (wait_iter--) {
                if (is_zombie_process(dest_pid)) {
                    log_debug("IPC send to terminated child process %u is dropped\n", dest_pid);
                    ret = 0;
                    break;
                } else {
                    /* There may be a race between receiving a SIGCHLD notification in the IPC
                     * worker thread (thus marking the destination process as a zombie) and sending
                     * a KILL in this thread, so we sleep for a bit and check for zombie again. */
                    uint64_t timeout_us = 10000;
                    thread_wait(&timeout_us, /*ignore_pending_signals=*/true);
                }
            }
        } else {
            ret = *(int*)resp;
            free(resp);
        }
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

int ipc_pid_kill_callback(IDTYPE src, void* data, uint64_t seq) {
    struct shim_ipc_pid_kill* msgin = (struct shim_ipc_pid_kill*)data;

    log_debug("IPC callback from %u: IPC_MSG_PID_KILL(%u, %d, %u, %d)\n", src, msgin->sender,
              msgin->type, msgin->id, msgin->signum);

    int ret = 0;
    bool response_expected = true;

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
                ret = ipc_broadcast(msg, src);
                if (ret < 0) {
                    break;
                }
            } else {
                response_expected = false;
            }

            ret = do_kill_proc(msgin->sender, g_process.pid, msgin->signum);
            break;
        default:
            BUG();
    }

    if (response_expected) {
        static_assert(SAME_TYPE(ret, int), "receiver assumes int");
        size_t total_msg_size = get_ipc_msg_size(sizeof(ret));
        struct shim_ipc_msg* msg = __alloca(total_msg_size);
        init_ipc_response(msg, seq, total_msg_size);
        memcpy(&msg->data, &ret, sizeof(ret));

        ret = ipc_send_message(src, msg);
    } else {
        ret = 0;
    }
    return ret;
}

int ipc_pid_getstatus(IDTYPE dest, int npids, IDTYPE* pids,
                      struct shim_ipc_pid_retstatus** status) {
    struct shim_ipc_pid_getstatus msgin = {
        .npids = npids,
    };
    size_t total_msg_size = get_ipc_msg_size(sizeof(msgin) + sizeof(IDTYPE) * npids);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_PID_GETSTATUS, total_msg_size);

    memcpy(&msg->data, &msgin, sizeof(msgin));
    memcpy(&((struct shim_ipc_pid_getstatus*)&msg->data)->pids, pids, sizeof(IDTYPE) * npids);

    log_debug("ipc send to %u: IPC_MSG_PID_GETSTATUS(%d, [%u, ...])\n", dest, npids, pids[0]);

    void* resp = NULL;
    int ret = ipc_send_msg_and_get_response(dest, msg, &resp);
    if (ret < 0) {
        return ret;
    }

    *status = resp;
    return 0;
}

struct thread_status {
    size_t npids;
    IDTYPE* pids;
    struct shim_ipc_pid_retstatus retstatus;
};

static int check_thread(struct shim_thread* thread, void* arg) {
    struct thread_status* status = (struct thread_status*)arg;
    int ret = 0;

    lock(&thread->lock);

    for (size_t i = 0; i < status->npids; i++)
        if (status->pids[i] == thread->tid) {
            size_t old_count = status->retstatus.count++;
            status->retstatus.status[old_count].pid = thread->tid;
            status->retstatus.status[old_count].tgid = g_process.pid;
            status->retstatus.status[old_count].pgid = __atomic_load_n(&g_process.pgid,
                                                                       __ATOMIC_ACQUIRE);
            ret = 1;
            goto out;
        }

out:
    unlock(&thread->lock);
    return ret;
}

int ipc_pid_getstatus_callback(IDTYPE src, void* data, uint64_t seq) {
    struct shim_ipc_pid_getstatus* msgin = (struct shim_ipc_pid_getstatus*)data;
    int ret = 0;

    log_debug("ipc callback from %u: IPC_MSG_PID_GETSTATUS(%lu, [%u, ...])\n", src, msgin->npids,
              msgin->pids[0]);

    struct thread_status* status = __alloca(sizeof(*status)
                                            + sizeof(struct pid_status) * msgin->npids);
    status->npids = msgin->npids;
    status->pids = msgin->pids;
    status->retstatus.count = 0;

    ret = walk_thread_list(&check_thread, &status, /*one_shot=*/false);
    if (ret < 0 && ret != -ESRCH)
        return ret;

    size_t msg_content_size = sizeof(struct shim_ipc_pid_retstatus)
                              + sizeof(struct pid_status) * status->retstatus.count;
    size_t total_msg_size = get_ipc_msg_size(msg_content_size);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_response(msg, seq, total_msg_size);

    memcpy(&msg->data, &status->retstatus, msg_content_size);

    if (status->retstatus.count) {
        log_debug("IPC send to %u: shim_ipc_pid_retstatus{%lu, ...}\n", src,
                  status->retstatus.count);
    } else {
        log_debug("IPC send to %u: shim_ipc_pid_retstatus{0, []}\n", src);
    }

    return ipc_send_message(src, msg);
}

static const char* pid_meta_code_str[4] = {
    "CRED",
    "EXEC",
    "CWD",
    "ROOT",
};

int ipc_pid_getmeta(IDTYPE pid, enum pid_meta_code code, struct shim_ipc_pid_retmeta** data) {
    IDTYPE dest;
    int ret;

    if ((ret = find_owner(pid, &dest)) < 0)
        return ret;

    struct shim_ipc_pid_getmeta msgin = {
        .pid = pid,
        .code = code,
    };
    size_t total_msg_size = get_ipc_msg_size(sizeof(msgin));
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_PID_GETMETA, total_msg_size);

    memcpy(&msg->data, &msgin, sizeof(msgin));

    log_debug("ipc send to %u: IPC_MSG_PID_GETMETA(%u, %s)\n", dest, pid, pid_meta_code_str[code]);

    struct shim_ipc_pid_retmeta* resp = NULL;
    ret = ipc_send_msg_and_get_response(dest, msg, (void**)&resp);
    if (ret < 0) {
        return ret;
    }
    if (resp->ret_val != 0) {
        ret = resp->ret_val;
        free(resp);
        return ret;
    }

    *data = resp;
    return 0;
}

int ipc_pid_getmeta_callback(IDTYPE src, void* msg_data, uint64_t seq) {
    struct shim_ipc_pid_getmeta* msgin = (struct shim_ipc_pid_getmeta*)msg_data;
    int ret = 0;

    log_debug("ipc callback from %u: IPC_MSG_PID_GETMETA(%u, %s)\n", src, msgin->pid,
              pid_meta_code_str[msgin->code]);

    struct shim_thread* thread = lookup_thread(msgin->pid);
    void* data = NULL;
    size_t datasize = 0;
    size_t bufsize = 0;
    int resp_ret_val = 0;

    if (!thread) {
        resp_ret_val = -ESRCH;
        goto out_send;
    }

    switch (msgin->code) {
        case PID_META_CRED:
            lock(&thread->lock);
            bufsize = sizeof(IDTYPE) * 2;
            data = malloc(bufsize);
            if (!data) {
                unlock(&thread->lock);
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
                   BUG();
            }
            if (!dent) {
                unlock(&g_process.fs_lock);
                ret = -ENOENT;
                goto out;
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
            BUG();
    }

out_send:;
    struct shim_ipc_pid_retmeta retmeta = {
        .datasize = datasize,
        .ret_val = resp_ret_val,
    };
    size_t total_msg_size = get_ipc_msg_size(sizeof(retmeta) + datasize);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_response(msg, seq, total_msg_size);

    memcpy(&msg->data, &retmeta, sizeof(retmeta));
    memcpy(&((struct shim_ipc_pid_retmeta*)&msg->data)->data, data, datasize);

    log_debug("IPC send to %u: shim_ipc_pid_retmeta{%lu, ...}\n", src, datasize);

    ret = ipc_send_message(src, msg);

out:
    if (thread) {
        put_thread(thread);
    }
    free(data);
    return ret;
}
