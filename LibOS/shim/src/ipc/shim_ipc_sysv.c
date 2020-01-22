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
 * This file contains functions and callbacks to handle IPC of SYSV namespace.
 */

#include <errno.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_checkpoint.h>
#include <shim_internal.h>
#include <shim_ipc.h>
#include <shim_sysv.h>
#include <shim_thread.h>

#define SYSV_RANGE_SIZE 128
#define SYSV_LEASE_TIME 1000

#define KEY_HASH(k)      ((k)->key)
#define KEY_COMP(k1, k2) ((k1)->key != (k2)->key || (k1)->type != (k2)->type)
#define KEY_COPY(k1, k2)         \
    do {                         \
        (k1)->key  = (k2)->key;  \
        (k1)->type = (k2)->type; \
    } while (0)

#define NS     sysv
#define NS_CAP SYSV
#define NS_KEY struct sysv_key

#define INCLUDE_IPC_NSIMPL
#include "shim_ipc_nsimpl.h"

int init_ns_sysv(void) {
    return init_namespace();
}

DEFINE_PROFILE_INTERVAL(ipc_sysv_delres_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_sysv_delres_callback, ipc);

int ipc_sysv_delres_send(struct shim_ipc_port* port, IDTYPE dest, IDTYPE resid,
                         enum sysv_type type) {
    BEGIN_PROFILE_INTERVAL();
    int ret    = 0;
    bool owned = false;

    if (!port) {
        if ((ret = connect_owner(resid, &port, &dest)) < 0)
            goto out;

        owned = true;
    }

    if (!owned) {
        size_t total_msg_size    = get_ipc_msg_size(sizeof(struct shim_ipc_sysv_delres));
        struct shim_ipc_msg* msg = __alloca(total_msg_size);
        init_ipc_msg(msg, IPC_SYSV_DELRES, total_msg_size, dest);

        struct shim_ipc_sysv_delres* msgin = (struct shim_ipc_sysv_delres*)&msg->msg;
        msgin->resid                       = resid;
        msgin->type                        = type;

        debug("ipc send to %u: IPC_SYSV_DELRES(%u, %s)\n", dest, resid, SYSV_TYPE_STR(type));

        ret = send_ipc_message(msg, port);
        goto out;
    }

    size_t total_msg_size           = get_ipc_msg_duplex_size(sizeof(struct shim_ipc_sysv_delres));
    struct shim_ipc_msg_duplex* msg = __alloca(total_msg_size);
    init_ipc_msg_duplex(msg, IPC_SYSV_DELRES, total_msg_size, dest);

    struct shim_ipc_sysv_delres* msgin = (struct shim_ipc_sysv_delres*)&msg->msg.msg;
    msgin->resid                       = resid;
    msgin->type                        = type;

    debug("ipc send to %u: IPC_SYSV_DELRES(%u, %s)\n", dest, resid, SYSV_TYPE_STR(type));

    ret = send_ipc_message_duplex(msg, port, NULL, NULL);
    put_ipc_port(port);
out:
    SAVE_PROFILE_INTERVAL(ipc_sysv_delres_send);
    return ret;
}

int ipc_sysv_delres_callback(IPC_CALLBACK_ARGS) {
    __UNUSED(port);

    BEGIN_PROFILE_INTERVAL();
    int ret                            = 0;
    struct shim_ipc_sysv_delres* msgin = (struct shim_ipc_sysv_delres*)&msg->msg;

    debug("ipc callback from %u: IPC_SYSV_DELRES(%u, %s)\n", msg->src, msgin->resid,
          SYSV_TYPE_STR(msgin->type));

    bool owned = false;
    ret        = -ENOENT;
    switch (msgin->type) {
        case SYSV_MSGQ: {
            struct shim_msg_handle* msgq = get_msg_handle_by_id(msgin->resid);
            if (!msgq)
                goto out;
            owned = msgq->owned;
            ret   = del_msg_handle(msgq);
            break;
        }
        case SYSV_SEM: {
            struct shim_sem_handle* sem = get_sem_handle_by_id(msgin->resid);
            if (!sem)
                goto out;
            owned = sem->owned;
            ret   = del_sem_handle(sem);
            break;
        }
        default:
            ret = -ENOSYS;
            break;
    }

    if (!ret)
        ret = owned ? RESPONSE_CALLBACK : 0;
out:
    SAVE_PROFILE_INTERVAL(ipc_sysv_delres_callback);
    return ret;
}

DEFINE_PROFILE_INTERVAL(ipc_sysv_movres_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_sysv_movres_callback, ipc);

int ipc_sysv_movres_send(struct sysv_client* client, IDTYPE owner, const char* uri, LEASETYPE lease,
                         IDTYPE resid, enum sysv_type type) {
    BEGIN_PROFILE_INTERVAL();
    int ret = 0;
    int len = strlen(uri);

    size_t total_msg_size    = get_ipc_msg_size(sizeof(struct shim_ipc_sysv_movres) + len);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_SYSV_MOVRES, total_msg_size, client->vmid);
    struct shim_ipc_sysv_movres* msgin = (struct shim_ipc_sysv_movres*)&msg->msg;
    msgin->resid                       = resid;
    msgin->type                        = type;
    msgin->owner                       = owner;
    msgin->lease                       = lease;
    memcpy(msgin->uri, uri, len + 1);
    msg->seq = client->seq;

    debug("ipc send to %u: IPC_SYSV_MOVRES(%u, %s, %u, %s)\n", client->vmid, resid,
          SYSV_TYPE_STR(type), owner, uri);

    ret = send_ipc_message(msg, client->port);
    SAVE_PROFILE_INTERVAL(ipc_sysv_movres_send);
    return ret;
}

int ipc_sysv_movres_callback(IPC_CALLBACK_ARGS) {
    BEGIN_PROFILE_INTERVAL();
    int ret                            = 0;
    struct shim_ipc_sysv_movres* msgin = (struct shim_ipc_sysv_movres*)&msg->msg;

    debug("ipc callback from %u: IPC_SYSV_MOVRES(%u, %s, %u, %s)\n", msg->src, msgin->resid,
          SYSV_TYPE_STR(msgin->type), msgin->owner, msgin->uri);

    struct shim_ipc_msg_duplex* obj = pop_ipc_msg_duplex(port, msg->seq);
    if (!obj)
        goto out;

    switch (msgin->type) {
        case SYSV_MSGQ:
        case SYSV_SEM:
            obj->retval = -EAGAIN;
            break;
        default:
            ret = -ENOSYS;
            goto out;
    }

    add_sysv_subrange(msgin->resid, msgin->owner, msgin->uri, &msgin->lease);

    if (obj->thread)
        thread_wakeup(obj->thread);

out:
    SAVE_PROFILE_INTERVAL(ipc_sysv_movres_callback);
    return ret;
}

DEFINE_PROFILE_INTERVAL(ipc_sysv_msgsnd_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_sysv_msgsnd_callback, ipc);

int ipc_sysv_msgsnd_send(struct shim_ipc_port* port, IDTYPE dest, IDTYPE msgid, long msgtype,
                         const void* buf, size_t size, unsigned long seq) {
    BEGIN_PROFILE_INTERVAL();
    int ret    = 0;
    bool owned = true;

    if (!dest) {
        if ((ret = connect_owner(msgid, &port, &dest)) < 0)
            goto out;

        owned = false;
    }

    size_t total_msg_size    = get_ipc_msg_size(sizeof(struct shim_ipc_sysv_msgsnd) + size);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_SYSV_MSGSND, total_msg_size, dest);
    struct shim_ipc_sysv_msgsnd* msgin = (struct shim_ipc_sysv_msgsnd*)&msg->msg;
    msgin->msgid                       = msgid;
    msgin->msgtype                     = msgtype;
    memcpy(msgin->msg, buf, size);
    msg->seq = seq;

    debug("ipc send to %u: IPC_SYSV_MSGSND(%u, %ld)\n", dest, msgid, msgtype);

    ret = send_ipc_message(msg, port);

    if (!owned)
        put_ipc_port(port);
out:
    SAVE_PROFILE_INTERVAL(ipc_sysv_msgsnd_send);
    return ret;
}

int ipc_sysv_msgsnd_callback(IPC_CALLBACK_ARGS) {
    BEGIN_PROFILE_INTERVAL();
    int ret                            = 0;
    struct shim_ipc_sysv_msgsnd* msgin = (struct shim_ipc_sysv_msgsnd*)&msg->msg;

    debug("ipc callback from %u: IPC_SYSV_MSGSND(%u, %ld)\n", msg->src, msgin->msgid,
          msgin->msgtype);

    size_t size = msg->size - sizeof(*msg) - sizeof(*msgin);

    if (msg->seq) {
        struct shim_ipc_msg_duplex* obj = pop_ipc_msg_duplex(port, msg->seq);
        void* priv                      = obj ? obj->private : NULL;

        if (priv) {
            struct shim_ipc_sysv_msgrcv* rcv = (struct shim_ipc_sysv_msgrcv*)obj->msg.msg;

            if (size > rcv->size)
                size = rcv->size;

            memcpy(priv, msgin->msg, size);
            obj->retval = size;
            if (obj->thread)
                thread_wakeup(obj->thread);
            goto out;
        }
    }

    struct shim_msg_handle* msgq = get_msg_handle_by_id(msgin->msgid);
    if (!msgq) {
        ret = -ENOENT;
        goto out;
    }

    if (msg->seq) {
        ret = add_sysv_msg(msgq, msgin->msgtype, size, msgin->msg, NULL);
    } else {
        struct sysv_client src;
        src.port = port;
        src.vmid = msg->src;
        src.seq  = msg->seq;
        ret      = add_sysv_msg(msgq, msgin->msgtype, size, msgin->msg, &src);
    }

out:
    SAVE_PROFILE_INTERVAL(ipc_sysv_msgsnd_callback);
    return ret;
}

DEFINE_PROFILE_INTERVAL(ipc_sysv_msgrcv_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_sysv_msgrcv_callback, ipc);

int ipc_sysv_msgrcv_send(IDTYPE msgid, long msgtype, int flags, void* buf, size_t size) {
    BEGIN_PROFILE_INTERVAL();
    IDTYPE owner;
    struct shim_ipc_port* port = NULL;
    int ret                    = 0;

    if ((ret = connect_owner(msgid, &port, &owner)) < 0)
        goto out;

    if (owner == cur_process.vmid) {
        ret = -EAGAIN;
        goto out;
    }

    assert(port);

    size_t total_msg_size           = get_ipc_msg_duplex_size(sizeof(struct shim_ipc_sysv_msgrcv));
    struct shim_ipc_msg_duplex* msg = __alloca(total_msg_size);
    init_ipc_msg_duplex(msg, IPC_SYSV_MSGRCV, total_msg_size, owner);

    struct shim_ipc_sysv_msgrcv* msgin = (struct shim_ipc_sysv_msgrcv*)&msg->msg.msg;
    msgin->msgid                       = msgid;
    msgin->msgtype                     = msgtype;
    msgin->size                        = size;
    msgin->flags                       = flags;

    debug("ipc send to %u: IPC_SYSV_MSGRCV(%u, %ld)\n", owner, msgid, msgtype);

    ret = send_ipc_message_duplex(msg, port, NULL, buf);
    put_ipc_port(port);
out:
    SAVE_PROFILE_INTERVAL(ipc_sysv_msgrcv_send);
    return ret;
}

int ipc_sysv_msgrcv_callback(IPC_CALLBACK_ARGS) {
    BEGIN_PROFILE_INTERVAL();
    int ret                            = 0;
    struct shim_ipc_sysv_msgrcv* msgin = (struct shim_ipc_sysv_msgrcv*)&msg->msg;

    debug("ipc callback from %u: IPC_SYSV_MSGRCV(%u, %ld)\n", msg->src, msgin->msgid,
          msgin->msgtype);

    struct shim_msg_handle* msgq = get_msg_handle_by_id(msgin->msgid);

    if (!msgq) {
        ret = -ENOENT;
        goto out;
    }

    void* buf = __alloca(msgin->size);
    struct sysv_client src;
    src.port = port;
    src.vmid = msg->src;
    src.seq  = msg->seq;

    ret = get_sysv_msg(msgq, msgin->msgtype, msgin->size, buf, msgin->flags, &src);

    if (ret > 0) {
        size_t size = ret;
        ret =
            ipc_sysv_msgsnd_send(port, msg->src, msgin->msgid, msgin->msgtype, buf, size, msg->seq);
    }

    put_msg_handle(msgq);
out:
    SAVE_PROFILE_INTERVAL(ipc_sysv_msgrcv_callback);
    return ret;
}

DEFINE_PROFILE_INTERVAL(ipc_sysv_msgmov_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_sysv_msgmov_callback, ipc);

int ipc_sysv_msgmov_send(struct shim_ipc_port* port, IDTYPE dest, IDTYPE msgid, LEASETYPE lease,
                         struct sysv_score* scores, int nscores) {
    BEGIN_PROFILE_INTERVAL();
    size_t total_msg_size =
        get_ipc_msg_size(sizeof(struct shim_ipc_sysv_msgmov) + sizeof(struct sysv_score) * nscores);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_SYSV_MSGMOV, total_msg_size, dest);
    struct shim_ipc_sysv_msgmov* msgin = (struct shim_ipc_sysv_msgmov*)&msg->msg;

    msgin->msgid   = msgid;
    msgin->lease   = lease;
    msgin->nscores = nscores;
    if (nscores)
        memcpy(msgin->scores, scores, sizeof(struct sysv_score) * nscores);

    debug("ipc send to %u: IPC_SYSV_MSGMOV(%d)\n", dest, msgid);
    int ret = send_ipc_message(msg, port);
    SAVE_PROFILE_INTERVAL(ipc_sysv_msgmov_send);
    return ret;
}

int ipc_sysv_msgmov_callback(IPC_CALLBACK_ARGS) {
    __UNUSED(port);

    BEGIN_PROFILE_INTERVAL();
    int ret                            = 0;
    struct shim_ipc_sysv_msgmov* msgin = (struct shim_ipc_sysv_msgmov*)&msg->msg;

    debug("ipc callback from %u: IPC_SYSV_MSGMOV(%d)\n", msg->src, msgin->msgid);

    struct shim_msg_handle* msgq = get_msg_handle_by_id(msgin->msgid);
    if (!msgq) {
        ret = -ENOENT;
        goto out;
    }

    struct shim_handle* hdl = container_of(msgq, struct shim_handle, info.msg);

    lock(&hdl->lock);
    int nscores = (msgin->nscores > MAX_SYSV_CLIENTS) ? MAX_SYSV_CLIENTS : msgin->nscores;
    if (nscores)
        memcpy(msgq->scores, msgin->scores, nscores);
    if (nscores < MAX_SYSV_CLIENTS)
        memset(msgq->scores + nscores, 0, sizeof(struct sysv_score) * (MAX_SYSV_CLIENTS - nscores));
    unlock(&hdl->lock);

    ret = recover_msg_ownership(msgq);

    struct shim_ipc_info* info;
    if (!get_ipc_info_cur_process(&info)) {
        add_sysv_subrange(msgin->msgid, info->vmid, qstrgetstr(&info->uri), &msgin->lease);
        put_ipc_info(info);
    }

    put_msg_handle(msgq);
out:
    SAVE_PROFILE_INTERVAL(ipc_sysv_msgmov_callback);
    return ret;
}

DEFINE_PROFILE_INTERVAL(ipc_sysv_semop_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_sysv_semop_callback, ipc);

int ipc_sysv_semop_send(IDTYPE semid, struct sembuf* sops, int nsops, unsigned long timeout,
                        unsigned long* seq) {
    BEGIN_PROFILE_INTERVAL();
    IDTYPE owner;
    struct shim_ipc_port* port = NULL;
    int ret                    = 0;
    bool waitforreply          = false;

    for (int i = 0; i < nsops; i++)
        if (sops[i].sem_op <= 0) {
            waitforreply = true;
            break;
        }

    if ((ret = connect_owner(semid, &port, &owner)) < 0)
        goto out;

    if (owner == cur_process.vmid) {
        ret = -EAGAIN;
        goto out;
    }

    assert(port);

    if (!waitforreply) {
        size_t total_msg_size =
            get_ipc_msg_size(sizeof(struct shim_ipc_sysv_semop) + sizeof(struct sembuf) * nsops);
        struct shim_ipc_msg* msg = __alloca(total_msg_size);
        init_ipc_msg(msg, IPC_SYSV_SEMOP, total_msg_size, owner);
        struct shim_ipc_sysv_semop* msgin = (struct shim_ipc_sysv_semop*)&msg->msg;

        msgin->semid   = semid;
        msgin->timeout = timeout;
        msgin->nsops   = nsops;
        memcpy(msgin->sops, sops, sizeof(struct sembuf) * nsops);
        msg->seq = *seq;

        debug("ipc send to %u: IPC_SYSV_SEMOP(%u, %ld, %u)\n", owner, semid, timeout, nsops);

        ret = send_ipc_message(msg, port);
        put_ipc_port(port);
        goto out;
    }

    size_t total_msg_size =
        get_ipc_msg_duplex_size(sizeof(struct shim_ipc_sysv_semop) + sizeof(struct sembuf) * nsops);
    struct shim_ipc_msg_duplex* msg = __alloca(total_msg_size);
    init_ipc_msg_duplex(msg, IPC_SYSV_SEMOP, total_msg_size, owner);

    struct shim_ipc_sysv_semop* msgin = (struct shim_ipc_sysv_semop*)&msg->msg.msg;
    msgin->semid                      = semid;
    msgin->timeout                    = timeout;
    msgin->nsops                      = nsops;
    memcpy(msgin->sops, sops, sizeof(struct sembuf) * nsops);
    msg->msg.seq = *seq;

    debug("ipc send to %u: IPC_SYSV_SEMOP(%u, %ld, %u)\n", owner, semid, timeout, nsops);

    ret = send_ipc_message_duplex(msg, port, seq, NULL);
    put_ipc_port(port);
out:
    SAVE_PROFILE_INTERVAL(ipc_sysv_semop_send);
    return ret;
}

int ipc_sysv_semop_callback(IPC_CALLBACK_ARGS) {
    BEGIN_PROFILE_INTERVAL();
    int ret                           = 0;
    struct shim_ipc_sysv_semop* msgin = (struct shim_ipc_sysv_semop*)&msg->msg;

    debug("ipc callback from %u: IPC_SYSV_SEMOP(%u, %ld, %u)\n", msg->src, msgin->semid,
          msgin->timeout, msgin->nsops);

    struct shim_sem_handle* sem = get_sem_handle_by_id(msgin->semid);
    if (!sem) {
        ret = -ENOENT;
        goto out;
    }

    struct sysv_client client;
    client.port = port;
    client.vmid = msg->src;
    client.seq  = msg->seq;
    ret         = submit_sysv_sem(sem, msgin->sops, msgin->nsops, msgin->timeout, &client);
    put_sem_handle(sem);
out:
    SAVE_PROFILE_INTERVAL(ipc_sysv_semop_callback);
    return ret;
}

DEFINE_PROFILE_INTERVAL(ipc_sysv_semctl_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_sysv_semctl_callback, ipc);

int ipc_sysv_semctl_send(IDTYPE semid, int semnum, int cmd, void* vals, size_t valsize) {
    BEGIN_PROFILE_INTERVAL();
    IDTYPE owner;
    struct shim_ipc_port* port = NULL;
    int ret                    = 0;

    if ((ret = connect_owner(semid, &port, &owner)) < 0)
        goto out;

    int ctlvalsize = (cmd == SETALL || cmd == SETVAL) ? valsize : 0;

    size_t total_msg_size =
        get_ipc_msg_duplex_size(sizeof(struct shim_ipc_sysv_semctl) + ctlvalsize);
    struct shim_ipc_msg_duplex* msg = __alloca(total_msg_size);
    init_ipc_msg_duplex(msg, IPC_SYSV_SEMCTL, total_msg_size, owner);

    struct shim_ipc_sysv_semctl* msgin = (struct shim_ipc_sysv_semctl*)&msg->msg.msg;
    msgin->semid                       = semid;
    msgin->semnum                      = semnum;
    msgin->cmd                         = cmd;
    msgin->valsize                     = ctlvalsize;
    if (ctlvalsize)
        memcpy(msgin->vals, vals, ctlvalsize);

    debug("ipc send to %u: IPC_SYSV_SEMCTL(%u, %d, %d)\n", owner, semid, semnum, cmd);

    ret = send_ipc_message_duplex(msg, port, NULL, vals);
    put_ipc_port(port);
out:
    SAVE_PROFILE_INTERVAL(ipc_sysv_semctl_send);
    return ret;
}

int ipc_sysv_semctl_callback(IPC_CALLBACK_ARGS) {
    BEGIN_PROFILE_INTERVAL();
    int ret                            = 0;
    struct shim_ipc_sysv_semctl* msgin = (struct shim_ipc_sysv_semctl*)&msg->msg;

    debug("ipc callback from %u: IPC_SYSV_SEMCTL(%u, %d, %d)\n", msg->src, msgin->semid,
          msgin->semnum, msgin->cmd);

    struct shim_sem_handle* sem = get_sem_handle_by_id(msgin->semid);
    if (!sem) {
        ret = -ENOENT;
        goto out;
    }

    void* vals = NULL;
    size_t valsize;
    switch (msgin->cmd) {
        case GETALL: {
            unsigned short* allsems = __alloca(sizeof(unsigned short) * sem->nsems);
            for (int i = 0; i < sem->nsems; i++) {
                allsems[i] = sem->sems[i].val;
            }

            vals    = allsems;
            valsize = sizeof(unsigned short) * sem->nsems;
            goto semret;
        }

        case GETNCNT:
            vals    = &sem->sems[msgin->semnum].ncnt;
            valsize = sizeof(unsigned short);
            goto semret;

        case GETPID:
            vals    = &sem->sems[msgin->semnum].pid;
            valsize = sizeof(IDTYPE);
            goto semret;

        case GETVAL:
            vals    = &sem->sems[msgin->semnum].val;
            valsize = sizeof(unsigned short);
            goto semret;

        case GETZCNT:
            vals    = &sem->sems[msgin->semnum].zcnt;
            valsize = sizeof(unsigned short);
            break;

        case SETALL: {
            if (msgin->valsize != sizeof(unsigned short) * sem->nsems) {
                ret = -EINVAL;
                break;
            }

            unsigned short* vals = (void*)msgin->vals;

            for (int i = 0; i < sem->nsems; i++) {
                sem->sems[i].val = vals[i];
            }

            ret = RESPONSE_CALLBACK;
            break;
        }

        case SETVAL: {
            ret = -EINVAL;
            if (msgin->valsize != sizeof(sem->sems[msgin->semnum].val))
                break;
            if (msgin->semnum >= sem->nsems)
                break;

            memcpy(&sem->sems[msgin->semnum].val, msgin->vals, msgin->valsize);
            ret = RESPONSE_CALLBACK;
            break;
        }

        default:
            ret = -ENOSYS;
            break;
    }

    put_sem_handle(sem);
    goto out;
semret:
    ret = ipc_sysv_semret_send(port, msg->src, vals, valsize, msg->seq);
out:
    SAVE_PROFILE_INTERVAL(ipc_sysv_semctl_callback);
    return ret;
}

DEFINE_PROFILE_INTERVAL(ipc_sysv_semret_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_sysv_semret_callback, ipc);

int ipc_sysv_semret_send(struct shim_ipc_port* port, IDTYPE dest, void* vals, size_t valsize,
                         unsigned long seq) {
    BEGIN_PROFILE_INTERVAL();
    int ret                  = 0;
    size_t total_msg_size    = get_ipc_msg_size(sizeof(struct shim_ipc_sysv_semret) + valsize);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_SYSV_SEMRET, total_msg_size, dest);

    struct shim_ipc_sysv_semret* msgin = (struct shim_ipc_sysv_semret*)&msg->msg;
    msgin->valsize                     = valsize;
    memcpy(msgin->vals, vals, valsize);
    msg->seq = seq;

    debug("ipc send to %u: IPC_SYSV_SEMRET\n", dest);

    ret = send_ipc_message(msg, port);
    SAVE_PROFILE_INTERVAL(ipc_sysv_semret_send);
    return ret;
}

int ipc_sysv_semret_callback(IPC_CALLBACK_ARGS) {
    BEGIN_PROFILE_INTERVAL();
    struct shim_ipc_sysv_semret* semret = (struct shim_ipc_sysv_semret*)&msg->msg;

    debug("ipc callback from %u: IPC_SYSV_SEMRET\n", msg->src);

    struct shim_ipc_msg_duplex* obj = pop_ipc_msg_duplex(port, msg->seq);
    if (obj) {
        struct shim_ipc_sysv_semctl* semctl = (struct shim_ipc_sysv_semctl*)&obj->msg.msg;

        void* vals = obj->private;

        if (vals) {
            switch (semctl->cmd) {
                case GETALL:
                case GETNCNT:
                case GETPID:
                case GETVAL:
                case GETZCNT: {
                    size_t retvalsize = semret->valsize;
                    if (retvalsize > semctl->valsize)
                        retvalsize = semctl->valsize;
                    memcpy(vals, semret->vals, retvalsize);
                    break;
                }
            }
        }

        if (obj->thread)
            thread_wakeup(obj->thread);
    }

    SAVE_PROFILE_INTERVAL(ipc_sysv_semret_callback);
    return 0;
}

DEFINE_PROFILE_INTERVAL(ipc_sysv_semmov_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_sysv_semmov_callback, ipc);

int ipc_sysv_semmov_send(struct shim_ipc_port* port, IDTYPE dest, IDTYPE semid, LEASETYPE lease,
                         struct sem_backup* sems, int nsems, struct sem_client_backup* srcs,
                         int nsrcs, struct sysv_score* scores, int nscores) {
    BEGIN_PROFILE_INTERVAL();
    size_t total_msg_size = get_ipc_msg_size(
        sizeof(struct shim_ipc_sysv_semmov) + sizeof(struct sem_backup) * nsems +
        sizeof(struct sem_client_backup) * nsrcs + sizeof(struct sysv_score) * nscores);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_SYSV_SEMMOV, total_msg_size, dest);

    struct shim_ipc_sysv_semmov* msgin = (struct shim_ipc_sysv_semmov*)&msg->msg;
    msgin->semid                       = semid;
    msgin->lease                       = lease;
    msgin->nsems                       = nsems;
    msgin->nsrcs                       = nsrcs;
    msgin->nscores                     = nscores;

    memcpy(&msgin->sems, sems, sizeof(struct sem_backup) * nsems);
    memcpy((void*)msgin->sems + sizeof(struct sem_backup) * nsems, srcs,
           sizeof(struct sem_client_backup) * nsrcs);
    memcpy((void*)msgin->sems + sizeof(struct sem_backup) * nsems +
               sizeof(struct sem_client_backup) * nsrcs,
           scores, sizeof(struct sysv_score) * nscores);

    debug("ipc send to : IPC_SYSV_SEMMOV(%d)\n", semid);

    int ret = send_ipc_message(msg, port);
    SAVE_PROFILE_INTERVAL(ipc_sysv_semmov_send);
    return ret;
}

int ipc_sysv_semmov_callback(IPC_CALLBACK_ARGS) {
    __UNUSED(port);

    BEGIN_PROFILE_INTERVAL();
    int ret                            = 0;
    struct shim_ipc_sysv_semmov* msgin = (struct shim_ipc_sysv_semmov*)&msg->msg;

    debug("ipc callback from %u: IPC_SYSV_SEMMOV(%d)\n", msg->src, msgin->semid);

    struct sem_backup* sems           = msgin->sems;
    struct sem_client_backup* clients = (struct sem_client_backup*)(sems + msgin->nsems);
    struct sysv_score* scores         = (struct sysv_score*)(clients + msgin->nsrcs);

    struct shim_sem_handle* sem = get_sem_handle_by_id(msgin->semid);
    if (!sem) {
        ret = -ENOENT;
        goto out;
    }

    struct shim_handle* hdl = container_of(sem, struct shim_handle, info.sem);

    lock(&hdl->lock);
    int nscores = (msgin->nscores > MAX_SYSV_CLIENTS) ? MAX_SYSV_CLIENTS : msgin->nscores;
    if (nscores)
        memcpy(sem->scores, scores, nscores);
    if (nscores < MAX_SYSV_CLIENTS)
        memset(sem->scores + nscores, 0, sizeof(struct sysv_score) * (MAX_SYSV_CLIENTS - nscores));
    unlock(&hdl->lock);

    ret = recover_sem_ownership(sem, sems, msgin->nsems, clients, msgin->nsrcs);

    struct shim_ipc_info* info;
    if (!get_ipc_info_cur_process(&info)) {
        add_sysv_subrange(msgin->semid, info->vmid, qstrgetstr(&info->uri), &msgin->lease);
        put_ipc_info(info);
    }

    put_sem_handle(sem);
out:
    SAVE_PROFILE_INTERVAL(ipc_sysv_semmov_callback);
    return ret;
}

#ifdef USE_SHARED_SEMAPHORE

DEFINE_PROFILE_INTERVAL(ipc_sysv_semquery_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_sysv_semquery_callback, ipc);

int ipc_sysv_semquery_send(IDTYPE semid, int* nsems, PAL_NUM** host_sem_ids) {
    BEGIN_PROFILE_INTERVAL();
    int ret = 0;
    IDTYPE dest;
    struct shim_ipc_port* port = NULL;

    if ((ret = connect_owner(semid, &port, &dest)) < 0)
        goto out;

    if (dest == cur_process.vmid) {
        ret = -EAGAIN;
        goto out;
    }

    assert(port);
    size_t total_msg_size = get_ipc_msg_duplex_size(sizeof(struct shim_ipc_sysv_semquery));
    struct shim_ipc_msg_duplex* msg = __alloca(total_msg_size);
    init_ipc_msg_duplex(msg, IPC_SYSV_SEMQUERY, total_msg_size, dest);

    struct shim_ipc_sysv_semquery* msgin = (struct shim_ipc_sysv_semquery*)&msg->msg.msg;
    msgin->semid                         = semid;

    debug("ipc send to %u: IPC_SYSV_SEMQUERY(%u)\n", dest, semid);

    ret = send_ipc_message_duplex(msg, port, NULL, host_sem_ids);
    put_ipc_port(port);
    if (ret >= 0) {
        *nsems = ret;
        ret    = 0;
    }
out:
    SAVE_PROFILE_INTERVAL(ipc_sysv_semquery_send);
    return ret;
}

int ipc_sysv_semquery_callback(IPC_CALLBACK_ARGS) {
    BEGIN_PROFILE_INTERVAL();
    int ret                              = 0;
    struct shim_ipc_sysv_semquery* msgin = (struct shim_ipc_sysv_semquery*)&msg->msg;

    debug("ipc callback from %u: IPC_SYSV_SEMQUERY(%u)\n", msg->src, msgin->semid);

    struct shim_sem_handle* sem = get_sem_handle_by_id(msgin->semid);
    if (!sem) {
        ret = -ENOENT;
        goto out;
    }

    ret = send_sem_host_ids(sem, port, msg->src, msg->seq);
    put_sem_handle(sem);
out:
    SAVE_PROFILE_INTERVAL(ipc_sysv_semreply_callback);
    return ret;
}

DEFINE_PROFILE_INTERVAL(ipc_sysv_semreply_send, ipc);
DEFINE_PROFILE_INTERVAL(ipc_sysv_semreply_callback, ipc);

int ipc_sysv_semreply_send(struct shim_ipc_port* port, IDTYPE dest, IDTYPE semid, int nsems,
                           PAL_NUM* host_sem_ids, unsigned long seq) {
    BEGIN_PROFILE_INTERVAL();
    int ret = 0;
    size_t total_msg_size =
        get_ipc_msg_size(sizeof(struct shim_ipc_sysv_semreply) + sizeof(PAL_NUM) * nsems);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_SYSV_SEMREPLY, total_msg_size, dest);

    struct shim_ipc_sysv_semreply* msgin = (struct shim_ipc_sysv_semreply*)&msg->msg;
    msgin->semid                         = semid;
    msgin->nsems                         = nsems;
    if (nsems)
        memcpy(msgin->host_sem_ids, host_sem_ids, sizeof(PAL_NUM) * nsems);
    msg->seq = seq;

    debug("ipc send to %u: IPC_SYSV_SEMREPLY(%u, %d)\n", dest, semid, nsems);

    ret = send_ipc_message(msg, port);
    SAVE_PROFILE_INTERVAL(ipc_sysv_semreply_send);
    return ret;
}

int ipc_sysv_semreply_callback(IPC_CALLBACK_ARGS) {
    BEGIN_PROFILE_INTERVAL();
    int ret                              = 0;
    struct shim_ipc_sysv_semreply* msgin = (struct shim_ipc_sysv_semreply*)&msg->msg;

    debug("ipc callback from %u: IPC_SYSV_SEMREPLY(%u, %d)\n", msg->src, msgin->semid,
          msgin->nsems);

    struct shim_ipc_msg_duplex* obj = pop_ipc_msg_duplex(port, msg->seq);
    if (!obj)
        goto out;

    PAL_NUM** semids = obj->private;
    if (semids)
        *semids = malloc_copy(msgin->host_sem_ids, sizeof(PAL_NUM) * msgin->nsems);
    obj->retval = msgin->nsems;

    if (obj->thread)
        thread_wakeup(obj->thread);
out:
    SAVE_PROFILE_INTERVAL(ipc_sysv_semreply_callback);
    return ret;
}

#endif /* USE_SHARED_SEMAPHORE */

int __balance_sysv_score(struct sysv_balance_policy* policy, struct shim_handle* hdl,
                         struct sysv_score* scores, int nscores, struct sysv_client* src,
                         long score) {
    assert(locked(&hdl->lock));

    struct sysv_score* s    = scores;
    struct sysv_score* last = scores + nscores;

    for (; s < last && !s->vmid; s++)
        ;

    struct sysv_score* free    = s > scores ? scores : NULL;
    struct sysv_score* highest = s < last ? s : NULL;
    struct sysv_score* lowest  = highest;
    struct sysv_score* owner   = NULL;
    struct sysv_score* chosen  = NULL;

    for (; s < last; s++) {
        if (!s->vmid) {
            if (!free)
                free = s;
            continue;
        }

        if (s->score >= highest->score)
            highest = s;
        if (s->score < lowest->score)
            lowest = s;

        if (src) {
            if (s->vmid == cur_process.vmid)
                owner = s;
            if (s->vmid == src->vmid) {
                chosen = s;
                continue;
            }
        } else {
            if (s->vmid == cur_process.vmid) {
                owner = chosen = s;
                continue;
            }
        }

        s->score = (s->score >= policy->score_decay) ? s->score - policy->score_decay : 0;
        debug("balance: %u => %ld\n", s->vmid, s->score);
    }

    if (!chosen) {
        chosen        = free ?: lowest;
        chosen->vmid  = src ? src->vmid : cur_process.vmid;
        chosen->score = 0;
    }

    chosen->score += score;
    if (chosen->score > policy->score_max)
        chosen->score = policy->score_max;

    debug("balance: %u => %ld\n", chosen->vmid, chosen->score);

    if (!src || chosen != highest ||
        chosen->score < (owner ? owner->score : 0) + policy->balance_threshold)
        return 0;

    return policy->migrate(hdl, src);
}
