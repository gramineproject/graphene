/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * shim_ipc_pid.c
 *
 * This file contains functions and callbacks to handle IPC of SYSV namespace.
 */

#include "shim_ipc_sysv.h"

#include <errno.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_checkpoint.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_sysv.h"
#include "shim_thread.h"

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

int ipc_sysv_delres_send(struct shim_ipc_port* port, IDTYPE dest, IDTYPE resid,
                         enum sysv_type type) {
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

    size_t total_msg_size = get_ipc_msg_with_ack_size(sizeof(struct shim_ipc_sysv_delres));
    struct shim_ipc_msg_with_ack* msg = __alloca(total_msg_size);
    init_ipc_msg_with_ack(msg, IPC_SYSV_DELRES, total_msg_size, dest);

    struct shim_ipc_sysv_delres* msgin = (struct shim_ipc_sysv_delres*)&msg->msg.msg;
    msgin->resid                       = resid;
    msgin->type                        = type;

    debug("ipc send to %u: IPC_SYSV_DELRES(%u, %s)\n", dest, resid, SYSV_TYPE_STR(type));

    ret = send_ipc_message_with_ack(msg, port, NULL, NULL);
    put_ipc_port(port);
out:
    return ret;
}

int ipc_sysv_delres_callback(IPC_CALLBACK_ARGS) {
    __UNUSED(port);

    int ret = 0;
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
    return ret;
}

int ipc_sysv_movres_send(struct sysv_client* client, IDTYPE owner, const char* uri, LEASETYPE lease,
                         IDTYPE resid, enum sysv_type type) {
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

    return send_ipc_message(msg, client->port);
}

int ipc_sysv_movres_callback(IPC_CALLBACK_ARGS) {
    int ret = 0;
    struct shim_ipc_sysv_movres* msgin = (struct shim_ipc_sysv_movres*)&msg->msg;

    debug("ipc callback from %u: IPC_SYSV_MOVRES(%u, %s, %u, %s)\n", msg->src, msgin->resid,
          SYSV_TYPE_STR(msgin->type), msgin->owner, msgin->uri);

    struct shim_ipc_msg_with_ack* obj = pop_ipc_msg_with_ack(port, msg->seq);
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
    return ret;
}

int ipc_sysv_msgsnd_send(struct shim_ipc_port* port, IDTYPE dest, IDTYPE msgid, long msgtype,
                         const void* buf, size_t size, unsigned long seq) {
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
    return ret;
}

int ipc_sysv_msgsnd_callback(IPC_CALLBACK_ARGS) {
    int ret = 0;
    struct shim_ipc_sysv_msgsnd* msgin = (struct shim_ipc_sysv_msgsnd*)&msg->msg;

    debug("ipc callback from %u: IPC_SYSV_MSGSND(%u, %ld)\n", msg->src, msgin->msgid,
          msgin->msgtype);

    size_t size = msg->size - sizeof(*msg) - sizeof(*msgin);

    if (msg->seq) {
        struct shim_ipc_msg_with_ack* obj = pop_ipc_msg_with_ack(port, msg->seq);
        void* priv = obj ? obj->private : NULL;

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
    return ret;
}

int ipc_sysv_msgrcv_send(IDTYPE msgid, long msgtype, int flags, void* buf, size_t size) {
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

    size_t total_msg_size = get_ipc_msg_with_ack_size(sizeof(struct shim_ipc_sysv_msgrcv));
    struct shim_ipc_msg_with_ack* msg = __alloca(total_msg_size);
    init_ipc_msg_with_ack(msg, IPC_SYSV_MSGRCV, total_msg_size, owner);

    struct shim_ipc_sysv_msgrcv* msgin = (struct shim_ipc_sysv_msgrcv*)&msg->msg.msg;
    msgin->msgid                       = msgid;
    msgin->msgtype                     = msgtype;
    msgin->size                        = size;
    msgin->flags                       = flags;

    debug("ipc send to %u: IPC_SYSV_MSGRCV(%u, %ld)\n", owner, msgid, msgtype);

    ret = send_ipc_message_with_ack(msg, port, NULL, buf);
    put_ipc_port(port);
out:
    return ret;
}

int ipc_sysv_msgrcv_callback(IPC_CALLBACK_ARGS) {
    int ret = 0;
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
    return ret;
}

int ipc_sysv_semop_send(IDTYPE semid, struct sembuf* sops, int nsops, unsigned long timeout,
                        unsigned long* seq) {
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

    size_t total_msg_size = get_ipc_msg_with_ack_size(sizeof(struct shim_ipc_sysv_semop)
                                                      + sizeof(struct sembuf) * nsops);
    struct shim_ipc_msg_with_ack* msg = __alloca(total_msg_size);
    init_ipc_msg_with_ack(msg, IPC_SYSV_SEMOP, total_msg_size, owner);

    struct shim_ipc_sysv_semop* msgin = (struct shim_ipc_sysv_semop*)&msg->msg.msg;
    msgin->semid                      = semid;
    msgin->timeout                    = timeout;
    msgin->nsops                      = nsops;
    memcpy(msgin->sops, sops, sizeof(struct sembuf) * nsops);
    msg->msg.seq = *seq;

    debug("ipc send to %u: IPC_SYSV_SEMOP(%u, %ld, %u)\n", owner, semid, timeout, nsops);

    ret = send_ipc_message_with_ack(msg, port, seq, NULL);
    put_ipc_port(port);
out:
    return ret;
}

int ipc_sysv_semop_callback(IPC_CALLBACK_ARGS) {
    int ret = 0;
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
    return ret;
}

int ipc_sysv_semctl_send(IDTYPE semid, int semnum, int cmd, void* vals, size_t valsize) {
    IDTYPE owner;
    struct shim_ipc_port* port = NULL;
    int ret                    = 0;

    if ((ret = connect_owner(semid, &port, &owner)) < 0)
        goto out;

    int ctlvalsize = (cmd == SETALL || cmd == SETVAL) ? valsize : 0;

    size_t total_msg_size =
        get_ipc_msg_with_ack_size(sizeof(struct shim_ipc_sysv_semctl) + ctlvalsize);
    struct shim_ipc_msg_with_ack* msg = __alloca(total_msg_size);
    init_ipc_msg_with_ack(msg, IPC_SYSV_SEMCTL, total_msg_size, owner);

    struct shim_ipc_sysv_semctl* msgin = (struct shim_ipc_sysv_semctl*)&msg->msg.msg;
    msgin->semid                       = semid;
    msgin->semnum                      = semnum;
    msgin->cmd                         = cmd;
    msgin->valsize                     = ctlvalsize;
    if (ctlvalsize)
        memcpy(msgin->vals, vals, ctlvalsize);

    debug("ipc send to %u: IPC_SYSV_SEMCTL(%u, %d, %d)\n", owner, semid, semnum, cmd);

    ret = send_ipc_message_with_ack(msg, port, NULL, vals);
    put_ipc_port(port);
out:
    return ret;
}

int ipc_sysv_semctl_callback(IPC_CALLBACK_ARGS) {
    int ret = 0;
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
    return ret;
}

int ipc_sysv_semret_send(struct shim_ipc_port* port, IDTYPE dest, void* vals, size_t valsize,
                         unsigned long seq) {
    size_t total_msg_size    = get_ipc_msg_size(sizeof(struct shim_ipc_sysv_semret) + valsize);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_SYSV_SEMRET, total_msg_size, dest);

    struct shim_ipc_sysv_semret* msgin = (struct shim_ipc_sysv_semret*)&msg->msg;
    msgin->valsize                     = valsize;
    memcpy(msgin->vals, vals, valsize);
    msg->seq = seq;

    debug("ipc send to %u: IPC_SYSV_SEMRET\n", dest);

    return send_ipc_message(msg, port);
}

int ipc_sysv_semret_callback(IPC_CALLBACK_ARGS) {
    struct shim_ipc_sysv_semret* semret = (struct shim_ipc_sysv_semret*)&msg->msg;

    debug("ipc callback from %u: IPC_SYSV_SEMRET\n", msg->src);

    struct shim_ipc_msg_with_ack* obj = pop_ipc_msg_with_ack(port, msg->seq);
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

    return 0;
}
