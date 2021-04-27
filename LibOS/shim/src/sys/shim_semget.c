/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system calls "semget", "semop", "semtimedop" and "semctl".
 */

#include <errno.h>

#include "list.h"
#include "pal.h"
#include "pal_error.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_lock.h"
#include "shim_sysv.h"
#include "shim_table.h"
#include "shim_utils.h"

#define SEM_HASH_LEN  8
#define SEM_HASH_NUM  (1 << SEM_HASH_LEN)
#define SEM_HASH_MASK (SEM_HASH_NUM - 1)
#define SEM_HASH(idx) ((idx) & SEM_HASH_MASK)

/* The sem_list links shim_sem_handle objects by the list field.
 * The sem_key_hlist links them by key_hlist, and qid_hlist by qid_hlist */
DEFINE_LISTP(shim_sem_handle);
static LISTP_TYPE(shim_sem_handle) sem_list;
static LISTP_TYPE(shim_sem_handle) sem_key_hlist[SEM_HASH_NUM];
static LISTP_TYPE(shim_sem_handle) sem_sid_hlist[SEM_HASH_NUM];
static struct shim_lock sem_list_lock;

#define SEM_TO_HANDLE(semhdl) container_of((semhdl), struct shim_handle, info.sem)

static int __add_sem_handle(unsigned long key, IDTYPE semid, int nsems, bool owned,
                            struct shim_sem_handle** semhdl) {
    assert(locked(&sem_list_lock));

    LISTP_TYPE(shim_sem_handle)* key_head =
        (key != IPC_PRIVATE) ? &sem_key_hlist[SEM_HASH(key)] : NULL;
    LISTP_TYPE(shim_sem_handle)* sid_head = semid ? &sem_sid_hlist[SEM_HASH(semid)] : NULL;

    struct shim_sem_handle* tmp;
    struct shim_handle* hdl = NULL;
    int ret = 0;

    if (key_head)
        LISTP_FOR_EACH_ENTRY(tmp, key_head, key_hlist) {
            if (tmp->semkey == key) {
                if (tmp->semid == semid)
                    goto out;
                return -EEXIST;
            }
        }

    if (sid_head)
        LISTP_FOR_EACH_ENTRY(tmp, sid_head, sid_hlist) {
            if (tmp->semid == semid) {
                if (key)
                    tmp->semkey = key;
                goto out;
            }
        }

    hdl = get_new_handle();
    if (!hdl)
        return -ENOMEM;

    hdl->type = TYPE_SEM;
    tmp = &hdl->info.sem;

    tmp->semkey = key;
    tmp->semid  = semid;
    tmp->owned  = owned;

    ret = DkEventCreate(&tmp->event, /*init_signaled=*/false, /*auto_clear=*/false);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto failed;
    }

    if (owned && nsems) {
        tmp->nsems = nsems;
        tmp->sems  = malloc(sizeof(struct sem_obj) * nsems);
        if (!tmp->sems) {
            ret = -ENOMEM;
            goto failed;
        }

        for (int i = 0; i < nsems; i++) {
            tmp->sems[i].num         = i;
            tmp->sems[i].val         = 0;
            tmp->sems[i].host_sem_id = 0;
            tmp->sems[i].host_sem    = NULL;
            INIT_LISTP(&tmp->sems[i].ops);
            INIT_LISTP(&tmp->sems[i].next_ops);
        }
    }

    INIT_LISTP(&tmp->migrated);
    INIT_LIST_HEAD(tmp, list);
    get_handle(hdl);
    LISTP_ADD_TAIL(tmp, &sem_list, list);
    INIT_LIST_HEAD(tmp, key_hlist);
    if (key_head) {
        get_handle(hdl);
        LISTP_ADD(tmp, key_head, key_hlist);
    }
    if (sid_head) {
        get_handle(hdl);
        LISTP_ADD(tmp, sid_head, sid_hlist);
    }

out:
    if (!semhdl) {
        put_handle(hdl);
        return 0;
    }

    *semhdl = tmp;
    return 0;

failed:
    put_handle(hdl);
    return ret;
}

int add_sem_handle(unsigned long key, IDTYPE id, int nsems, bool owned) {
    lock(&sem_list_lock);
    int ret = __add_sem_handle(key, id, nsems, owned, NULL);
    unlock(&sem_list_lock);
    return ret;
}

struct shim_sem_handle* get_sem_handle_by_key(unsigned long key) {
    LISTP_TYPE(shim_sem_handle)* key_head = &sem_key_hlist[SEM_HASH(key)];
    struct shim_sem_handle* tmp;
    struct shim_sem_handle* found = NULL;

    lock(&sem_list_lock);

    LISTP_FOR_EACH_ENTRY(tmp, key_head, key_hlist) {
        if (tmp->semkey == key) {
            found = tmp;
            break;
        }
    }

    if (found)
        get_handle(SEM_TO_HANDLE(found));

    unlock(&sem_list_lock);
    return found;
}

struct shim_sem_handle* get_sem_handle_by_id(IDTYPE semid) {
    LISTP_TYPE(shim_sem_handle)* sid_head = &sem_sid_hlist[SEM_HASH(semid)];
    struct shim_sem_handle* tmp;
    struct shim_sem_handle* found = NULL;

    lock(&sem_list_lock);

    LISTP_FOR_EACH_ENTRY(tmp, sid_head, sid_hlist) {
        if (tmp->semid == semid) {
            found = tmp;
            break;
        }
    }

    if (found)
        get_handle(SEM_TO_HANDLE(found));

    unlock(&sem_list_lock);
    return found;
}

void put_sem_handle(struct shim_sem_handle* sem) {
    put_handle(SEM_TO_HANDLE(sem));
}

static int __del_sem_handle(struct shim_sem_handle* sem) {
    struct shim_handle* hdl = SEM_TO_HANDLE(sem);
    assert(locked(&hdl->lock));

    if (sem->deleted)
        return 0;

    sem->deleted = true;

    lock(&sem_list_lock);
    LISTP_DEL_INIT(sem, &sem_list, list);
    put_handle(hdl);
    if (!LIST_EMPTY(sem, key_hlist)) {
        // DEP: Yuck
        LISTP_TYPE(shim_sem_handle)* key_head = &sem_key_hlist[SEM_HASH(sem->semkey)];
        LISTP_DEL_INIT(sem, key_head, key_hlist);
        put_handle(hdl);
    }
    if (!LIST_EMPTY(sem, sid_hlist)) {
        // DEP: Yuck
        LISTP_TYPE(shim_sem_handle)* sid_head = &sem_sid_hlist[SEM_HASH(sem->semid)];
        LISTP_DEL_INIT(sem, sid_head, sid_hlist);
        put_handle(hdl);
    }
    unlock(&sem_list_lock);
    return 0;
}

int del_sem_handle(struct shim_sem_handle* sem) {
    struct shim_handle* hdl = SEM_TO_HANDLE(sem);
    lock(&hdl->lock);
    int ret = __del_sem_handle(sem);
    unlock(&hdl->lock);
    return ret;
}

long shim_do_semget(key_t key, int nsems, int semflg) {
    IDTYPE semid = 0;
    int ret;

    if (!create_lock_runtime(&sem_list_lock)) {
        return -ENOMEM;
    }

    if (key != IPC_PRIVATE) {
        struct shim_sem_handle* sem = get_sem_handle_by_key(key);
        if (sem) {
            semid = sem->semid;
            put_sem_handle(sem);
            return (semflg & IPC_EXCL) ? -EEXIST : (int)semid;
        }
    }

    struct sysv_key k;
    k.key  = key;
    k.type = SYSV_SEM;

    if (semflg & IPC_CREAT) {
        do {
            semid = allocate_ipc_id(0, 0);
            if (!semid)
                semid = ipc_lease_send();
        } while (!semid);

        if (key != IPC_PRIVATE) {
            if ((ret = ipc_sysv_tellkey_send(NULL, 0, &k, semid, 0)) < 0) {
                release_ipc_id(semid);
                return ret;
            }
        }

        add_sem_handle(key, semid, nsems, true);
    } else {
        if ((ret = ipc_sysv_findkey_send(&k)) < 0)
            return ret;

        semid = ret;
        if ((ret = ipc_query_send(semid)) < 0)
            return ret;
    }

    return semid;
}

static int connect_sem_handle(int semid, int nsems, struct shim_sem_handle** semp) {
    struct shim_sem_handle* sem = get_sem_handle_by_id(semid);
    int ret;

    if (!sem) {
        if ((ret = ipc_query_send(semid)) < 0)
            return ret;

        if (!sem) {
            lock(&sem_list_lock);
            ret = __add_sem_handle(IPC_PRIVATE, semid, nsems, false, &sem);
            unlock(&sem_list_lock);
            if (ret < 0)
                return ret;
        }
    }

    *semp = sem;
    return 0;
}

static int __do_semop(int semid, struct sembuf* sops, unsigned int nsops, unsigned long timeout) {
    int ret;
    struct shim_sem_handle* sem;
    size_t nsems = 0;

    for (size_t i = 0; i < nsops; i++)
        if (sops[i].sem_num >= nsems)
            nsems = sops[i].sem_num + 1;

    if (!create_lock_runtime(&sem_list_lock)) {
        return -ENOMEM;
    }

    if ((ret = connect_sem_handle(semid, nsems, &sem)) < 0)
        return ret;

    ret = submit_sysv_sem(sem, sops, nsops, timeout, NULL);
    put_sem_handle(sem);
    return ret;
}

long shim_do_semop(int semid, struct sembuf* sops, unsigned int nsops) {
    return __do_semop(semid, sops, nsops, IPC_SEM_NOTIMEOUT);
}

long shim_do_semtimedop(int semid, struct sembuf* sops, unsigned int nsops,
                       const struct timespec* timeout) {
    unsigned long timeout_ns = IPC_SEM_NOTIMEOUT;
    if (timeout) {
        timeout_ns = timeout->tv_sec * 1000000000ULL + timeout->tv_nsec;
    }

    return __do_semop(semid, sops, nsops, timeout_ns);
}

long shim_do_semctl(int semid, int semnum, int cmd, unsigned long arg) {
    struct shim_sem_handle* sem;
    int ret;

    if (!create_lock_runtime(&sem_list_lock)) {
        return -ENOMEM;
    }

    if ((ret = connect_sem_handle(semid, 0, &sem)) < 0)
        return ret;

    struct shim_handle* hdl = SEM_TO_HANDLE(sem);
    lock(&hdl->lock);

    switch (cmd) {
        case IPC_RMID: {
            if (!sem->owned) {
                ret = ipc_sysv_delres_send(NULL, 0, semid, SYSV_SEM);
                if (ret < 0)
                    goto out;
            }

            __del_sem_handle(sem);
            goto out;
        }
    }

    if (sem->owned) {
        if (sem->deleted) {
            ret = -EIDRM;
            goto out;
        }

        switch (cmd) {
            case GETALL:
                for (int i = 0; i < sem->nsems; i++) {
                    unsigned short val        = sem->sems[i].val;
                    ((unsigned short*)arg)[i] = val;
                }
                break;

            case GETNCNT:
                ret = sem->sems[semnum].ncnt;
                break;

            case GETPID:
                ret = sem->sems[semnum].pid;
                break;

            case GETVAL:
                ret = sem->sems[semnum].val;
                break;

            case GETZCNT:
                ret = sem->sems[semnum].zcnt;
                break;

            case SETALL:
                for (int i = 0; i < sem->nsems; i++) {
                    unsigned short val = ((unsigned short*)arg)[i];
                    sem->sems[i].val   = val;
                }
                break;

            case SETVAL: {
                unsigned short val    = arg;
                sem->sems[semnum].val = val;
                break;
            }
        }
    } else {
        switch (cmd) {
            case GETALL:
            case SETALL: {
                int valsize = sem->nsems * sizeof(unsigned short);
                ret = ipc_sysv_semctl_send(sem->semid, 0, cmd, (unsigned short*)arg, valsize);
                break;
            }

            case GETVAL:
            case GETNCNT:
            case GETPID:
            case GETZCNT: {
                int valsize = sizeof(unsigned short);
                unsigned short val;
                ret = ipc_sysv_semctl_send(sem->semid, semnum, cmd, &val, valsize);
                if (!ret)
                    ret = val;
                break;
            }

            case SETVAL: {
                unsigned short val = arg;
                ret = ipc_sysv_semctl_send(sem->semid, semnum, cmd, &val, sizeof(unsigned short));
                break;
            }
        }
    }

out:
    unlock(&hdl->lock);
    put_sem_handle(sem);
    return ret;
}

static bool __handle_sysv_sems(struct shim_sem_handle* sem) {
    bool progressed = false;
    bool setevent   = false;

    struct sem_obj* sobj;
    for (sobj = sem->sems; sobj < &sem->sems[sem->nsems]; sobj++)
        LISTP_SPLICE_TAIL_INIT(&sobj->next_ops, &sobj->ops, progress, sem_ops);

    for (sobj = sem->sems; sobj < &sem->sems[sem->nsems]; sobj++) {
        struct sem_ops* sops;
        struct sem_ops* n;

        LISTP_FOR_EACH_ENTRY_SAFE(sops, n, &sobj->ops, progress) {
            struct sembuf* op = &sops->ops[sops->stat.current];
            assert(op->sem_num == sobj->num);
            // first_iter is a variable defined by LISTP_FOR_EACH_ENTRY_SAFE
            // The second part of this assertion is only valid after the first attempt
            assert(first_iter || (sops != n));
            if (sops->stat.completed)
                goto send_result;
        again:
            if (op->sem_op > 0) {
                sobj->val += op->sem_op;
                log_debug("sem %u: add %u => %u\n", sobj->num, op->sem_op, sobj->val);
            } else if (op->sem_op < 0) {
                if (sobj->val < -op->sem_op) {
                    if (op->sem_flg & IPC_NOWAIT) {
                        log_error("sem %u: wait for %u failed\n", sobj->num, -op->sem_op);
                        goto failed;
                    }
                    continue;
                }
                sobj->val -= -op->sem_op;
                log_debug("sem %u: wait for %u => %u\n", sobj->num, -op->sem_op, sobj->val);
            } else {
                if (sobj->val) {
                    if (op->sem_flg & IPC_NOWAIT) {
                        log_error("sem %u: wait for 0 failed\n", sobj->num);
                        goto failed;
                    }
                    continue;
                }
                log_debug("sem %u: wait for 0\n", sobj->num);
            }

            progressed = true;
            sops->stat.current++;
            if (sops->stat.current == sops->stat.nops) {
                sops->stat.completed = true;
                goto send_result;
            }

            op = &sops->ops[sops->stat.current];
            if (op->sem_num != sobj->num) {
                LISTP_MOVE_TAIL(sops, &sem->sems[op->sem_num].next_ops, &sobj->ops, progress);
                continue;
            }

            goto again;
        failed:
            progressed        = true;
            sops->stat.failed = true;
        send_result:
            /* Chia-Che 10/17/17: If the code reaches this point, sops should
             * still be in sobj->ops. */
            LISTP_DEL_INIT(sops, &sobj->ops, progress);
            sem->nreqs--;
            if (!sops->client.vmid) {
                setevent = true;
                continue;
            }

            size_t total_msg_size         = get_ipc_msg_size(sizeof(struct shim_ipc_resp));
            struct shim_ipc_msg* resp_msg = __alloca(total_msg_size);
            init_ipc_msg(resp_msg, IPC_MSG_RESP, total_msg_size, sops->client.vmid);
            resp_msg->seq = sops->client.seq;

            struct shim_ipc_resp* resp = (struct shim_ipc_resp*)resp_msg->msg;
            resp->retval               = sops->stat.completed ? 0 : -EAGAIN;

            send_ipc_message(resp_msg, sops->client.port);

            put_ipc_port(sops->client.port);
            sops->client.vmid = 0;
            sops->client.port = NULL;
            sops->client.seq  = 0;
            free(sops);
        }
    }

    if (setevent)
        DkEventSet(sem->event);

    return progressed;
}

static void __handle_one_sysv_sem(struct shim_sem_handle* sem, struct sem_stat* stat,
                                  struct sembuf* sops) {
    bool progressed = false;

again:
    while (stat->current < stat->nops) {
        struct sem_obj* sobj = &sem->sems[sops[stat->current].sem_num];
        struct sembuf* op    = &sops[stat->current];

        if (op->sem_op > 0) {
            progressed = true;
            sobj->val += op->sem_op;
            log_debug("sem %u: add %u => %u\n", sobj->num, op->sem_op, sobj->val);
        } else if (op->sem_op < 0) {
            if (sobj->val < -op->sem_op) {
                if (op->sem_flg & IPC_NOWAIT) {
                    stat->failed = true;
                    log_error("sem %u: wait for %u failed\n", sobj->num, -op->sem_op);
                    return;
                }
                goto failed;
            }
            progressed = true;
            sobj->val -= -op->sem_op;
            log_debug("sem %u: wait for %u => %u\n", sobj->num, -op->sem_op, sobj->val);
        } else {
            if (sobj->val) {
                if (op->sem_flg & IPC_NOWAIT) {
                    stat->failed = true;
                    log_error("sem %u: wait for 0 failed\n", sobj->num);
                    return;
                }
                goto failed;
            }
            progressed = true;
            log_debug("sem %u: wait for 0\n", sobj->num);
        }

        stat->current++;
    }

    stat->completed = true;
failed:
    if (progressed) {
        while (__handle_sysv_sems(sem))
            ;
        progressed = false;
        if (!stat->completed)
            goto again;
    }
}

int submit_sysv_sem(struct shim_sem_handle* sem, struct sembuf* sops, int nsops,
                    unsigned long timeout, struct sysv_client* client) {
    int ret = 0;
    struct shim_handle* hdl = SEM_TO_HANDLE(sem);
    struct sem_ops* sem_ops = NULL;
    bool malloced           = false;
    struct sem_stat stat;
    stat.nops      = nsops;
    stat.current   = 0;
    stat.timeout   = timeout;
    stat.completed = false;
    stat.failed    = false;

    lock(&hdl->lock);

    if (sem->deleted) {
        ret = -EIDRM;
        goto out_locked;
    }

    IDTYPE semid      = sem->semid;
    bool sendreply    = false;
    unsigned long seq = client ? client->seq : 0;

    for (int i = 0; i < nsops; i++) {
        struct sembuf* op = &sops[i];

        if (op->sem_op > 0) {
            /* nothing to do */
        } else {
            sendreply = true;
        }
    }

    if (sem->deleted) {
        if (!client || sendreply) {
            ret = -EIDRM;
            goto out_locked;
        }

        ret = ipc_sysv_delres_send(client->port, client->vmid, sem->semid, SYSV_SEM);
        goto out_locked;
    }

    if (!sem->owned) {
        if (client) {
            ret = -ECONNREFUSED;
            goto out_locked;
        }

    unowned:
        unlock(&hdl->lock);
        ret = ipc_sysv_semop_send(semid, sops, nsops, timeout, &seq);
        if (ret != -EAGAIN && ret != -ECONNREFUSED)
            goto out;

        lock(&hdl->lock);
        if (!sem->owned)
            goto out_locked;
    }

    if (seq) {
        struct sem_ops* op;

        LISTP_FOR_EACH_ENTRY(op, &sem->migrated, progress) {
            if (op->client.vmid == (client ? client->vmid : g_process_ipc_info.vmid) &&
                seq == op->client.seq) {
                LISTP_DEL_INIT(op, &sem->migrated, progress);
                sem_ops  = op;
                stat     = sem_ops->stat;
                malloced = true;
                break;
            }
        }
    }

    __handle_one_sysv_sem(sem, &stat, sops);

    if (stat.completed || stat.failed) {
        ret = stat.completed ? 0 : -EAGAIN;
        if (client && sendreply) {
            size_t total_msg_size         = get_ipc_msg_size(sizeof(struct shim_ipc_resp));
            struct shim_ipc_msg* resp_msg = __alloca(total_msg_size);
            init_ipc_msg(resp_msg, IPC_MSG_RESP, total_msg_size, client->vmid);
            resp_msg->seq = client->seq;

            struct shim_ipc_resp* resp = (struct shim_ipc_resp*)resp_msg->msg;
            resp->retval               = ret;

            ret = send_ipc_message(resp_msg, client->port);
        }
        goto out_locked;
    }

    if (client) {
        assert(sendreply);
        if (!sem_ops || !malloced) {
            sem_ops = malloc(sizeof(struct sem_ops) + sizeof(struct sembuf) * nsops);
            if (!sem_ops) {
                ret = -ENOMEM;
                goto out_locked;
            }

            sem_ops->client.vmid = 0;
            sem_ops->client.port = NULL;
            sem_ops->client.seq  = 0;
            INIT_LIST_HEAD(sem_ops, progress);
            malloced = true;
        }
    } else {
        if (!sem_ops) {
            sem_ops              = __alloca(sizeof(struct sem_ops) + sizeof(struct sembuf) * nsops);
            sem_ops->client.vmid = 0;
            sem_ops->client.port = NULL;
            sem_ops->client.seq  = 0;
            INIT_LIST_HEAD(sem_ops, progress);
        }
    }

    sem_ops->stat = stat;
    for (int i = 0; i < nsops; i++) {
        sem_ops->ops[i] = sops[i];
    }

    LISTP_TYPE(sem_ops)* next_ops = &sem->sems[sops[stat.current].sem_num].next_ops;
    assert(LIST_EMPTY(sem_ops, progress));
    LISTP_ADD_TAIL(sem_ops, next_ops, progress);
    // CHECK_LIST_HEAD(next_ops);
    sem->nreqs++;

    if (client) {
        assert(sendreply);
        add_ipc_port(client->port, client->vmid, NULL);
        get_ipc_port(client->port);
        sem_ops->client = *client;
        sem_ops         = NULL;
        goto out_locked;
    }

    while (!sem_ops->stat.completed && !sem_ops->stat.failed) {
        if (!sem->owned) {
            /* Chia-Che 10/17/17: sem_ops may move from semaphore to semaphore
               base on its current state */
            next_ops = &sem->sems[sem_ops->ops[sem_ops->stat.current].sem_num].next_ops;
            LISTP_DEL_INIT(sem_ops, next_ops, progress);
            goto unowned;
        }

        unlock(&hdl->lock);
        object_wait_with_retry(sem->event);
        lock(&hdl->lock);
    }

    ret = sem_ops->stat.completed ? 0 : -EAGAIN;

out_locked:
    unlock(&hdl->lock);
out:
    if (sem_ops && malloced)
        free(sem_ops);
    return ret;
}
