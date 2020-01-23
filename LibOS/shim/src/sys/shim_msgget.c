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
 * shim_msgget.c
 *
 * Implementation of system call "msgget", "msgsnd", "msgrcv" and "msgctl".
 *
 * XXX(borysp): I'm pretty sure there are possible deadlocks in this code. Sometimes it first takes
 * `msgq_list_lock` and then `hdl->lock`, sometimes other way round. Someone will have to rewrite
 * it someday.
 */

#include <errno.h>
#include <list.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_ipc.h>
#include <shim_profile.h>
#include <shim_sysv.h>
#include <shim_unistd.h>
#include <shim_utils.h>

#define MSGQ_HASH_LEN  8
#define MSGQ_HASH_NUM  (1 << MSGQ_HASH_LEN)
#define MSGQ_HASH_MASK (MSGQ_HASH_NUM - 1)
#define MSGQ_HASH(idx) ((idx) & MSGQ_HASH_MASK)

/* The msgq_list links shim_msg_handle objects by the list field.
 * The msgq_key_hlist links them by key_hlist, and qid_hlist by qid_hlist */
DEFINE_LISTP(shim_msg_handle);
static LISTP_TYPE(shim_msg_handle) msgq_list;
static LISTP_TYPE(shim_msg_handle) msgq_key_hlist[MSGQ_HASH_NUM];
static LISTP_TYPE(shim_msg_handle) msgq_qid_hlist[MSGQ_HASH_NUM];
static struct shim_lock msgq_list_lock;

static int __load_msg_persist(struct shim_msg_handle* msgq, bool readmsg);
static int __store_msg_persist(struct shim_msg_handle* msgq);

DEFINE_PROFILE_CATEGORY(sysv_msg, );

#define MSG_TO_HANDLE(msghdl) container_of((msghdl), struct shim_handle, info.msg)

static int __add_msg_handle(unsigned long key, IDTYPE msqid, bool owned,
                            struct shim_msg_handle** msghdl) {
    assert(locked(&msgq_list_lock));

    LISTP_TYPE(shim_msg_handle)* key_head =
        (key != IPC_PRIVATE) ? &msgq_key_hlist[MSGQ_HASH(key)] : NULL;
    LISTP_TYPE(shim_msg_handle)* qid_head = msqid ? &msgq_qid_hlist[MSGQ_HASH(msqid)] : NULL;

    struct shim_msg_handle* tmp;

    if (key_head)
        LISTP_FOR_EACH_ENTRY(tmp, key_head, key_hlist) {
            if (tmp->msqkey == key) {
                if (tmp->msqid == msqid) {
                    if (msghdl)
                        *msghdl = tmp;
                    return 0;
                }
                return -EEXIST;
            }
        }

    if (qid_head)
        LISTP_FOR_EACH_ENTRY(tmp, qid_head, qid_hlist) {
            if (tmp->msqid == msqid) {
                if (key)
                    tmp->msqkey = key;
                if (msghdl)
                    *msghdl = tmp;
                return 0;
            }
        }

    struct shim_handle* hdl = get_new_handle();
    if (!hdl)
        return -ENOMEM;

    struct shim_msg_handle* msgq = &hdl->info.msg;

    hdl->type         = TYPE_MSG;
    msgq->msqkey      = key;
    msgq->msqid       = msqid;
    msgq->owned       = owned;
    msgq->deleted     = false;
    msgq->currentsize = 0;
    msgq->event       = DkSynchronizationEventCreate(PAL_FALSE);

    msgq->queue     = malloc(MSG_QOBJ_SIZE * DEFAULT_MSG_QUEUE_SIZE);
    msgq->queuesize = DEFAULT_MSG_QUEUE_SIZE;
    msgq->queueused = 0;
    msgq->freed     = NULL;

    msgq->ntypes   = 0;
    msgq->maxtypes = INIT_MSG_TYPE_SIZE;
    msgq->types    = malloc(sizeof(struct msg_type) * INIT_MSG_TYPE_SIZE);

    INIT_LIST_HEAD(msgq, list);
    get_handle(hdl);
    LISTP_ADD_TAIL(msgq, &msgq_list, list);

    INIT_LIST_HEAD(msgq, key_hlist);
    if (key_head) {
        get_handle(hdl);
        LISTP_ADD(msgq, key_head, key_hlist);
    }
    INIT_LIST_HEAD(msgq, qid_hlist);
    if (qid_head) {
        get_handle(hdl);
        LISTP_ADD(msgq, qid_head, qid_hlist);
    }

    if (!msghdl) {
        put_handle(hdl);
        return 0;
    }

    *msghdl = msgq;
    return 0;
}

int add_msg_handle(unsigned long key, IDTYPE id, bool owned) {
    lock(&msgq_list_lock);
    int ret = __add_msg_handle(key, id, owned, NULL);
    unlock(&msgq_list_lock);
    return ret;
}

struct shim_msg_handle* get_msg_handle_by_key(unsigned long key) {
    LISTP_TYPE(shim_msg_handle)* key_head = &msgq_key_hlist[MSGQ_HASH(key)];
    struct shim_msg_handle* tmp;
    struct shim_msg_handle* found = NULL;

    lock(&msgq_list_lock);

    LISTP_FOR_EACH_ENTRY(tmp, key_head, key_hlist) {
        if (tmp->msqkey == key) {
            found = tmp;
            break;
        }
    }

    if (found)
        get_handle(MSG_TO_HANDLE(found));

    unlock(&msgq_list_lock);
    return found;
}

struct shim_msg_handle* get_msg_handle_by_id(IDTYPE msqid) {
    LISTP_TYPE(shim_msg_handle)* qid_head = &msgq_qid_hlist[MSGQ_HASH(msqid)];
    struct shim_msg_handle* tmp;
    struct shim_msg_handle* found = NULL;

    lock(&msgq_list_lock);

    LISTP_FOR_EACH_ENTRY(tmp, qid_head, qid_hlist) {
        if (tmp->msqid == msqid) {
            found = tmp;
            break;
        }
    }

    if (found)
        get_handle(MSG_TO_HANDLE(found));

    unlock(&msgq_list_lock);
    return found;
}

void put_msg_handle(struct shim_msg_handle* msgq) {
    put_handle(MSG_TO_HANDLE(msgq));
}

static void* __get_msg_qobj(struct shim_msg_handle* msgq) {
    struct msg_qobj* obj = NULL;

    if (msgq->freed) {
        obj         = msgq->freed;
        msgq->freed = obj->next;
        obj->next   = NULL;
        return obj;
    }

    if (msgq->queueused < msgq->queuesize) {
        obj = &msgq->queue[msgq->queueused];
        msgq->queueused++;
        obj->next = NULL;
        return obj;
    }

    return NULL;
}

static void __free_msg_qobj(struct shim_msg_handle* msgq, void* obj) {
    ((struct msg_qobj*)obj)->next = msgq->freed;
    msgq->freed                   = obj;
}

static void __free_msg_linked_qobjs(struct shim_msg_handle* msgq, void* obj) {
    struct msg_qobj* qobj = obj;
    while (qobj) {
        struct msg_qobj* next = qobj->next;
        __free_msg_qobj(msgq, qobj);
        qobj = next;
    }
}

static int __del_msg_handle(struct shim_msg_handle* msgq) {
    struct shim_handle* hdl = MSG_TO_HANDLE(msgq);
    assert(locked(&hdl->lock));

    if (msgq->deleted)
        return -EIDRM;

    msgq->deleted = true;
    free(msgq->queue);
    msgq->queuesize = 0;
    msgq->queueused = 0;
    free(msgq->types);
    msgq->ntypes = 0;

    lock(&msgq_list_lock);
    LISTP_DEL_INIT(msgq, &msgq_list, list);
    put_handle(hdl);
    if (!LIST_EMPTY(msgq, key_hlist)) {
        // DEP: Yuck, re-find the head; maybe we can do better...
        LISTP_TYPE(shim_msg_handle)* key_head = &msgq_key_hlist[MSGQ_HASH(msgq->msqkey)];
        LISTP_DEL_INIT(msgq, key_head, key_hlist);
        put_handle(hdl);
    }
    if (!LIST_EMPTY(msgq, qid_hlist)) {
        // DEP: Yuck, re-find the head; maybe we can do better...
        LISTP_TYPE(shim_msg_handle)* qid_head = &msgq_qid_hlist[MSGQ_HASH(msgq->msqid)];
        LISTP_DEL_INIT(msgq, qid_head, qid_hlist);
        put_handle(hdl);
    }
    unlock(&msgq_list_lock);
    return 0;
}

int del_msg_handle(struct shim_msg_handle* msgq) {
    struct shim_handle* hdl = MSG_TO_HANDLE(msgq);
    lock(&hdl->lock);
    int ret = __del_msg_handle(msgq);
    unlock(&hdl->lock);
    return ret;
}

int shim_do_msgget(key_t key, int msgflg) {
    INC_PROFILE_OCCURENCE(syscall_use_ipc);
    IDTYPE msgid = 0;
    int ret;

    if (!create_lock_runtime(&msgq_list_lock)) {
        return -ENOMEM;
    }

    if (key != IPC_PRIVATE) {
        struct shim_msg_handle* msgq = get_msg_handle_by_key(key);
        if (msgq) {
            msgid = msgq->msqid;
            put_msg_handle(msgq);
            return (msgflg & IPC_EXCL) ? -EEXIST : (int)msgid;
        }
    }

    struct sysv_key k;
    k.key  = key;
    k.type = SYSV_MSGQ;

    if (msgflg & IPC_CREAT) {
        do {
            msgid = allocate_sysv(0, 0);
            if (!msgid)
                ipc_sysv_lease_send(NULL);
        } while (!msgid);

        if (key != IPC_PRIVATE) {
            if ((ret = ipc_sysv_tellkey_send(NULL, 0, &k, msgid, 0)) < 0) {
                release_sysv(msgid);
                return ret;
            }
        }

        add_msg_handle(key, msgid, true);
    } else {
        /* query the manager with the key to find the
           corresponding sysvkey */
        if ((ret = ipc_sysv_findkey_send(&k)) < 0)
            return ret;

        msgid = ret;

        if ((ret = ipc_sysv_query_send(msgid)) < 0)
            return ret;

        add_msg_handle(key, msgid, false);
    }

    return msgid;
}

static int connect_msg_handle(int msqid, struct shim_msg_handle** msgqp) {
    struct shim_msg_handle* msgq = get_msg_handle_by_id(msqid);
    int ret;

    if (!msgq) {
        if ((ret = ipc_sysv_query_send(msqid)) < 0)
            return ret;

        if (!msgq) {
            lock(&msgq_list_lock);
            ret = __add_msg_handle(IPC_PRIVATE, msqid, false, &msgq);
            unlock(&msgq_list_lock);
            if (ret < 0)
                return ret;
        }
    }

    if (msgq->deleted)
        return -EIDRM;

    *msgqp = msgq;
    return 0;
}

int recover_msg_ownership(struct shim_msg_handle* msgq) {
    struct shim_handle* hdl = MSG_TO_HANDLE(msgq);
    lock(&hdl->lock);
    assert(!msgq->owned);
    int ret = __load_msg_persist(msgq, true);

    if (ret < 0) {
        ret = (ret == -ENOENT) ? -EIDRM : ret;
        goto out;
    }

    msgq->owned = true;
    DkEventSet(msgq->event);
out:
    unlock(&hdl->lock);
    return 0;
}

int shim_do_msgsnd(int msqid, const void* msgp, size_t msgsz, int msgflg) {
    INC_PROFILE_OCCURENCE(syscall_use_ipc);
    // Issue #755 - https://github.com/oscarlab/graphene/issues/755
    __UNUSED(msgflg);

    int ret;

    if (msgsz > MSGMAX)
        return -EINVAL;

    if (!msgp)
        return -EFAULT;

    struct __kernel_msgbuf* msgbuf = (struct __kernel_msgbuf*)msgp;

    if (msgbuf->mtype < 0)
        return -EINVAL;

    struct shim_msg_handle* msgq;

    if (!create_lock_runtime(&msgq_list_lock)) {
        return -ENOMEM;
    }

    if ((ret = connect_msg_handle(msqid, &msgq)) < 0)
        return ret;

    ret = add_sysv_msg(msgq, msgbuf->mtype, msgsz, msgbuf->mtext, NULL);
    put_msg_handle(msgq);
    return ret;
}

int shim_do_msgrcv(int msqid, void* msgp, size_t msgsz, long msgtype, int msgflg) {
    INC_PROFILE_OCCURENCE(syscall_use_ipc);

    // Issue #755 - https://github.com/oscarlab/graphene/issues/755
    __UNUSED(msgflg);

    int ret;

    if (msgsz > MSGMAX)
        return -EINVAL;
    if (!msgp)
        return -EFAULT;

    struct __kernel_msgbuf* msgbuf = (struct __kernel_msgbuf*)msgp;
    struct shim_msg_handle* msgq;

    if (!create_lock_runtime(&msgq_list_lock)) {
        return -ENOMEM;
    }

    if ((ret = connect_msg_handle(msqid, &msgq)) < 0)
        return ret;

    ret = get_sysv_msg(msgq, msgtype, msgsz, msgbuf->mtext, msgflg, NULL);
    put_msg_handle(msgq);
    return ret;
}

int shim_do_msgctl(int msqid, int cmd, struct msqid_ds* buf) {
    INC_PROFILE_OCCURENCE(syscall_use_ipc);

    // Issue #756 - https://github.com/oscarlab/graphene/issues/756
    __UNUSED(buf);

    struct shim_msg_handle* msgq;
    int ret;

    if (!create_lock_runtime(&msgq_list_lock)) {
        return -ENOMEM;
    }

    if ((ret = connect_msg_handle(msqid, &msgq)) < 0)
        return ret;

    switch (cmd) {
        case IPC_RMID:
            if (!msgq->owned) {
                ret = ipc_sysv_delres_send(NULL, 0, msgq->msqid, SYSV_MSGQ);
                if (ret < 0)
                    break;
            }

            del_msg_handle(msgq);
            break;

        default:
            ret = -ENOSYS;
            break;
    }

    put_msg_handle(msgq);
    return ret;
}

static struct msg_type* __add_msg_type(int type, struct msg_type** ptypes, int* pntypes,
                                       int* pmaxtypes) {
    struct msg_type* types = *ptypes;
    int ntypes             = *pntypes;
    int maxtypes           = *pmaxtypes;

    struct msg_type* mtype;
    for (mtype = types; mtype < &types[ntypes] && mtype->type <= type; mtype++)
        if (mtype->type == type)
            return mtype;

    int off                    = mtype - types;
    struct msg_type* new_types = types;

    if (ntypes == maxtypes)
        new_types = malloc(sizeof(struct msg_type) * maxtypes * 2);

    if (mtype < &types[ntypes])
        memmove(new_types + off + 1, mtype, sizeof(struct msg_type) * (ntypes - off));

    if (new_types != types) {
        memcpy(new_types, types, sizeof(struct msg_type) * off);
        free(types);
        mtype      = new_types + off;
        *ptypes    = new_types;
        *pmaxtypes = maxtypes * 2;
    }

    mtype->type     = type;
    mtype->msgs     = NULL;
    mtype->msg_tail = NULL;
    mtype->reqs     = NULL;
    mtype->req_tail = NULL;

    (*pntypes)++;
    return mtype;
}

static int __load_msg_qobjs(struct shim_msg_handle* msgq, struct msg_type* mtype,
                            struct msg_item* msg, void* data) {
    size_t copysize = MSG_ITEM_DATA_SIZE(msg->size);
    memcpy(data, msg->data, copysize);
    mtype->msgs = msg->next;
    __free_msg_qobj(msgq, msg);

    while (copysize < msg->size) {
        assert(mtype->msgs);
        struct msg_ext_item* ext = (struct msg_ext_item*)mtype->msgs;
        size_t sz                = MSG_EXT_ITEM_DATA_SIZE(msg->size - copysize);
        memcpy(data + copysize, ext->data, sz);
        copysize += sz;
        mtype->msgs = ext->next;
        __free_msg_qobj(msgq, ext);
    }

    if (!mtype->msgs)
        mtype->msg_tail = NULL;

    msgq->nmsgs--;
    msgq->currentsize -= msg->size;
    return 0;
}

static int __store_msg_qobjs(struct shim_msg_handle* msgq, struct msg_type* mtype, size_t size,
                             const void* data) {
    struct msg_item* newmsg = __get_msg_qobj(msgq);
    if (!newmsg)
        return -EAGAIN;

    struct msg_item* old_tail = mtype->msg_tail;

    newmsg->next    = NULL;
    newmsg->size    = size;
    size_t copysize = MSG_ITEM_DATA_SIZE(size);
    memcpy(newmsg->data, data, copysize);

    if (mtype->msg_tail) {
        mtype->msg_tail->next = newmsg;
        mtype->msg_tail       = newmsg;
    } else {
        assert(!mtype->msgs);
        mtype->msgs = mtype->msg_tail = newmsg;
    }

    while (copysize < size) {
        struct msg_ext_item* ext = __get_msg_qobj(msgq);
        if (!ext)
            goto eagain;

        size_t sz = MSG_EXT_ITEM_DATA_SIZE(size - copysize);
        memcpy(ext->data, data + copysize, sz);
        ext->next             = NULL;
        mtype->msg_tail->next = ext;
        mtype->msg_tail       = (struct msg_item*)ext;
        copysize += sz;
    }

    msgq->nmsgs++;
    msgq->currentsize += size;
    return 0;

eagain:
    __free_msg_linked_qobjs(msgq, newmsg);

    if (mtype->msgs == newmsg)
        mtype->msgs = NULL;

    mtype->msg_tail = old_tail;
    return -EAGAIN;
}

#if MIGRATE_SYSV_MSG == 1
static int msg_balance_migrate(struct shim_handle* hdl, struct sysv_client* client);

static struct sysv_balance_policy msg_policy = {
    .score_decay       = MSG_SCORE_DECAY,
    .score_max         = MSG_SCORE_MAX,
    .balance_threshold = MSG_BALANCE_THRESHOLD,
    .migrate           = &msg_balance_migrate,
};
#endif

DEFINE_PROFILE_INTERVAL(add_sysv_msg, sysv_msg);

int add_sysv_msg(struct shim_msg_handle* msgq, long type, size_t size, const void* data,
                 struct sysv_client* src) {
    BEGIN_PROFILE_INTERVAL();

    struct shim_handle* hdl = MSG_TO_HANDLE(msgq);
    int ret                 = 0;
    lock(&hdl->lock);

    if (msgq->deleted) {
        ret = -EIDRM;
        goto out_locked;
    }

    if (!msgq->owned) {
        unlock(&hdl->lock);
        ret = ipc_sysv_msgsnd_send(src->port, src->vmid, msgq->msqid, type, data, size, src->seq);
        goto out;
    }

    struct msg_type* mtype = __add_msg_type(type, &msgq->types, &msgq->ntypes, &msgq->maxtypes);

    if ((ret = __store_msg_qobjs(msgq, mtype, size, data)) < 0)
        goto out_locked;

#if MIGRATE_SYSV_MSG == 1
    if (msgq->owned)
        __balance_sysv_score(&msg_policy, hdl, msgq->scores, MAX_SYSV_CLIENTS, src, MSG_SND_SCORE);
#endif
    DkEventSet(msgq->event);
    ret = 0;
out_locked:
    unlock(&hdl->lock);
out:
    SAVE_PROFILE_INTERVAL(add_sysv_msg);
    return ret;
}

static struct msg_type* __find_msg_type(int type, struct msg_type* types, int ntypes) {
    for (struct msg_type* mtype = types; mtype < &types[ntypes] && mtype->type <= type; mtype++)
        if (mtype->type == type)
            return mtype;
    return NULL;
}

static int __add_msg_req(struct shim_msg_handle* msgq, struct msg_type* mtype, int size, int flags,
                         struct sysv_client* src) {
    if (msgq->deleted)
        return -EIDRM;

    struct msg_req* req = __get_msg_qobj(msgq);
    if (!req)
        return -ENOMEM;

    get_ipc_port(src->port);

    req->next  = NULL;
    req->size  = size;
    req->flags = flags;
    req->dest  = *src;

    if (mtype->req_tail) {
        mtype->req_tail->next = req;
        mtype->req_tail       = req;
    } else {
        assert(!mtype->reqs);
        mtype->reqs = mtype->req_tail = req;
    }

    return 0;
}

DEFINE_PROFILE_INTERVAL(get_sysv_msg, sysv_msg);

int get_sysv_msg(struct shim_msg_handle* msgq, long type, size_t size, void* data, int flags,
                 struct sysv_client* src) {
    BEGIN_PROFILE_INTERVAL();
    int ret                   = 0;
    struct shim_handle* hdl   = MSG_TO_HANDLE(msgq);
    struct msg_item* msg      = NULL;
    struct msg_type* alltypes = NULL;
    struct msg_type* mtype    = NULL;
    lock(&hdl->lock);

    if (msgq->deleted) {
        ret = -EIDRM;
        goto out_locked;
    }

#if MIGRATE_SYSV_MSG == 1
    if (msgq->owned) {
        __balance_sysv_score(&msg_policy, hdl, msgq->scores, MAX_SYSV_CLIENTS, src, MSG_RCV_SCORE);

        if (!msgq->owned && src) {
            struct shim_ipc_info* owner = msgq->owner;
            assert(owner);
            ret = ipc_sysv_movres_send(src, owner->vmid, qstrgetstr(&owner->uri), msgq->lease,
                                       msgq->msqid, SYSV_MSGQ);
            goto out_locked;
        }
    }
#endif

    if (!msgq->owned) {
        if (src) {
            struct shim_ipc_info* owner = msgq->owner;
            ret = owner ? ipc_sysv_movres_send(src, owner->vmid, qstrgetstr(&owner->uri),
                                               msgq->lease, msgq->msqid, SYSV_MSGQ)
                        : -ECONNREFUSED;
            goto out_locked;
        }

    unowned:
        unlock(&hdl->lock);
        ret = ipc_sysv_msgrcv_send(msgq->msqid, type, flags, data, size);
        if (ret != -EAGAIN && ret != -ECONNREFUSED)
            goto out;

        lock(&hdl->lock);

        if (!msgq->owned)
            goto out_locked;
    }

    while (1) {
        if (alltypes != msgq->types || !mtype || mtype->type != type) {
            alltypes = msgq->types;
            mtype    = __find_msg_type(type, alltypes, msgq->ntypes);
        }

        if (mtype && mtype->msgs) {
            msg = mtype->msgs;
            if (msg->size > size && !(flags & MSG_NOERROR)) {
                ret = -E2BIG;
                goto out;
            }
            break;
        }

        if (flags & IPC_NOWAIT || src)
            break;

        unlock(&hdl->lock);
        object_wait_with_retry(msgq->event);
        lock(&hdl->lock);

        if (!msgq->owned)
            goto unowned;
    }

    if (!msg) {
        ret =
            (!(flags & IPC_NOWAIT) && src) ? __add_msg_req(msgq, mtype, size, flags, src) : -ENOMSG;
        goto out_locked;
    }

    if ((ret = __load_msg_qobjs(msgq, mtype, msg, data)) < 0)
        goto out_locked;

    ret = msg->size;
out_locked:
    unlock(&hdl->lock);
out:
    SAVE_PROFILE_INTERVAL(get_sysv_msg);
    return ret;
}

static int __store_msg_persist(struct shim_msg_handle* msgq) {
    int ret = 0;

    if (msgq->deleted)
        goto out;

    debug("store msgq %d to persistent store\n", msgq->msqid);

    char fileuri[20];
    snprintf(fileuri, 20, URI_PREFIX_FILE "msgq.%08x", msgq->msqid);

    PAL_HANDLE file = DkStreamOpen(fileuri, PAL_ACCESS_RDWR, 0600, PAL_CREATE_TRY, 0);
    if (!file) {
        ret = -PAL_ERRNO;
        goto out;
    }

    int expected_size = sizeof(struct msg_handle_backup) + sizeof(struct msg_backup) * msgq->nmsgs +
                        msgq->currentsize;

    if (DkStreamSetLength(file, expected_size))
        goto err_file;

    void* mem =
        (void*)DkStreamMap(file, NULL, PAL_PROT_READ | PAL_PROT_WRITE, 0,
                           ALLOC_ALIGN_UP(expected_size));
    if (!mem) {
        ret = -EFAULT;
        goto err_file;
    }

    struct msg_handle_backup* mback = mem;
    mem += sizeof(struct msg_handle_backup);

    mback->perm        = msgq->perm;
    mback->nmsgs       = msgq->nmsgs;
    mback->currentsize = msgq->currentsize;

    struct msg_type* mtype;
    for (mtype = msgq->types; mtype < &msgq->types[msgq->ntypes]; mtype++) {
        while (mtype->msgs) {
            struct msg_backup* msg = mem;
            mem += sizeof(struct msg_backup) + mtype->msgs->size;

            msg->type = mtype->type;
            msg->size = mtype->msgs->size;
            __load_msg_qobjs(msgq, mtype, mtype->msgs, msg->data);
        }

        mtype->msgs = mtype->msg_tail = NULL;
    }

    DkStreamUnmap(mem, ALLOC_ALIGN_UP(expected_size));

    if (msgq->owned)
        for (mtype = msgq->types; mtype < &msgq->types[msgq->ntypes]; mtype++) {
            struct msg_req* req = mtype->reqs;
            mtype->reqs = mtype->req_tail = NULL;
            while (req) {
                struct sysv_client* c = &req->dest;
                struct msg_req* next  = req->next;

                send_response_ipc_message(c->port, c->vmid, -EIDRM, c->seq);

                put_ipc_port(c->port);
                __free_msg_qobj(msgq, req);
                req = next;
            }
        }

    msgq->owned = false;
    ret         = 0;
    goto out;

err_file:
    DkStreamDelete(file, 0);
    DkObjectClose(file);

out:
    // To wake up any receiver waiting on local message which must
    // now be requested from new owner.
    DkEventSet(msgq->event);
    return ret;
}

static int __load_msg_persist(struct shim_msg_handle* msgq, bool readmsg) {
    int ret = 0;

    char fileuri[20];
    snprintf(fileuri, 20, URI_PREFIX_FILE "msgq.%08x", msgq->msqid);

    PAL_HANDLE file = DkStreamOpen(fileuri, PAL_ACCESS_RDONLY, 0, 0, 0);

    if (!file)
        return -EIDRM;

    struct msg_handle_backup mback;

    size_t bytes = DkStreamRead(file, 0, sizeof(struct msg_handle_backup), &mback, NULL, 0);

    if (bytes == PAL_STREAM_ERROR) {
        ret = -PAL_ERRNO;
        goto out;
    }
    if (bytes < sizeof(struct msg_handle_backup)) {
        ret = -EFAULT;
        goto out;
    }

    msgq->perm = mback.perm;

    if (!readmsg || !mback.nmsgs)
        goto done;

    int expected_size = sizeof(struct msg_handle_backup) + sizeof(struct msg_backup) * mback.nmsgs +
                        mback.currentsize;

    void* mem = (void*)DkStreamMap(file, NULL, PAL_PROT_READ, 0, ALLOC_ALIGN_UP(expected_size));

    if (!mem) {
        ret = -PAL_ERRNO;
        goto out;
    }

    mem += sizeof(struct msg_handle_backup);

    struct msg_type* mtype = NULL;
    for (int i = 0; i < mback.nmsgs; i++) {
        struct msg_backup* m = mem;
        mem += sizeof(struct msg_backup) + m->size;

        debug("load msg: type=%ld, size=%d\n", m->type, m->size);

        if (!mtype || mtype->type != m->type)
            mtype = __add_msg_type(m->type, &msgq->types, &msgq->ntypes, &msgq->maxtypes);

        if ((ret = __store_msg_qobjs(msgq, mtype, m->size, m->data)) < 0)
            goto out;
    };

    DkStreamUnmap(mem, ALLOC_ALIGN_UP(expected_size));

done:
    DkStreamDelete(file, 0);
    ret = 0;
    goto out;

out:
    DkObjectClose(file);
    return ret;
}

int store_all_msg_persist(void) {
    struct shim_msg_handle* msgq;
    struct shim_msg_handle* n;

    if (!create_lock_runtime(&msgq_list_lock)) {
        return -ENOMEM;
    }

    lock(&msgq_list_lock);

    LISTP_FOR_EACH_ENTRY_SAFE(msgq, n, &msgq_list, list) {
        if (msgq->owned) {
            struct shim_handle* hdl = MSG_TO_HANDLE(msgq);
            lock(&hdl->lock);
            __store_msg_persist(msgq);
            unlock(&hdl->lock);
        }
    }

    unlock(&msgq_list_lock);
    return 0;
}

int shim_do_msgpersist(int msqid, int cmd) {
    struct shim_msg_handle* msgq;
    struct shim_handle* hdl;
    int ret = -EINVAL;

    if (!create_lock_runtime(&msgq_list_lock)) {
        return -ENOMEM;
    }

    switch (cmd) {
        case MSGPERSIST_STORE:
            msgq = get_msg_handle_by_id(msqid);
            if (!msgq)
                return -EINVAL;

            hdl = MSG_TO_HANDLE(msgq);
            lock(&hdl->lock);
            ret = __store_msg_persist(msgq);
            unlock(&hdl->lock);
            put_msg_handle(msgq);
            break;

        case MSGPERSIST_LOAD:
            lock(&msgq_list_lock);
            ret = __add_msg_handle(0, msqid, false, &msgq);
            if (!ret)
                ret = __load_msg_persist(msgq, true);
            unlock(&msgq_list_lock);
            put_msg_handle(msgq);
            break;
    }

    return ret;
}

#if MIGRATE_SYSV_MSG == 1
static int msg_balance_migrate(struct shim_handle* hdl, struct sysv_client* src) {
    struct shim_msg_handle* msgq = &hdl->info.msg;
    int ret                      = 0;

    debug("trigger msg queue balancing, migrate to process %u\n", src->vmid);

    if ((ret = __store_msg_persist(msgq)) < 0)
        return 0;

    struct shim_ipc_info* info = lookup_ipc_info(src->vmid);
    if (!info)
        goto failed;

    ipc_sysv_sublease_send(src->vmid, msgq->msqid, qstrgetstr(&info->uri), &msgq->lease);

    ret = ipc_sysv_msgmov_send(src->port, src->vmid, msgq->msqid, msgq->lease, msgq->scores,
                               MAX_SYSV_CLIENTS);
    if (ret < 0)
        goto failed_info;

    msgq->owner = info;

    for (struct msg_type* mtype = msgq->types; mtype < &msgq->types[msgq->ntypes]; mtype++) {
        struct msg_req* req = mtype->reqs;
        mtype->reqs = mtype->req_tail = NULL;
        while (req) {
            struct msg_req* next = req->next;

            ipc_sysv_movres_send(&req->dest, info->vmid, qstrgetstr(&info->uri), msgq->lease,
                                 msgq->msqid, SYSV_MSGQ);

            put_ipc_port(req->dest.port);
            __free_msg_qobj(msgq, req);
            req = next;
        }
    }

    ret = 0;
    DkEventSet(msgq->event);
    goto out;

failed_info:
    put_ipc_info(info);
failed:
    ret = __load_msg_persist(msgq, true);
out:
    return ret;
}
#endif
