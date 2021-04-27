/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system calls "msgget", "msgsnd", "msgrcv" and "msgctl".
 *
 * XXX(borysp): I'm pretty sure there are possible deadlocks in this code. Sometimes it first takes
 * `msgq_list_lock` and then `hdl->lock`, sometimes other way round. Someone will have to rewrite
 * it someday.
 */

#include <errno.h>

#include "list.h"
#include "pal.h"
#include "pal_error.h"
#include "perm.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_lock.h"
#include "shim_sysv.h"
#include "shim_table.h"
#include "shim_types.h"
#include "shim_utils.h"
#include "stat.h"

#define MSGQ_HASH_LEN  8
#define MSGQ_HASH_NUM  (1 << MSGQ_HASH_LEN)
#define MSGQ_HASH_MASK (MSGQ_HASH_NUM - 1)
#define MSGQ_HASH(idx) ((idx) & MSGQ_HASH_MASK)

/* The msgq_key_hlist links them by key_hlist, and qid_hlist by qid_hlist */
DEFINE_LISTP(shim_msg_handle);
static LISTP_TYPE(shim_msg_handle) msgq_key_hlist[MSGQ_HASH_NUM];
static LISTP_TYPE(shim_msg_handle) msgq_qid_hlist[MSGQ_HASH_NUM];
static struct shim_lock msgq_list_lock;

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

    hdl->type = TYPE_MSG;

    struct shim_msg_handle* msgq = &hdl->info.msg;

    msgq->msqkey      = key;
    msgq->msqid       = msqid;
    msgq->owned       = owned;
    msgq->deleted     = false;
    msgq->currentsize = 0;
    int ret = DkEventCreate(&msgq->event, /*init_signaled=*/false, /*auto_clear=*/true);
    if (ret < 0) {
        // Needs some cleanup, but this function is broken anyway...
        return pal_to_unix_errno(ret);
    }

    msgq->queue     = malloc(MSG_QOBJ_SIZE * DEFAULT_MSG_QUEUE_SIZE);
    msgq->queuesize = DEFAULT_MSG_QUEUE_SIZE;
    msgq->queueused = 0;
    msgq->freed     = NULL;

    msgq->ntypes   = 0;
    msgq->maxtypes = INIT_MSG_TYPE_SIZE;
    msgq->types    = malloc(sizeof(struct msg_type) * INIT_MSG_TYPE_SIZE);

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

long shim_do_msgget(key_t key, int msgflg) {
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
            msgid = allocate_ipc_id(0, 0);
            if (!msgid)
                ipc_lease_send();
        } while (!msgid);

        if (key != IPC_PRIVATE) {
            if ((ret = ipc_sysv_tellkey_send(NULL, 0, &k, msgid, 0)) < 0) {
                release_ipc_id(msgid);
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

        if ((ret = ipc_query_send(msgid)) < 0)
            return ret;

        add_msg_handle(key, msgid, false);
    }

    return msgid;
}

static int connect_msg_handle(int msqid, struct shim_msg_handle** msgqp) {
    struct shim_msg_handle* msgq = get_msg_handle_by_id(msqid);
    int ret;

    if (!msgq) {
        if ((ret = ipc_query_send(msqid)) < 0)
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

long shim_do_msgsnd(int msqid, const void* msgp, size_t msgsz, int msgflg) {
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

    // FIXME: This call crashes Graphene, causing NULL dereference in add_sysv_msg. Everything in
    // this file seems to be broken, so probably better to just rewrite it?
    ret = add_sysv_msg(msgq, msgbuf->mtype, msgsz, msgbuf->mtext, NULL);
    put_msg_handle(msgq);
    return ret;
}

long shim_do_msgrcv(int msqid, void* msgp, size_t msgsz, long msgtype, int msgflg) {
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

long shim_do_msgctl(int msqid, int cmd, struct msqid_ds* buf) {
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

int add_sysv_msg(struct shim_msg_handle* msgq, long type, size_t size, const void* data,
                 struct sysv_client* src) {
    struct shim_handle* hdl = MSG_TO_HANDLE(msgq);
    int ret = 0;

    lock(&hdl->lock);

    if (msgq->deleted) {
        ret = -EIDRM;
        goto out_locked;
    }

    if (!msgq->owned) {
        unlock(&hdl->lock);
        assert(src);
        ret = ipc_sysv_msgsnd_send(src->port, src->vmid, msgq->msqid, type, data, size, src->seq);
        goto out;
    }

    struct msg_type* mtype = __add_msg_type(type, &msgq->types, &msgq->ntypes, &msgq->maxtypes);

    if ((ret = __store_msg_qobjs(msgq, mtype, size, data)) < 0)
        goto out_locked;

    DkEventSet(msgq->event);
    ret = 0;
out_locked:
    unlock(&hdl->lock);
out:
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

int get_sysv_msg(struct shim_msg_handle* msgq, long type, size_t size, void* data, int flags,
                 struct sysv_client* src) {
    int ret = 0;
    struct shim_handle* hdl   = MSG_TO_HANDLE(msgq);
    struct msg_item* msg      = NULL;
    struct msg_type* alltypes = NULL;
    struct msg_type* mtype    = NULL;
    lock(&hdl->lock);

    if (msgq->deleted) {
        ret = -EIDRM;
        goto out_locked;
    }

    if (!msgq->owned) {
        if (src) {
            ret = -ECONNREFUSED;
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
    return ret;
}
