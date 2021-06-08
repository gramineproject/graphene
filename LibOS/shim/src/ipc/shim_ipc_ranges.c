/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains functions and callbacks to communicate pid/sysv ranges.
 */

#include <errno.h>

#include "assert.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_lock.h"
#include "shim_utils.h"

#define BITS (sizeof(char) * 8)

#define INIT_RANGE_MAP_SIZE 32

struct idx_bitmap {
    unsigned char map[RANGE_SIZE / BITS];
};

struct subrange {
    IDTYPE owner;
};

struct sub_map {
    struct subrange* map[RANGE_SIZE];
};

DEFINE_LIST(range);
struct range {
    LIST_TYPE(range) hlist;
    LIST_TYPE(range) list;
    IDTYPE offset;
    IDTYPE owner;
    struct idx_bitmap* used;
    struct sub_map* subranges;
};

struct range_bitmap {
    IDTYPE map_size;
    unsigned char map[];
};

/* Helper functions __*_range*() must be called with range_map_lock held */
static struct range_bitmap* range_map;
static struct shim_lock range_map_lock;

struct ipc_range {
    IDTYPE base;
    IDTYPE size;
    IDTYPE owner;
};

#define RANGE_HASH_LEN  6
#define RANGE_HASH_NUM  (1 << RANGE_HASH_LEN)
#define RANGE_HASH_MASK (RANGE_HASH_NUM - 1)
#define RANGE_HASH(off) (((off - 1) / RANGE_SIZE) & RANGE_HASH_MASK)

/* This hash table organizes range structs by hlist */
DEFINE_LISTP(range);
static LISTP_TYPE(range) range_table[RANGE_HASH_NUM];

/* These lists organize range structs by list */
static LISTP_TYPE(range) owned_ranges;
static LISTP_TYPE(range) offered_ranges;

static int nowned = 0;
static int noffered = 0;
static int nsubed = 0;

static int __extend_range_bitmap(IDTYPE expected) {
    assert(locked(&range_map_lock));

    IDTYPE size = INIT_RANGE_MAP_SIZE;

    if (range_map)
        size = range_map->map_size;

    while (size <= expected) {
        size *= 2;
    }

    struct range_bitmap* new_map = malloc(sizeof(struct range_bitmap) + size / BITS);
    if (!new_map)
        return -ENOMEM;

    if (range_map) {
        memcpy(new_map->map, range_map->map, range_map->map_size / BITS);
        memset(new_map->map + range_map->map_size / BITS, 0, (size - range_map->map_size) / BITS);
        free(range_map);
    } else {
        memset(new_map->map, 0, size / BITS);
    }

    new_map->map_size = size;
    range_map = new_map;
    return 0;
}

static int __set_range_bitmap(IDTYPE off, bool unset) {
    assert(locked(&range_map_lock));

    IDTYPE i = off / BITS;
    IDTYPE j = off - i * BITS;
    unsigned char* m = range_map->map + i;
    unsigned char f  = 1U << j;
    if (unset) {
        if (!((*m) & f))
            return -ENOENT;
        (*m) &= ~f;
    } else {
        if ((*m) & f)
            return -EEXIST;
        (*m) |= f;
    }
    return 0;
}

static bool __check_range_bitmap(IDTYPE off) {
    assert(locked(&range_map_lock));

    IDTYPE i = off / BITS;
    IDTYPE j = off - i * BITS;
    unsigned char* m = range_map->map + i;
    unsigned char f  = 1U << j;
    return (*m) && ((*m) & f);
}

static struct range* __get_range(IDTYPE off) {
    assert(locked(&range_map_lock));

    LISTP_TYPE(range)* head = range_table + RANGE_HASH(off);

    if (!range_map || off >= range_map->map_size)
        return NULL;

    if (!__check_range_bitmap(off))
        return NULL;

    struct range* r;

    LISTP_FOR_EACH_ENTRY(r, head, hlist) {
        if (r->offset == off)
            return r;
    }

    return NULL;
}

static int __add_range(struct range* r, IDTYPE off, IDTYPE owner) {
    assert(locked(&range_map_lock));

    LISTP_TYPE(range)* head = range_table + RANGE_HASH(off);
    int ret = 0;

    if (!range_map || range_map->map_size <= off) {
        ret = __extend_range_bitmap(off);
        if (ret < 0)
            return ret;
    }

    r->owner     = owner;
    r->offset    = off;
    r->used      = NULL;
    r->subranges = NULL;

    ret = __set_range_bitmap(off, false);
    if (ret == -EEXIST) {
        struct range* tmp;

        LISTP_FOR_EACH_ENTRY(tmp, head, hlist) {
            if (tmp->offset == off) {
                LISTP_DEL(tmp, head, hlist);

                /* Chia-Che Tsai 10/17/17: only when tmp->owner == g_self_vmid, tmp is on the owned
                 * list, otherwise it is an offered. */
                if (tmp->owner == g_self_vmid) {
                    LISTP_DEL(tmp, &owned_ranges, list);
                    nowned--;
                } else {
                    LISTP_DEL(tmp, &offered_ranges, list);
                    noffered--;
                }

                r->used      = tmp->used;
                r->subranges = tmp->subranges;
                free(tmp);
                break;
            }
        }
    }

    INIT_LIST_HEAD(r, hlist);
    LISTP_ADD(r, head, hlist);
    INIT_LIST_HEAD(r, list);

    LISTP_TYPE(range)* list = (owner == g_self_vmid) ? &owned_ranges : &offered_ranges;
    struct range* prev      = LISTP_FIRST_ENTRY(list, range, list);
    struct range* tmp;

    LISTP_FOR_EACH_ENTRY(tmp, list, list) {
        if (tmp->offset >= off)
            break;
        prev = tmp;
    }

    LISTP_ADD_AFTER(r, prev, list, list);

    if (owner == g_self_vmid)
        nowned++;
    else
        noffered++;

    return 0;
}

static int add_ipc_range(IDTYPE base, IDTYPE owner) {
    IDTYPE off = (base - 1) / RANGE_SIZE;
    int ret;

    struct range* r = malloc(sizeof(struct range));
    if (!r)
        return -ENOMEM;

    lock(&range_map_lock);
    r->owner = 0;
    ret = __add_range(r, off, owner);
    if (ret < 0)
        free(r);
    unlock(&range_map_lock);
    return ret;
}

static void __del_ipc_subrange(struct subrange** ptr) {
    struct subrange* s = *ptr;
    *ptr = NULL;
    free(s);
    nsubed--;
}

int add_ipc_subrange(IDTYPE idx, IDTYPE owner) {
    IDTYPE off = (idx - 1) / RANGE_SIZE;
    IDTYPE base = off * RANGE_SIZE + 1;
    int err = 0;
    struct subrange* s = malloc(sizeof(struct subrange));
    if (!s)
        return -ENOMEM;

    assert(owner);
    lock(&range_map_lock);

    s->owner = owner;

    struct range* r = __get_range(off);
    if (!r) {
        r = malloc(sizeof(struct range));
        if (!r) {
            err = -ENOMEM;
            goto failed;
        }

        if ((err = __add_range(r, off, 0)) < 0) {
            free(r);
            goto failed;
        }
    }

    if (!r->subranges) {
        r->subranges = calloc(1, sizeof(struct sub_map));
        if (!r->subranges) {
            err = -ENOMEM;
            goto failed;
        }
    }

    struct subrange** m = &r->subranges->map[idx - base];

    if (*m)
        __del_ipc_subrange(m);

    (*m) = s;
    nsubed++;

    unlock(&range_map_lock);
    return 0;

failed:
    unlock(&range_map_lock);
    free(s);
    return err;
}

static int alloc_ipc_range(IDTYPE owner, IDTYPE* base) {
    struct range* r = malloc(sizeof(struct range));
    if (!r)
        return -ENOMEM;

    int ret = 0;
    lock(&range_map_lock);
    r->owner = 0;
    IDTYPE i = 0, j = 0;

    if (range_map)
        for (i = 0; i < range_map->map_size; i++) {
            unsigned char map = range_map->map[i];

            if (map < 255U) {
                for (j = 0; j < BITS; map >>= 1, j++)
                    if (!(map & 1U))
                        break;
                assert(j < BITS);
                break;
            }
        }

    ret = __add_range(r, i * BITS + j, owner);
    if (ret < 0) {
        free(r);
        goto out;
    }

    if (base)
        *base = (i * BITS + j) * RANGE_SIZE + 1;

out:
    unlock(&range_map_lock);
    return ret;
}

static int get_ipc_range(IDTYPE idx, struct ipc_range* range) {
    IDTYPE off = (idx - 1) / RANGE_SIZE;

    lock(&range_map_lock);

    struct range* r = __get_range(off);
    if (!r) {
        unlock(&range_map_lock);
        return -ESRCH;
    }

    IDTYPE base = r->offset * RANGE_SIZE + 1;
    IDTYPE sz = RANGE_SIZE;
    IDTYPE owner = r->owner;

    if (r->subranges && r->subranges->map[idx - base]) {
        struct subrange* s = r->subranges->map[idx - base];
        base = idx;
        sz = 1;
        owner = s->owner;
    }

    if (!owner) {
        unlock(&range_map_lock);
        return -ESRCH;
    }

    range->base  = base;
    range->size  = sz;
    range->owner = owner;

    unlock(&range_map_lock);
    return 0;
}

IDTYPE allocate_ipc_id(IDTYPE min, IDTYPE max) {
    IDTYPE idx = min;
    struct range* r;
    lock(&range_map_lock);

    LISTP_FOR_EACH_ENTRY(r, &owned_ranges, list) {
        if (max && idx >= max)
            break;

        IDTYPE base = r->offset * RANGE_SIZE + 1;
        if (idx >= base + RANGE_SIZE)
            continue;
        if (idx < base)
            idx = base;
        if (!r->used) {
            r->used = calloc(1, sizeof(struct idx_bitmap));
            if (!r->used)
                continue;
        }

        IDTYPE i         = (idx - base) / BITS;
        IDTYPE j         = (idx - base) - i * BITS;
        unsigned char* m = r->used->map + i;
        unsigned char f  = 1U << j;

        for (; i < RANGE_SIZE / BITS; i++, j = 0, f = 1U, m++) {
            unsigned char map = (*m) ^ (f - 1);

            if (map < 255U) {
                for (; j < BITS; f <<= 1, j++)
                    if (!(map & f)) {
                        (*m) |= f;
                        idx = base + i * BITS + j;
                        goto out;
                    }
            }
        }
    }
    idx = 0;

out:
    unlock(&range_map_lock);
    return idx;
}

void release_ipc_id(IDTYPE idx) {
    IDTYPE off = (idx - 1) / RANGE_SIZE;
    IDTYPE base = off * RANGE_SIZE + 1;

    lock(&range_map_lock);

    struct range* r = __get_range(off);
    if (!r)
        goto out;

    if (r->subranges && r->subranges->map[idx - base])
        __del_ipc_subrange(&r->subranges->map[idx - base]);

    if (!r->used)
        goto out;

    if (idx < base || idx >= base + RANGE_SIZE)
        goto out;

    IDTYPE i = (idx - base) / BITS;
    IDTYPE j = (idx - base) - i * BITS;
    unsigned char* m = r->used->map + i;
    unsigned char f  = 1U << j;
    if ((*m) & f) {
        (*m) &= ~f;
    }

out:
    unlock(&range_map_lock);
}

int init_ns_ranges(void) {
    if (!create_lock(&range_map_lock)) {
        return -ENOMEM;
    }
    return 0;
}

int find_owner(IDTYPE idx, IDTYPE* owner) {
    struct ipc_range range = { 0 };

    int ret = get_ipc_range(idx, &range);
    if (ret == -ESRCH) {
        if ((ret = ipc_query_send(idx)) < 0)
            return -ESRCH;

        ret = get_ipc_range(idx, &range);
    }

    if (ret < 0)
        goto out;

    if (range.owner == g_self_vmid) {
        ret = -ESRCH;
        goto out;
    }

    if (owner)
        *owner = range.owner;
out:
    assert(ret || range.owner);
    return ret;
}

int ipc_lease_send(void) {
    if (!g_process_ipc_ids.leader_vmid) {
        return alloc_ipc_range(g_self_vmid, NULL);
    }

    IDTYPE leader = g_process_ipc_ids.leader_vmid;

    size_t total_msg_size = get_ipc_msg_with_ack_size(0);
    struct shim_ipc_msg_with_ack* msg = __alloca(total_msg_size);
    init_ipc_msg_with_ack(msg, IPC_MSG_LEASE, total_msg_size);

    log_debug("ipc send to %u: IPC_MSG_LEASE\n", leader);

    return send_ipc_message_with_ack(msg, leader, NULL);
}

int ipc_lease_callback(IDTYPE src, void* data, unsigned long seq) {
    __UNUSED(data);
    log_debug("ipc callback from %u: IPC_MSG_LEASE\n", src);

    IDTYPE base = 0;

    int ret = alloc_ipc_range(src, &base);
    if (ret < 0)
        goto out;

    ret = ipc_offer_send(src, base, RANGE_SIZE, seq);
out:
    return ret;
}

int ipc_offer_send(IDTYPE dest, IDTYPE base, IDTYPE size, unsigned long seq) {
    int ret = 0;
    struct shim_ipc_offer msgin = {
        .base = base,
        .size = size,
    };

    size_t total_msg_size = get_ipc_msg_size(sizeof(msgin));
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_OFFER, total_msg_size);
    msg->header.seq = seq;

    memcpy(&msg->data, &msgin, sizeof(msgin));

    log_debug("ipc send to %u: IPC_MSG_OFFER(%u, %u)\n", dest, base, size);
    ret = send_ipc_message(msg, dest);
    return ret;
}

static void msg_add_range(struct shim_ipc_msg_with_ack* req_msg, void* _args) {
    struct shim_ipc_offer* args = _args;

    switch (args->size) {
        case RANGE_SIZE:
            add_ipc_range(args->base, g_self_vmid);
            break;
        case 1:
            if (req_msg) {
                struct shim_ipc_sublease* s = (void*)&req_msg->msg.data;
                add_ipc_subrange(s->idx, s->tenant);
            }
            break;
        default:
            BUG();
    }

    if (req_msg) {
        assert(req_msg->thread);
        thread_wakeup(req_msg->thread);
    }
}

int ipc_offer_callback(IDTYPE src, void* data, unsigned long seq) {
    struct shim_ipc_offer* msgin = data;

    log_debug("ipc callback from %u: IPC_MSG_OFFER(%u, %u)\n", src, msgin->base, msgin->size);

    if (msgin->size == RANGE_SIZE || msgin->size == 1) {
        ipc_msg_response_handle(seq, msg_add_range, msgin);
    }
    return 0;
}

int ipc_sublease_send(IDTYPE tenant, IDTYPE idx) {
    if (!g_process_ipc_ids.leader_vmid) {
        return add_ipc_subrange(idx, tenant);
    }

    struct shim_ipc_sublease msgin = {
        .tenant = tenant,
        .idx = idx,
    };

    size_t total_msg_size = get_ipc_msg_with_ack_size(sizeof(msgin));
    struct shim_ipc_msg_with_ack* msg = __alloca(total_msg_size);
    init_ipc_msg_with_ack(msg, IPC_MSG_SUBLEASE, total_msg_size);

    memcpy(&msg->msg.data, &msgin, sizeof(msgin));

    IDTYPE leader = g_process_ipc_ids.leader_vmid;
    log_debug("ipc send to %u: IPC_MSG_SUBLEASE(%u, %u)\n", leader, tenant, idx);

    return send_ipc_message_with_ack(msg, leader, NULL);
}

int ipc_sublease_callback(IDTYPE src, void* data, unsigned long seq) {
    struct shim_ipc_sublease* msgin = data;

    log_debug("ipc callback from %u: IPC_MSG_SUBLEASE(%u, %u)\n", src, msgin->idx, msgin->tenant);

    int ret = add_ipc_subrange(msgin->idx, msgin->tenant);
    if (ret < 0) {
        return ret;
    }

    return ipc_offer_send(src, msgin->idx, 1, seq);
}

int ipc_query_send(IDTYPE idx) {
    struct ipc_range range = { 0 };
    if (!get_ipc_range(idx, &range)) {
        return 0;
    }

    if (!g_process_ipc_ids.leader_vmid) {
        return -ESRCH;
    }

    struct shim_ipc_query msgin = {
        .idx = idx,
    };

    size_t total_msg_size = get_ipc_msg_with_ack_size(sizeof(msgin));
    struct shim_ipc_msg_with_ack* msg = __alloca(total_msg_size);
    init_ipc_msg_with_ack(msg, IPC_MSG_QUERY, total_msg_size);

    memcpy(&msg->msg.data, &msgin, sizeof(msgin));

    IDTYPE leader = g_process_ipc_ids.leader_vmid;
    log_debug("ipc send to %u: IPC_MSG_QUERY(%u)\n", leader, idx);

    return send_ipc_message_with_ack(msg, leader, NULL);
}

static int ipc_answer_send(IDTYPE dest, size_t answers_cnt, struct ipc_ns_offered* answers,
                           unsigned long seq) {
    struct shim_ipc_answer msgin = {
        .answers_cnt = answers_cnt,
    };

    size_t total_msg_size = get_ipc_msg_size(sizeof(msgin) + answers_cnt * sizeof(answers[0]));
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_ANSWER, total_msg_size);
    msg->header.seq = seq;

    memcpy(&msg->data, &msgin, sizeof(msgin));
    memcpy(&((struct shim_ipc_answer*)&msg->data)->answers, answers,
           answers_cnt * sizeof(answers[0]));

    if (answers_cnt == 1)
        log_debug("ipc send to %u: IPC_MSG_ANSWER([%u, %u])\n", dest, answers[0].base,
                  answers[0].size);
    else if (answers_cnt)
        log_debug("ipc send to %u: IPC_MSG_ANSWER([%u, %u], ...)\n", dest, answers[0].base,
                  answers[0].size);

    return send_ipc_message(msg, dest);
}

int ipc_answer_callback(IDTYPE src, void* data, unsigned long seq) {
    struct shim_ipc_answer* msgin = data;

    if (msgin->answers_cnt == 1) {
        log_debug("ipc callback from %u: IPC_MSG_ANSWER([%u, %u])\n", src, msgin->answers[0].base,
                  msgin->answers[0].size);
    } else if (msgin->answers_cnt) {
        log_debug("ipc callback from %u: IPC_MSG_ANSWER([%u, %u], ...)\n", src,
                  msgin->answers[0].base, msgin->answers[0].size);
    }

    for (size_t i = 0; i < msgin->answers_cnt; i++) {
        struct ipc_ns_offered* ans = &msgin->answers[i];

        switch (ans->size) {
            case RANGE_SIZE:
                add_ipc_range(ans->base, ans->owner);
                break;
            case 1:
                add_ipc_subrange(ans->base, ans->owner);
                break;
            default:
                break;
        }
    }

    ipc_msg_response_handle(seq, wake_req_msg_thread, NULL);

    return 0;
}

int ipc_query_callback(IDTYPE src, void* data, unsigned long seq) {
    struct shim_ipc_query* msgin = data;

    log_debug("ipc callback from %u: IPC_MSG_QUERY(%u)\n", src, msgin->idx);

    struct ipc_range range;
    int ret = 0;
    memset(&range, 0, sizeof(struct ipc_range));

    ret = get_ipc_range(msgin->idx, &range);
    if (ret < 0)
        goto out;

    assert(msgin->idx >= range.base && msgin->idx < range.base + range.size);
    assert(range.owner);

    struct ipc_ns_offered ans = {
        .base = range.base,
        .size = range.size,
        .owner = range.owner,
    };

    ret = ipc_answer_send(src, 1, &ans, seq);
out:
    return ret;
}

int ipc_queryall_send(void) {
    if (!g_process_ipc_ids.leader_vmid) {
        return 0;
    }

    IDTYPE leader = g_process_ipc_ids.leader_vmid;

    size_t total_msg_size = get_ipc_msg_with_ack_size(0);
    struct shim_ipc_msg_with_ack* msg = __alloca(total_msg_size);
    init_ipc_msg_with_ack(msg, IPC_MSG_QUERYALL, total_msg_size);

    log_debug("ipc send to %u: IPC_MSG_QUERYALL\n", leader);

    return send_ipc_message_with_ack(msg, leader, NULL);
}

int ipc_queryall_callback(IDTYPE src, void* data, unsigned long seq) {
    __UNUSED(data);
    log_debug("ipc callback from %u: IPC_MSG_QUERYALL\n", src);

    LISTP_TYPE(range)* list = &offered_ranges;
    struct range* r;

    lock(&range_map_lock);

    size_t maxanswers = nowned + noffered + nsubed;
    size_t answers_cnt = 0, i;
    struct ipc_ns_offered* answers = __alloca(sizeof(struct ipc_ns_offered) * maxanswers);

retry:
    LISTP_FOR_EACH_ENTRY(r, list, list) {
        IDTYPE owner = r->owner;

        IDTYPE base = r->offset * RANGE_SIZE + 1;
        answers[answers_cnt].base = base;
        answers[answers_cnt].size = RANGE_SIZE;
        answers[answers_cnt].owner = owner;
        answers_cnt++;

        if (!r->subranges)
            continue;

        for (i = 0; i < RANGE_SIZE; i++) {
            if (!r->subranges->map[i])
                continue;

            struct subrange* s = r->subranges->map[i];
            owner = s->owner;

            answers[answers_cnt].base = base + i;
            answers[answers_cnt].size = 1;
            answers[answers_cnt].owner = owner;
            answers_cnt++;
        }
    }

    if (list == &offered_ranges) {
        list = &owned_ranges;
        goto retry;
    }

    unlock(&range_map_lock);

    return ipc_answer_send(src, answers_cnt, answers, seq);
}

int get_all_pid_status(struct pid_status** status) {
    assert(status);

    /* run queryall unconditionally */
    ipc_queryall_send();

    size_t statuses_cnt = 0;
    size_t bufsize = RANGE_SIZE;

    struct pid_status* status_buf = malloc(bufsize);
    if (!status_buf)
        return -ENOMEM;

    LISTP_TYPE(range)* list = &offered_ranges;
    struct range* r;
    int ret;

    lock(&range_map_lock);

retry:
    LISTP_FOR_EACH_ENTRY(r, list, list) {
        struct subrange* s = NULL;
        IDTYPE owner = 0;
        IDTYPE off, idx;
        IDTYPE base;
        IDTYPE pids[RANGE_SIZE];
        struct pid_status* range_status;

#define UNDEF_IDX ((IDTYPE)-1)

        idx = UNDEF_IDX;
        off = r->offset;
        base = off * RANGE_SIZE + 1;

    next_sub:
        if (idx == UNDEF_IDX) {
            owner = r->owner;
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
            owner = s->owner;
        }

        if (owner == g_self_vmid) {
            idx++;
            goto next_sub;
        }

        if (idx == UNDEF_IDX) {
            for (int i = 0; i < RANGE_SIZE; i++)
                pids[i] = base + i;
        } else {
            pids[0] = base + idx;
        }

        ret = ipc_pid_getstatus_send(owner, idx == UNDEF_IDX ? RANGE_SIZE : 1, pids, &range_status);

        if (ret > 0) {
            if (statuses_cnt + ret > bufsize) {
                size_t newsize = bufsize * 2;

                while (statuses_cnt + ret > newsize)
                    newsize *= 2;

                struct pid_status* new_buf = malloc(newsize);

                if (!new_buf) {
                    unlock(&range_map_lock);
                    free(range_status);
                    free(status_buf);
                    return -ENOMEM;
                }

                memcpy(new_buf, status_buf, sizeof(struct pid_status) * statuses_cnt);

                free(status_buf);
                status_buf = new_buf;
                bufsize    = newsize;
            }

            memcpy(status_buf + statuses_cnt, range_status, sizeof(struct pid_status) * ret);
            free(range_status);
            statuses_cnt += ret;
        }

        idx++;
        goto next_sub;
    }

    if (list == &offered_ranges) {
        list = &owned_ranges;
        goto retry;
    }

    unlock(&range_map_lock);

    if (!statuses_cnt) {
        free(status_buf);
        *status = NULL;
        return 0;
    }

    *status = status_buf;
    return statuses_cnt;
}
