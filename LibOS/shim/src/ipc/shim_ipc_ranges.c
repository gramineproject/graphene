/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * shim_ipc_ranges.h
 *
 * This file contains functions and callbacks to communicate pid/sysv ranges.
 */

#include <errno.h>

#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_utils.h"

#define BITS (sizeof(char) * 8)

#define INIT_RANGE_MAP_SIZE 32

struct idx_bitmap {
    unsigned char map[RANGE_SIZE / BITS];
};

struct subrange {
    struct shim_ipc_info* owner;
    LEASETYPE lease;
};

struct sub_map {
    struct subrange* map[RANGE_SIZE];
};

DEFINE_LIST(range);
struct range {
    LIST_TYPE(range) hlist;
    LIST_TYPE(range) list;
    IDTYPE offset;
    struct shim_ipc_info* owner;
    LEASETYPE lease;
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
    struct shim_qstr uri;
    LEASETYPE lease;
    struct shim_ipc_port* port;
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

DEFINE_LIST(ns_query);
struct ns_query {
    IDTYPE dest;
    unsigned long seq;
    struct shim_ipc_port* port;
    LIST_TYPE(ns_query) list;
};

DEFINE_LISTP(ns_query);
static LISTP_TYPE(ns_query) ns_queries;

#define KEY_HASH_LEN  8
#define KEY_HASH_NUM  (1 << KEY_HASH_LEN)
#define KEY_HASH_MASK (KEY_HASH_NUM - 1)

DEFINE_LIST(key);
struct key {
    struct sysv_key key;
    IDTYPE id;
    LIST_TYPE(key) hlist;
};
DEFINE_LISTP(key);
static LISTP_TYPE(key) key_map[KEY_HASH_NUM];

static inline LEASETYPE get_lease(void) {
    return DkSystemTimeQuery() + LEASE_TIME;
}

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

static int __add_range(struct range* r, IDTYPE off, IDTYPE owner, const char* uri,
                       LEASETYPE lease) {
    assert(locked(&range_map_lock));

    LISTP_TYPE(range)* head = range_table + RANGE_HASH(off);
    int ret = 0;

    if (!range_map || range_map->map_size <= off) {
        ret = __extend_range_bitmap(off);
        if (ret < 0)
            return ret;
    }

    r->owner     = NULL;
    r->offset    = off;
    r->lease     = lease;
    r->used      = NULL;
    r->subranges = NULL;

    if (owner) {
        r->owner = create_ipc_info_in_list(owner, uri, strlen(uri));
        if (!r->owner)
            return -ENOMEM;
    }

    ret = __set_range_bitmap(off, false);
    if (ret == -EEXIST) {
        struct range* tmp;

        LISTP_FOR_EACH_ENTRY(tmp, head, hlist) {
            if (tmp->offset == off) {
                LISTP_DEL(tmp, head, hlist);

                /* Chia-Che Tsai 10/17/17: only when tmp->owner is non-NULL,
                 * and tmp->owner->vmid == cur_process.vmid, tmp is on the
                 * owned list, otherwise it is an offered. */
                if (tmp->owner && tmp->owner->vmid == cur_process.vmid) {
                    LISTP_DEL(tmp, &owned_ranges, list);
                    nowned--;
                } else {
                    LISTP_DEL(tmp, &offered_ranges, list);
                    noffered--;
                }

                if (tmp->owner)
                    put_ipc_info_in_list(tmp->owner);

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

    LISTP_TYPE(range)* list = (owner == cur_process.vmid) ? &owned_ranges : &offered_ranges;
    struct range* prev      = LISTP_FIRST_ENTRY(list, range, list);
    struct range* tmp;

    LISTP_FOR_EACH_ENTRY(tmp, list, list) {
        if (tmp->offset >= off)
            break;
        prev = tmp;
    }

    LISTP_ADD_AFTER(r, prev, list, list);

    if (owner == cur_process.vmid)
        nowned++;
    else
        noffered++;

    return 0;
}

static int add_ipc_range(IDTYPE base, IDTYPE owner, const char* uri, LEASETYPE lease) {
    IDTYPE off = (base - 1) / RANGE_SIZE;
    int ret;

    struct range* r = malloc(sizeof(struct range));
    if (!r)
        return -ENOMEM;

    lock(&range_map_lock);
    r->owner = NULL;
    ret = __add_range(r, off, owner, uri, lease);
    if (ret < 0)
        free(r);
    unlock(&range_map_lock);
    return ret;
}

static void __del_ipc_subrange(struct subrange** ptr) {
    struct subrange* s = *ptr;
    *ptr = NULL;
    put_ipc_info(s->owner);
    free(s);
    nsubed--;
}

int add_ipc_subrange(IDTYPE idx, IDTYPE owner, const char* uri, LEASETYPE* lease) {
    IDTYPE off = (idx - 1) / RANGE_SIZE;
    IDTYPE base = off * RANGE_SIZE + 1;
    int err = 0;
    struct subrange* s = malloc(sizeof(struct subrange));
    if (!s)
        return -ENOMEM;

    assert(owner);
    lock(&range_map_lock);

    s->owner = create_ipc_info_in_list(owner, uri, strlen(uri));
    if (!s->owner) {
        err = -ENOMEM;
        goto failed;
    }

    s->lease = (lease && (*lease)) ? (*lease) : get_lease();

    struct range* r = __get_range(off);
    if (!r) {
        r = malloc(sizeof(struct range));
        if (!r) {
            err = -ENOMEM;
            goto failed;
        }

        if ((err = __add_range(r, off, 0, NULL, 0)) < 0) {
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

    if (lease)
        *lease = s->lease;

    unlock(&range_map_lock);
    return 0;

failed:
    if (s->owner)
        put_ipc_info(s->owner);

    unlock(&range_map_lock);
    free(s);
    return err;
}

static int alloc_ipc_range(IDTYPE owner, const char* uri, IDTYPE* base, LEASETYPE* lease) {
    struct range* r = malloc(sizeof(struct range));
    if (!r)
        return -ENOMEM;

    int ret = 0;
    lock(&range_map_lock);
    r->owner = NULL;
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

    LEASETYPE l = get_lease();
    ret = __add_range(r, i * BITS + j, owner, uri, l);
    if (ret < 0) {
        if (r->owner)
            put_ipc_info(r->owner);
        free(r);
        goto out;
    }

    if (base)
        *base = (i * BITS + j) * RANGE_SIZE + 1;

    if (lease)
        *lease = l;
out:
    unlock(&range_map_lock);
    return ret;
}

static int get_ipc_range(IDTYPE idx, struct ipc_range* range, struct shim_ipc_info** info) {
    IDTYPE off = (idx - 1) / RANGE_SIZE;

    lock(&range_map_lock);

    struct range* r = __get_range(off);
    if (!r) {
        unlock(&range_map_lock);
        return -ESRCH;
    }

    IDTYPE base = r->offset * RANGE_SIZE + 1;
    IDTYPE sz = RANGE_SIZE;
    LEASETYPE l = r->lease;
    struct shim_ipc_info* p = r->owner;

    if (r->subranges && r->subranges->map[idx - base]) {
        struct subrange* s = r->subranges->map[idx - base];
        base = idx;
        sz = 1;
        l = s->lease;
        p = s->owner;
    }

    if (!p) {
        unlock(&range_map_lock);
        return -ESRCH;
    }

    if (p->port)
        get_ipc_port(p->port);

    range->base  = base;
    range->size  = sz;
    range->lease = l;
    range->owner = p->vmid;
    qstrcopy(&range->uri, &p->uri);
    range->port = p->port;

    if (info) {
        get_ipc_info(p);
        *info = p;
    }

    unlock(&range_map_lock);
    return 0;
}

#if 0 /* unused */
static int del_ipc_range(IDTYPE idx) {
    IDTYPE off = (idx - 1) / RANGE_SIZE;
    int ret = -ESRCH;

    lock(&range_map_lock);

    struct range* r = __get_range(off);
    if (!r)
        goto failed;

    if (r->subranges) {
        for (IDTYPE i = 0; i < RANGE_SIZE; i++)
            if (r->subranges->map[i]) {
                ret = -EBUSY;
                goto failed;
            }
    }
    ret = __set_range_bitmap(off, true);
    if (ret < 0)
        goto failed;

    if (r->owner->vmid == cur_process.vmid)
        nowned--;
    else
        noffered--;

    if (r->subranges)
        free(r->subranges);
    if (r->used)
        free(r->used);
    // Re-acquire the head; kind of ugly
    LISTP_TYPE(range)* head = range_table + RANGE_HASH(off);
    LISTP_DEL(r, head, hlist);

    /* Chia-Che Tsai 10/17/17: only when r->owner is non-NULL,
     * and r->owner->vmid == cur_process.vmid, r is on the
     * owned list, otherwise it is an offered. */
    if (r->owner && r->owner->vmid == cur_process.vmid)
        LISTP_DEL(r, &owned_ranges, list);
    else
        LISTP_DEL(r, &offered_ranges, list);

    put_ipc_info(r->owner);
    free(r);

    ret = 0;
failed:
    unlock(&range_map_lock);
    return ret;
}

int del_ipc_subrange(IDTYPE idx) {
    IDTYPE off = (idx - 1) / RANGE_SIZE;
    IDTYPE base = off * RANGE_SIZE + 1;
    int ret = -ESRCH;

    lock(&range_map_lock);

    struct range* r = __get_range(off);
    if (!r)
        goto failed;

    if (!r->subranges || !r->subranges->map[idx - base])
        goto failed;

    __del_ipc_subrange(&r->subranges->map[idx - base]);
    ret = 0;
failed:
    unlock(&range_map_lock);
    return ret;
}
#endif

static int renew_ipc_range(IDTYPE idx, LEASETYPE* lease) {
    IDTYPE off = (idx - 1) / RANGE_SIZE;

    lock(&range_map_lock);

    struct range* r = __get_range(off);
    if (!r) {
        unlock(&range_map_lock);
        return -ESRCH;
    }

    r->lease = get_lease();
    if (lease)
        *lease = r->lease;
    unlock(&range_map_lock);
    return 0;
}

static int renew_ipc_subrange(IDTYPE idx, LEASETYPE* lease) {
    IDTYPE off = (idx - 1) / RANGE_SIZE;
    IDTYPE base = off * RANGE_SIZE + 1;

    lock(&range_map_lock);

    struct range* r = __get_range(off);
    if (!r) {
        unlock(&range_map_lock);
        return -ESRCH;
    }

    if (!r->subranges || !r->subranges->map[idx - base]) {
        unlock(&range_map_lock);
        return -ESRCH;
    }

    struct subrange* s = r->subranges->map[idx - base];
    s->lease           = get_lease();
    if (lease)
        *lease = s->lease;
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

static void ipc_leader_exit(struct shim_ipc_port* port, IDTYPE vmid, unsigned int exitcode) {
    __UNUSED(exitcode);  // Kept for API compatibility
    lock(&cur_process.lock);

    if (!cur_process.ns || cur_process.ns->port != port) {
        unlock(&cur_process.lock);
        return;
    }

    struct shim_ipc_info* info = cur_process.ns;
    cur_process.ns = NULL;
    unlock(&cur_process.lock);

    debug("ipc port %p of process %u closed suggests leader exits\n", port, vmid);

    put_ipc_info(info);
}

/*
 * __discover_ns(): Discover the leader of this namespace.
 * @block: Whether to block for discovery.
 * @need_locate: Need the location information of the leader.
 */
static void __discover_ns(bool block, bool need_locate) {
    bool ipc_pending = false;
    lock(&cur_process.lock);

    if (cur_process.ns) {
        if (cur_process.ns->vmid == cur_process.vmid) {
            if (need_locate && qstrempty(&cur_process.ns->uri)) {
                bool is_self_ipc_info      = false; /* not cur_process.self but cur_process.ns */
                struct shim_ipc_info* info = create_ipc_info_cur_process(is_self_ipc_info);
                if (info) {
                    put_ipc_info(cur_process.ns);
                    cur_process.ns = info;
                    add_ipc_port(info->port, 0, IPC_PORT_CLIENT, &ipc_leader_exit);
                }
            }
            goto out;
        }

        if (!qstrempty(&cur_process.ns->uri))
            goto out;
    }

    /*
     * Now we need to discover the leader through IPC. Because IPC calls can be blocking,
     * we need to temporarily release cur_process.lock to prevent deadlocks. If the discovery
     * succeeds, cur_process.ns will contain the IPC information of the namespace leader.
     */

    unlock(&cur_process.lock);

    // Send out an IPC message to find out the namespace information.
    // If the call is non-blocking, can't expect the answer when the function finishes.
    int ret = ipc_findns_send(block);
    if (!ret) {
        ipc_pending = !block;  // There is still some unfinished business with IPC
        lock(&cur_process.lock);
        assert(cur_process.ns);
        goto out;
    }

    lock(&cur_process.lock);

    // At this point, (1) the leader is not me, (2) I don't know leader's URI,
    // and (3) I failed to find out the leader via IPC. But I am pressed to
    // report the leader so promote myself (and remove stale leader info).
    if (cur_process.ns)
        put_ipc_info(cur_process.ns);

    if (!need_locate) {
        cur_process.ns = create_ipc_info(cur_process.vmid, NULL, 0);
        goto out;
    }

    bool is_self_ipc_info = false; /* not cur_process.self but cur_process.ns */
    if (!(cur_process.ns = create_ipc_info_cur_process(is_self_ipc_info)))
        goto out;

    // Finally, set the IPC port as a leadership port
    add_ipc_port(cur_process.ns->port, 0, IPC_PORT_CLIENT, &ipc_leader_exit);

out:
    if (cur_process.ns && !ipc_pending) {
        // Assertions for checking the correctness of __discover_ns()
        assert(cur_process.ns->vmid == cur_process.vmid  // The current process is the leader;
               || cur_process.ns->port                   // Or there is a connected port
               || !qstrempty(&cur_process.ns->uri));     // Or there is a known URI
        if (need_locate)
            assert(!qstrempty(&cur_process.ns->uri));  // A known URI is needed
    }

    unlock(&cur_process.lock);
}

int connect_ns(IDTYPE* vmid, struct shim_ipc_port** portptr) {
    __discover_ns(true, false);  // This function cannot be called with cur_process.lock held
    lock(&cur_process.lock);

    if (!cur_process.ns) {
        unlock(&cur_process.lock);
        return -ESRCH;
    }

    if (cur_process.ns->vmid == cur_process.vmid) {
        if (vmid)
            *vmid = cur_process.ns->vmid;
        unlock(&cur_process.lock);
        return 0;
    }

    if (!cur_process.ns->port) {
        if (qstrempty(&cur_process.ns->uri)) {
            unlock(&cur_process.lock);
            return -ESRCH;
        }

        PAL_HANDLE pal_handle = DkStreamOpen(qstrgetstr(&cur_process.ns->uri), 0, 0, 0, 0);

        if (!pal_handle) {
            unlock(&cur_process.lock);
            return -PAL_ERRNO();
        }

        add_ipc_port_by_id(cur_process.ns->vmid, pal_handle, IPC_PORT_LEADER | IPC_PORT_LISTEN,
                           &ipc_leader_exit, &cur_process.ns->port);
    }

    if (vmid)
        *vmid = cur_process.ns->vmid;
    if (portptr) {
        if (cur_process.ns->port)
            get_ipc_port(cur_process.ns->port);
        *portptr = cur_process.ns->port;
    }

    unlock(&cur_process.lock);
    return 0;
}

#if 0 /* unused */
static int disconnect_ns(struct shim_ipc_port * port)
{
    lock(&cur_process.lock);
    if (cur_process.ns && cur_process.ns->port == port) {
        cur_process.ns->port = NULL;
        put_ipc_port(port);
    }
    unlock(&cur_process.lock);
    del_ipc_port(port, IPC_PORT_LEADER);
    return 0;
}
#endif

int prepare_ipc_leader(void) {
    lock(&cur_process.lock);
    bool need_discover = (!cur_process.ns || qstrempty(&cur_process.ns->uri));
    unlock(&cur_process.lock);

    if (need_discover)
        __discover_ns(true, true);  // This function cannot be called with cur_process.lock held
    return 0;
}

int connect_owner(IDTYPE idx, struct shim_ipc_port** portptr, IDTYPE* owner) {
    struct shim_ipc_info* info = NULL;
    struct ipc_range range;
    memset(&range, 0, sizeof(struct ipc_range));

    int ret = get_ipc_range(idx, &range, &info);
    if (ret == -ESRCH) {
        if ((ret = ipc_query_send(idx)) < 0)
            return -ESRCH;

        ret = get_ipc_range(idx, &range, &info);
    }

    if (ret < 0)
        goto out;

    if (range.owner == cur_process.vmid) {
        ret = -ESRCH;
        assert(!range.port);
        goto out;
    }

    if (range.port)
        goto success;

    IDTYPE type = IPC_PORT_OWNER | IPC_PORT_LISTEN;

    if (!range.port) {
        PAL_HANDLE pal_handle = DkStreamOpen(qstrgetstr(&range.uri), 0, 0, 0, 0);

        if (!pal_handle) {
            ret = -PAL_ERRNO() ?: -EACCES;
            goto out;
        }

        add_ipc_port_by_id(range.owner, pal_handle, type, NULL, &range.port);
        assert(range.port);
    }

    lock(&range_map_lock);
    if (info->port)
        put_ipc_port(info->port);
    get_ipc_port(range.port);
    info->port = range.port;
    unlock(&range_map_lock);

success:
    if (portptr)
        *portptr = range.port;
    else
        put_ipc_port(range.port);

    if (owner)
        *owner = range.owner;
out:
    if (info)
        put_ipc_info(info);

    assert(ret || range.port);
    return ret;
}

int ipc_findns_send(bool block) {
    int ret = -ESRCH;

    lock(&cur_process.lock);
    if (!cur_process.parent || !cur_process.parent->port) {
        unlock(&cur_process.lock);
        goto out;
    }

    IDTYPE dest = cur_process.parent->vmid;
    struct shim_ipc_port* port = cur_process.parent->port;
    get_ipc_port(port);
    unlock(&cur_process.lock);

    if (block) {
        size_t total_msg_size = get_ipc_msg_with_ack_size(0);
        struct shim_ipc_msg_with_ack* msg = __alloca(total_msg_size);
        init_ipc_msg_with_ack(msg, IPC_MSG_FINDNS, total_msg_size, dest);

        debug("ipc send to %u: IPC_MSG_FINDNS\n", dest);

        ret = send_ipc_message_with_ack(msg, port, NULL, NULL);
        goto out_port;
    }

    size_t total_msg_size = get_ipc_msg_size(0);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_FINDNS, total_msg_size, dest);

    debug("ipc send to %u: IPC_MSG_FINDNS\n", dest);

    ret = send_ipc_message(msg, port);
out_port:
    put_ipc_port(port);
out:
    return ret;
}

int ipc_findns_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    debug("ipc callback from %u: IPC_MSG_FINDNS\n", msg->src);

    int ret = 0;
    __discover_ns(false, true);  // This function cannot be called with cur_process.lock held
    lock(&cur_process.lock);

    if (cur_process.ns && !qstrempty(&cur_process.ns->uri)) {
        // Got the answer! Send back the discovery now.
        ret = ipc_tellns_send(port, msg->src, cur_process.ns, msg->seq);
    } else {
        // Don't know the answer yet, set up a callback for sending the discovery later.
        struct ns_query* query = malloc(sizeof(struct ns_query));
        if (query) {
            query->dest = msg->src;
            query->seq  = msg->seq;
            get_ipc_port(port);
            query->port = port;
            INIT_LIST_HEAD(query, list);
            LISTP_ADD_TAIL(query, &ns_queries, list);
        } else {
            ret = -ENOMEM;
        }
    }
    unlock(&cur_process.lock);
    return ret;
}

int ipc_tellns_send(struct shim_ipc_port* port, IDTYPE dest, struct shim_ipc_info* leader,
                    unsigned long seq) {
    size_t total_msg_size    = get_ipc_msg_size(leader->uri.len + sizeof(struct shim_ipc_tellns));
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_TELLNS, total_msg_size, dest);

    struct shim_ipc_tellns* msgin = (void*)&msg->msg;
    msgin->vmid = leader->vmid;
    memcpy(msgin->uri, qstrgetstr(&leader->uri), leader->uri.len + 1);
    msg->seq = seq;

    debug("ipc send to %u: IPC_MSG_TELLNS(%u, %s)\n", dest, leader->vmid, msgin->uri);

    int ret = send_ipc_message(msg, port);
    return ret;
}

int ipc_tellns_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_tellns* msgin = (void*)&msg->msg;
    int ret = 0;

    debug("ipc callback from %u: IPC_MSG_TELLNS(%u, %s)\n", msg->src, msgin->vmid, msgin->uri);

    lock(&cur_process.lock);

    if (cur_process.ns) {
        cur_process.ns->vmid = msgin->vmid;
        qstrsetstr(&cur_process.ns->uri, msgin->uri, strlen(msgin->uri));
    } else {
        cur_process.ns = create_ipc_info(msgin->vmid, msgin->uri, strlen(msgin->uri));
        if (!cur_process.ns) {
            ret = -ENOMEM;
            goto out;
        }
    }

    assert(cur_process.ns->vmid != 0);
    assert(!qstrempty(&cur_process.ns->uri));

    struct ns_query* query;
    struct ns_query* pos;

    LISTP_FOR_EACH_ENTRY_SAFE(query, pos, &ns_queries, list) {
        LISTP_DEL(query, &ns_queries, list);
        ipc_tellns_send(query->port, query->dest, cur_process.ns, query->seq);
        put_ipc_port(query->port);
        free(query);
    }

    struct shim_ipc_msg_with_ack* obj = pop_ipc_msg_with_ack(port, msg->seq);
    if (obj && obj->thread)
        thread_wakeup(obj->thread);

out:
    unlock(&cur_process.lock);
    return ret;
}

int ipc_lease_send(LEASETYPE* lease) {
    IDTYPE leader;
    struct shim_ipc_port* port = NULL;
    struct shim_ipc_info* self = NULL;
    int ret = 0;

    if ((ret = connect_ns(&leader, &port)) < 0)
        goto out;

    if ((ret = get_ipc_info_cur_process(&self)) < 0)
        goto out;

    if (leader == cur_process.vmid) {
        ret = alloc_ipc_range(cur_process.vmid, qstrgetstr(&self->uri), NULL, NULL);
        put_ipc_info(self);
        goto out;
    }

    size_t len = self->uri.len;
    size_t total_msg_size = get_ipc_msg_with_ack_size(len + sizeof(struct shim_ipc_lease));
    struct shim_ipc_msg_with_ack* msg = __alloca(total_msg_size);
    init_ipc_msg_with_ack(msg, IPC_MSG_LEASE, total_msg_size, leader);

    struct shim_ipc_lease* msgin = (void*)&msg->msg.msg;
    assert(!qstrempty(&self->uri));
    memcpy(msgin->uri, qstrgetstr(&self->uri), len + 1);
    put_ipc_info(self);

    debug("ipc send to %u: IPC_MSG_LEASE(%s)\n", leader, msgin->uri);

    ret = send_ipc_message_with_ack(msg, port, NULL, lease);
out:
    if (port)
        put_ipc_port(port);
    return ret;
}

int ipc_lease_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_lease* msgin = (void*)&msg->msg;

    debug("ipc callback from %u: IPC_MSG_LEASE(%s)\n", msg->src, msgin->uri);

    IDTYPE base = 0;
    LEASETYPE lease = 0;

    int ret = alloc_ipc_range(msg->src, msgin->uri, &base, &lease);
    if (ret < 0)
        goto out;

    ret = ipc_offer_send(port, msg->src, base, RANGE_SIZE, lease, msg->seq);

out:
    return ret;
}

int ipc_offer_send(struct shim_ipc_port* port, IDTYPE dest, IDTYPE base, IDTYPE size,
                   LEASETYPE lease, unsigned long seq) {
    int ret = 0;
    size_t total_msg_size = get_ipc_msg_size(sizeof(struct shim_ipc_offer));
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_OFFER, total_msg_size, dest);

    struct shim_ipc_offer* msgin = (void*)&msg->msg;
    msgin->base  = base;
    msgin->size  = size;
    msgin->lease = lease;
    msg->seq = seq;

    debug("ipc send to %u: IPC_MSG_OFFER(%u, %u, %lu)\n", port->vmid, base, size, lease);
    ret = send_ipc_message(msg, port);
    return ret;
}

int ipc_offer_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_offer* msgin = (void*)&msg->msg;

    debug("ipc callback from %u: IPC_MSG_OFFER(%u, %u, %lu)\n", msg->src, msgin->base, msgin->size,
          msgin->lease);

    struct shim_ipc_msg_with_ack* obj = pop_ipc_msg_with_ack(port, msg->seq);

    switch (msgin->size) {
        case RANGE_SIZE:
            add_ipc_range(msgin->base, cur_process.vmid, qstrgetstr(&cur_process.self->uri),
                          msgin->lease);
            LEASETYPE* priv = obj ? obj->private : NULL;
            if (priv)
                *priv = msgin->lease;
            break;
        case 1:
            if (obj) {
                struct shim_ipc_sublease* s = (void*)&obj->msg.msg;
                add_ipc_subrange(s->idx, s->tenant, s->uri, &msgin->lease);

                LEASETYPE* priv = obj->private;
                if (priv)
                    *priv = msgin->lease;
            }
            break;
        default:
            goto out;
    }

    if (obj && obj->thread)
        thread_wakeup(obj->thread);

out:
    return 0;
}

/* TODO: unused */
int ipc_renew_send(IDTYPE base, IDTYPE size) {
    IDTYPE leader;
    struct shim_ipc_port* port = NULL;
    int ret = 0;

    if ((ret = connect_ns(&leader, &port)) < 0)
        goto out;

    size_t total_msg_size    = get_ipc_msg_size(sizeof(struct shim_ipc_renew));
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_RENEW, total_msg_size, leader);

    struct shim_ipc_renew* msgin = (void*)&msg->msg;
    msgin->base = base;
    msgin->size = size;

    debug("ipc send to : IPC_MSG_RENEW(%u, %u)\n", base, size);
    ret = send_ipc_message(msg, port);
    put_ipc_port(port);
out:
    return ret;
}

/* TODO: unused */
int ipc_renew_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_renew* msgin = (void*)&msg->msg;
    int ret = 0;

    debug("ipc callback from %u: IPC_MSG_RENEW(%u, %u)\n", msg->src, msgin->base, msgin->size);

    if (msgin->size != 1 && msgin->size != RANGE_SIZE) {
        ret = -EINVAL;
        goto out;
    }

    LEASETYPE lease = 0;

    switch (msgin->size) {
        case RANGE_SIZE:
            ret = renew_ipc_range(msgin->base, &lease);
            break;
        case 1:
            ret = renew_ipc_subrange(msgin->size, &lease);
            break;
        default:
            ret = -EINVAL;
            break;
    }

    if (ret < 0)
        goto out;

    ret = ipc_offer_send(port, msg->src, msgin->base, msgin->size, lease, msg->seq);

out:
    return ret;
}

int ipc_sublease_send(IDTYPE tenant, IDTYPE idx, const char* uri, LEASETYPE* lease) {
    IDTYPE leader;
    struct shim_ipc_port* port = NULL;
    int ret = 0;

    if ((ret = connect_ns(&leader, &port)) < 0)
        goto out;

    if (leader == cur_process.vmid) {
        ret = add_ipc_subrange(idx, tenant, uri, NULL);
        goto out;
    }

    size_t len = strlen(uri);
    size_t total_msg_size = get_ipc_msg_with_ack_size(len + sizeof(struct shim_ipc_sublease));
    struct shim_ipc_msg_with_ack* msg = __alloca(total_msg_size);
    init_ipc_msg_with_ack(msg, IPC_MSG_SUBLEASE, total_msg_size, leader);

    struct shim_ipc_sublease* msgin = (void*)&msg->msg.msg;
    msgin->tenant = tenant;
    msgin->idx    = idx;
    memcpy(msgin->uri, uri, len + 1);

    debug("ipc send to %u: IPC_MSG_SUBLEASE(%u, %u, %s)\n", leader, tenant, idx, msgin->uri);

    ret = send_ipc_message_with_ack(msg, port, NULL, lease);
out:
    if (port)
        put_ipc_port(port);
    return ret;
}

int ipc_sublease_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_sublease* msgin = (void*)&msg->msg;

    debug("ipc callback from %u: IPC_MSG_SUBLEASE(%u, %u, %s)\n", msg->src, msgin->idx,
          msgin->tenant, msgin->uri);

    LEASETYPE lease = 0;
    int ret = add_ipc_subrange(msgin->idx, msgin->tenant, msgin->uri, &lease);

    ret = ipc_offer_send(port, msg->src, msgin->idx, 1, lease, msg->seq);
    return ret;
}

int ipc_query_send(IDTYPE idx) {
    struct ipc_range range;
    IDTYPE leader;
    struct shim_ipc_port* port = NULL;
    int ret = 0;
    memset(&range, 0, sizeof(struct ipc_range));

    if (!get_ipc_range(idx, &range, NULL))
        goto out;

    if ((ret = connect_ns(&leader, &port)) < 0)
        goto out;

    if (cur_process.vmid == leader) {
        ret = -ESRCH;
        goto out;
    }

    size_t total_msg_size = get_ipc_msg_with_ack_size(sizeof(struct shim_ipc_query));
    struct shim_ipc_msg_with_ack* msg = __alloca(total_msg_size);
    init_ipc_msg_with_ack(msg, IPC_MSG_QUERY, total_msg_size, leader);

    struct shim_ipc_query* msgin = (void*)&msg->msg.msg;
    msgin->idx = idx;

    debug("ipc send to %u: IPC_MSG_QUERY(%u)\n", leader, idx);

    ret = send_ipc_message_with_ack(msg, port, NULL, NULL);
out:
    if (port)
        put_ipc_port(port);
    return ret;
}

int ipc_query_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_query* msgin = (void*)&msg->msg;

    debug("ipc callback from %u: IPC_MSG_QUERY(%u)\n", msg->src, msgin->idx);

    struct ipc_range range;
    int ret = 0;
    memset(&range, 0, sizeof(struct ipc_range));

    ret = get_ipc_range(msgin->idx, &range, NULL);
    if (ret < 0)
        goto out;

    assert(msgin->idx >= range.base && msgin->idx < range.base + range.size);
    assert(range.owner);
    assert(!qstrempty(&range.uri));

    struct ipc_ns_offered ans;
    ans.base         = range.base;
    ans.size         = range.size;
    ans.lease        = range.lease;
    ans.owner_offset = 0;
    size_t ownerdatasz = sizeof(struct ipc_ns_client) + range.uri.len;
    struct ipc_ns_client* owner = __alloca(ownerdatasz);
    owner->vmid = range.owner;
    assert(!qstrempty(&range.uri));
    memcpy(owner->uri, qstrgetstr(&range.uri), range.uri.len + 1);

    ret = ipc_answer_send(port, msg->src, 1, &ans, 1, &owner, &ownerdatasz, msg->seq);
out:
    return ret;
}

int ipc_queryall_send(void) {
    IDTYPE leader;
    struct shim_ipc_port* port = NULL;
    int ret = 0;

    if ((ret = connect_ns(&leader, &port)) < 0)
        goto out;

    if (cur_process.vmid == leader)
        goto out;

    size_t total_msg_size = get_ipc_msg_with_ack_size(0);
    struct shim_ipc_msg_with_ack* msg = __alloca(total_msg_size);
    init_ipc_msg_with_ack(msg, IPC_MSG_QUERYALL, total_msg_size, leader);

    debug("ipc send to %u: IPC_MSG_QUERYALL\n", leader);

    ret = send_ipc_message_with_ack(msg, port, NULL, NULL);
    put_ipc_port(port);
out:
    return ret;
}

int ipc_queryall_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    debug("ipc callback from %u: IPC_MSG_QUERYALL\n", msg->src);

    LISTP_TYPE(range)* list = &offered_ranges;
    struct range* r;
    int ret;

    lock(&range_map_lock);

    size_t maxanswers = nowned + noffered + nsubed;
    size_t answers_cnt = 0, owners_cnt = 0, i;
    struct ipc_ns_offered* answers = __alloca(sizeof(struct ipc_ns_offered) * maxanswers);
    struct ipc_ns_client** ownerdata = __alloca(sizeof(struct ipc_ns_client*) * maxanswers);
    size_t* ownerdatasz = __alloca(sizeof(size_t) * maxanswers);
    size_t owner_offset = 0;

retry:
    LISTP_FOR_EACH_ENTRY(r, list, list) {
        struct shim_ipc_info* p = r->owner;
        size_t datasz = sizeof(struct ipc_ns_client) + p->uri.len;
        struct ipc_ns_client* owner = __alloca(datasz);

        assert(!qstrempty(&p->uri));
        owner->vmid = p->vmid;
        memcpy(owner->uri, qstrgetstr(&p->uri), p->uri.len + 1);

        IDTYPE base = r->offset * RANGE_SIZE + 1;
        answers[answers_cnt].base         = base;
        answers[answers_cnt].size         = RANGE_SIZE;
        answers[answers_cnt].lease        = r->lease;
        answers[answers_cnt].owner_offset = owner_offset;
        answers_cnt++;

        ownerdata[owners_cnt]   = owner;
        ownerdatasz[owners_cnt] = datasz;
        owners_cnt++;

        owner_offset += datasz;

        if (!r->subranges)
            continue;

        for (i = 0; i < RANGE_SIZE; i++) {
            if (!r->subranges->map[i])
                continue;

            struct subrange* s = r->subranges->map[i];
            p = s->owner;
            datasz = sizeof(struct ipc_ns_client) + p->uri.len;
            owner = __alloca(datasz);

            assert(!qstrempty(&p->uri));
            owner->vmid = p->vmid;
            memcpy(owner->uri, qstrgetstr(&p->uri), p->uri.len + 1);

            answers[answers_cnt].base         = base + i;
            answers[answers_cnt].size         = 1;
            answers[answers_cnt].lease        = s->lease;
            answers[answers_cnt].owner_offset = owner_offset;
            answers_cnt++;

            ownerdata[owners_cnt]   = owner;
            ownerdatasz[owners_cnt] = datasz;
            owners_cnt++;

            owner_offset += datasz;
        }
    }

    if (list == &offered_ranges) {
        list = &owned_ranges;
        goto retry;
    }

    unlock(&range_map_lock);

    ret = ipc_answer_send(port, msg->src, answers_cnt, answers, owners_cnt, ownerdata, ownerdatasz,
                          msg->seq);

    return ret;
}

int ipc_answer_send(struct shim_ipc_port* port, IDTYPE dest, size_t answers_cnt,
                    struct ipc_ns_offered* answers, size_t owners_cnt,
                    struct ipc_ns_client** ownerdata, size_t* ownerdatasz, unsigned long seq) {
    size_t owner_offset = sizeof(struct shim_ipc_answer)
                          + sizeof(struct ipc_ns_offered) * answers_cnt;
    size_t total_ownerdatasz = 0;
    for (size_t i = 0; i < owners_cnt; i++) {
        total_ownerdatasz += ownerdatasz[i];
    }

    size_t total_msg_size = get_ipc_msg_size(owner_offset + total_ownerdatasz);
    struct shim_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_ANSWER, total_msg_size, dest);

    struct shim_ipc_answer* msgin = (void*)&msg->msg;
    msgin->answers_cnt = answers_cnt;
    for (size_t i = 0; i < answers_cnt; i++) {
        msgin->answers[i] = answers[i];
        msgin->answers[i].owner_offset += owner_offset;
    }
    for (size_t i = 0; i < owners_cnt; i++) {
        memcpy((void*)msgin + owner_offset, ownerdata[i], ownerdatasz[i]);
        owner_offset += ownerdatasz[i];
    }
    msg->seq = seq;

    if (answers_cnt == 1)
        debug("ipc send to %u: IPC_MSG_ANSWER([%u, %u])\n", dest, answers[0].base, answers[0].size);
    else if (answers_cnt)
        debug("ipc send to %u: IPC_MSG_ANSWER([%u, %u], ...)\n", dest, answers[0].base,
              answers[0].size);

    return send_ipc_message(msg, port);
}

int ipc_answer_callback(struct shim_ipc_msg* msg, struct shim_ipc_port* port) {
    struct shim_ipc_answer* msgin = (void*)&msg->msg;

    if (msgin->answers_cnt == 1)
        debug("ipc callback from %u: IPC_MSG_ANSWER([%u, %u])\n", msg->src, msgin->answers[0].base,
              msgin->answers[0].size);
    else if (msgin->answers_cnt)
        debug("ipc callback from %u: IPC_MSG_ANSWER([%u, %u], ...)\n", msg->src,
              msgin->answers[0].base, msgin->answers[0].size);

    for (size_t i = 0; i < msgin->answers_cnt; i++) {
        struct ipc_ns_offered* ans  = &msgin->answers[i];
        struct ipc_ns_client* owner = (void*)msgin + ans->owner_offset;

        switch (ans->size) {
            case RANGE_SIZE:
                add_ipc_range(ans->base, owner->vmid, owner->uri, ans->lease);
                break;
            case 1:
                add_ipc_subrange(ans->base, owner->vmid, owner->uri, &ans->lease);
                break;
            default:
                break;
        }
    }

    struct shim_ipc_msg_with_ack* obj = pop_ipc_msg_with_ack(port, msg->seq);
    if (obj && obj->thread)
        thread_wakeup(obj->thread);

    return 0;
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
        struct shim_ipc_info* p;
        IDTYPE off, idx;
        IDTYPE base;
        IDTYPE pids[RANGE_SIZE];
        struct pid_status* range_status;

#define UNDEF_IDX ((IDTYPE)-1)

    next_range:
        idx = UNDEF_IDX;
        off = r->offset;
        base = off * RANGE_SIZE + 1;

    next_sub:
        if (idx == UNDEF_IDX) {
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
            IDTYPE type = IPC_PORT_OWNER | IPC_PORT_LISTEN;
            IDTYPE owner = p->vmid;
            struct shim_ipc_port* port = NULL;
            size_t uri_len = p->uri.len;
            char uri[uri_len + 1];

            memcpy(&uri, qstrgetstr(&p->uri), uri_len);
            uri[uri_len] = 0;

            unlock(&range_map_lock);

            PAL_HANDLE pal_handle = DkStreamOpen(uri, 0, 0, 0, 0);

            if (pal_handle)
                add_ipc_port_by_id(owner, pal_handle, type, NULL, &port);

            lock(&range_map_lock);
            LISTP_FOR_EACH_ENTRY(r, list, list) {
                if (r->offset >= off)
                    break;
            }
            /* DEP 5/15/17: I believe this is checking if the list is empty */
            // if (&r->list == list)
            if (LISTP_EMPTY(list))
                break;
            if (r->offset > off)
                goto next_range;
            if (!port)
                continue;

            if (idx == UNDEF_IDX) {
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

        if (idx == UNDEF_IDX) {
            for (int i = 0; i < RANGE_SIZE; i++)
                pids[i] = base + i;
        } else {
            pids[0] = base + idx;
        }

        ret = ipc_pid_getstatus_send(p->port, p->vmid, idx == UNDEF_IDX ? RANGE_SIZE : 1, pids,
                                     &range_status);

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

int sysv_add_key(struct sysv_key* key, IDTYPE id) {
    assert(key);

    LISTP_TYPE(key)* head = &key_map[key->key & KEY_HASH_MASK];
    struct key* k;
    int ret = -EEXIST;

    lock(&range_map_lock);

    LISTP_FOR_EACH_ENTRY(k, head, hlist) {
        if (k->key.key == key->key && k->key.type == key->type)
            goto out;
    }

    k = malloc(sizeof(struct key));
    if (!k) {
        ret = -ENOMEM;
        goto out;
    }

    k->key.key  = key->key;
    k->key.type = key->type;
    k->id       = id;
    INIT_LIST_HEAD(k, hlist);
    LISTP_ADD(k, head, hlist);

    debug("add key/id pair (%lu, %u) to hash list: %p\n", key->key, id, head);
    ret = 0;
out:
    unlock(&range_map_lock);
    return ret;
}

int sysv_get_key(struct sysv_key* key, bool delete) {
    assert(key);

    LISTP_TYPE(key)* head = &key_map[key->key & KEY_HASH_MASK];
    struct key* k;
    int id = -ENOENT;

    lock(&range_map_lock);

    LISTP_FOR_EACH_ENTRY(k, head, hlist) {
        if (k->key.key == key->key && k->key.type == key->type) {
            id = k->id;
            if (delete) {
                LISTP_DEL(k, head, hlist);
                free(k);
            }
            break;
        }
    }

    unlock(&range_map_lock);
    return id;
}
