/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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
 * shim_ipc_nsimpl.h
 *
 * This file contains a template for generic functions and callbacks to
 * implement a namespace.
 */

#include <shim_internal.h>
#include <shim_ipc.h>
#include <shim_utils.h>
#include <shim_profile.h>

#include <errno.h>

#if !defined(NS) || !defined(NS_CAP)
# error "NS or NS_CAP is not defined"
#endif

#define NS_STR     XSTRINGIFY(NS)
#define NS_CAP_STR XSTRINGIFY(NS_CAP)

#define RANGE_SIZE CONCAT2(NS_CAP, RANGE_SIZE)

#define BITS    (sizeof(unsigned char) * 8)

struct idx_bitmap {
    unsigned char       map[RANGE_SIZE / BITS];
};

struct subrange {
    struct shim_ipc_info *  owner;
    LEASETYPE           lease;
};

struct sub_map {
    struct subrange *   map[RANGE_SIZE];
};

DEFINE_LIST(range);
struct range {
    LIST_TYPE(range)    hlist;
    LIST_TYPE(range)    list;
    int                 offset;
    struct shim_ipc_info *  owner;
    LEASETYPE           lease;
    struct idx_bitmap * used;
    struct sub_map *    subranges;
};

struct range_bitmap {
    int                 map_size;
    unsigned char       map[];
};

static struct range_bitmap * range_map;
static LOCKTYPE range_map_lock;

#define RANGE_HASH_LEN      6
#define RANGE_HASH_NUM      (1 << RANGE_HASH_LEN)
#define RANGE_HASH_MASK     (RANGE_HASH_NUM - 1)
#define RANGE_HASH(off)     (((off - 1) / RANGE_SIZE) & RANGE_HASH_MASK)

/* This hash table organizes range structs by hlist */
DEFINE_LISTP(range);
static LISTP_TYPE(range) range_table [RANGE_HASH_NUM];
/* These lists organizes range structs by list 
 */
static LISTP_TYPE(range) owned_ranges;
static LISTP_TYPE(range) offered_ranges;
static int nowned = 0;
static int noffered = 0;
static int nsubed = 0;

DEFINE_LIST(ns_query);
struct ns_query {
    IDTYPE                  dest;
    unsigned long           seq;
    struct shim_ipc_port *  port;
    LIST_TYPE(ns_query)     list;
};

DEFINE_LISTP(ns_query);
static LISTP_TYPE(ns_query) ns_queries;

static inline LEASETYPE get_lease (void)
{
    return DkSystemTimeQuery() + CONCAT2(NS_CAP, LEASE_TIME);
}

void CONCAT3(debug_print, NS, ranges) (void)
{
    lock(range_map_lock);
    sys_printf(NS_STR " ranges in process %010u:\n", cur_process.vmid);

    if (!range_map) {
        unlock(range_map_lock);
        return;
    }

    for (int i = 0 ; i < range_map->map_size ; i++) {
        unsigned char map = range_map->map[i];

        if (!map)
            continue;

        for (int j = 0 ; j < BITS ; map >>= 1, j++) {
            if (!(map & 1))
                continue;

            int off = i * BITS + j;
            LISTP_TYPE(range) * head = range_table + RANGE_HASH(off);
            struct range * tmp, * r = NULL;

            listp_for_each_entry(tmp, head, hlist)
                if (tmp->offset == off) {
                    r = tmp;
                    break;
                }

            assert(r);
            IDTYPE base = RANGE_SIZE * off + 1;
            struct shim_ipc_info * p = r->owner;

            sys_printf("%04u - %04u: owner %010u, port \"%s\" lease %u\n",
                       base, base + RANGE_SIZE - 1,
                       p->vmid, qstrgetstr(&p->uri), r->lease);

            if (!r->subranges)
                continue;

            for (int k = 0 ; k < RANGE_SIZE ; k++) {
                struct subrange * s = r->subranges->map[j];
                if (!s)
                    continue;

                p = s->owner;
                sys_printf("   %04u: owner %010u, port \"%s\" lease %u\n",
                           base + k, p->vmid,
                           qstrgetstr(&p->uri), s->lease);
            }
        }
    }

    unlock(range_map_lock);
}

#define INIT_RANGE_MAP_SIZE     32

static int __extend_range_bitmap (int expected)
{
    int size = INIT_RANGE_MAP_SIZE;

    if (range_map)
        size = range_map->map_size;

    while (size <= expected)
        size *= 2;

    struct range_bitmap * new_map = malloc(sizeof(struct range_bitmap) +
                                           size / BITS);
    if (!new_map)
        return -ENOMEM;

    if (range_map) {
        memcpy(new_map->map, range_map->map, range_map->map_size / BITS);
        memset(new_map->map + range_map->map_size / BITS, 0,
               (size - range_map->map_size) / BITS);
        free(range_map);
    } else {
        memset(new_map->map, 0, size / BITS);
    }

    new_map->map_size = size;
    range_map = new_map;
    return 0;
}

static int __set_range_bitmap (int off, bool unset)
{
    int i = off / BITS;
    int j = off - i * BITS;
    unsigned char * m = range_map->map + i;
    unsigned char f = 1U << j;
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

static bool __check_range_bitmap (int off)
{
    int i = off / BITS;
    int j = off - i * BITS;
    unsigned char * m = range_map->map + i;
    unsigned char f = 1U << j;
    return (*m) && ((*m) & f);
}

static struct range * __get_range (int off)
{
    LISTP_TYPE(range) * head = range_table + RANGE_HASH(off);

    if (!range_map || off >= range_map->map_size)
        return NULL;

    if (!__check_range_bitmap(off))
        return NULL;

    struct range * r;

    listp_for_each_entry(r, head, hlist)
        if (r->offset == off)
            return r;

    return NULL;
}

static int __add_range (struct range * r, int off, IDTYPE owner,
                        const char * uri, LEASETYPE lease)
{
    LISTP_TYPE(range) * head = range_table + RANGE_HASH(off);
    int ret = 0;

    if (!range_map || range_map->map_size <= off) {
        ret = __extend_range_bitmap(off);
        if (ret < 0)
            return ret;
    }

    r->owner = NULL;
    r->offset = off;
    r->lease = lease;
    r->used = NULL;
    r->subranges = NULL;

    if (owner) {
        r->owner = lookup_and_alloc_client(owner, uri);
        if (!r->owner)
            return -ENOMEM;
    }

    ret = __set_range_bitmap(off, false);
    if (ret == -EEXIST) {
        struct range * tmp;

        listp_for_each_entry(tmp, head, hlist)
            if (tmp->offset == off) {
                listp_del(tmp, head, hlist);

                /* Chia-Che Tsai 10/17/17: only when tmp->owner is non-NULL,
                 * and tmp->owner->vmid == cur_process.vmid, tmp is on the
                 * owned list, otherwise it is an offered. */
                if (tmp->owner && tmp->owner->vmid == cur_process.vmid)
                    listp_del(tmp, &owned_ranges, list);
                else
                    listp_del(tmp, &offered_ranges, list);

                if (tmp->owner)
                    put_client(tmp->owner);

                r->used = tmp->used;
                r->subranges = tmp->subranges;
                free(tmp);
                break;
            }
    }

    INIT_LIST_HEAD(r, hlist);
    listp_add(r, head, hlist);
    INIT_LIST_HEAD(r, list);

    LISTP_TYPE(range)* list = (owner == cur_process.vmid) ? &owned_ranges
                              : &offered_ranges;
    struct range * prev = listp_first_entry(list, range, list);
    struct range * tmp;


    listp_for_each_entry(tmp, list, list) {
        if (tmp->offset >= off)
            break;
        prev = tmp;
    }

    listp_add_after(r, prev, list, list);

    if (owner == cur_process.vmid)
        nowned++;
    else
        noffered++;

    return 0;
}

int CONCAT3(add, NS, range) (IDTYPE base, IDTYPE owner,
                             const char * uri, LEASETYPE lease)
{
    int off = (base - 1) / RANGE_SIZE;
    int ret;

    struct range * r = malloc(sizeof(struct range));
    if (!r)
        return -ENOMEM;

    lock(range_map_lock);
    r->owner = NULL;
    ret = __add_range(r, off, owner, uri, lease);
    if (ret < 0)
        free(r);
    unlock(range_map_lock);
    return ret;
}

static void CONCAT3(__del, NS, subrange) (struct subrange ** ptr)
{
    struct subrange * s = *ptr;
    *ptr = NULL;
    put_ipc_info(s->owner);
    free(s);
    nsubed--;
}

int CONCAT3(add, NS, subrange) (IDTYPE idx, IDTYPE owner,
                                const char * uri, LEASETYPE * lease)
{
    int off = (idx - 1) / RANGE_SIZE, err = 0;
    IDTYPE base = off * RANGE_SIZE + 1;
    struct subrange * s = malloc(sizeof(struct subrange));
    if (!s)
        return -ENOMEM;

    assert(owner);
    lock(range_map_lock);

    s->owner = lookup_and_alloc_client(owner, uri);
    if (!s->owner) {
        err = -ENOMEM;
        goto failed;
    }

    s->lease = (lease && (*lease)) ? (*lease) : get_lease();

    struct range * r = __get_range(off);
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

    struct subrange ** m = &r->subranges->map[idx - base];

    if (*m)
        CONCAT3(__del, NS, subrange)(m);

    (*m) = s;
    nsubed++;

    if (lease)
        *lease = s->lease;

    unlock(range_map_lock);
    return 0;

failed:
    if (s->owner)
        put_ipc_info(s->owner);

    unlock(range_map_lock);
    free(s);
    return err;
}

int CONCAT3(alloc, NS, range) (IDTYPE owner, const char * uri,
                               IDTYPE * base, LEASETYPE * lease)
{
    struct range * r = malloc(sizeof(struct range));
    if (!r)
        return -ENOMEM;

    int ret = 0;
    lock(range_map_lock);
    r->owner = NULL;
    int i = 0, j = 0;

    if (range_map)
        for (i = 0 ; i < range_map->map_size ; i++) {
            unsigned char map = range_map->map[i];

            if (map < 255U) {
                for (j = 0 ; j < BITS ; map >>= 1, j++)
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
    unlock(range_map_lock);
    return ret;
}

int CONCAT3(get, NS, range) (IDTYPE idx,
                             struct CONCAT2(NS, range) * range,
                             struct shim_ipc_info ** info)
{
    int off = (idx - 1) / RANGE_SIZE;

    lock(range_map_lock);

    struct range * r = __get_range(off);
    if (!r) {
        unlock(range_map_lock);
        return -ESRCH;
    }

    IDTYPE base = r->offset * RANGE_SIZE + 1;
    IDTYPE sz   = RANGE_SIZE;
    LEASETYPE l = r->lease;
    struct shim_ipc_info * p = r->owner;

    if (r->subranges && r->subranges->map[idx - base]) {
        struct subrange * s = r->subranges->map[idx - base];
        base = idx;
        sz = 1;
        l = s->lease;
        p = s->owner;
    }

    if (!p) {
        unlock(range_map_lock);
        return -ESRCH;
    }

    if (p->port)
        get_ipc_port(p->port);

    range->base  = base;
    range->size  = sz;
    range->lease = l;
    range->owner = p->vmid;
    qstrcopy(&range->uri, &p->uri);
    range->port  = p->port;

    if (info) {
        get_ipc_info(p);
        *info = p;
    }

    unlock(range_map_lock);
    return 0;
}

int CONCAT3(del, NS, range) (IDTYPE idx)
{
    int off = (idx - 1) / RANGE_SIZE;
    int ret = -ESRCH;

    lock(range_map_lock);

    struct range * r = __get_range(off);
    if (!r)
        goto failed;

    ret = __set_range_bitmap(off, true);
    if (ret < 0)
        goto failed;

    if (r->subranges) {
        for (int i = 0 ; i < RANGE_SIZE ; i++)
            if (r->subranges->map[i]) {
                ret = -EBUSY;
                goto failed;
            }

        free(r->subranges);
    }

    if (r->owner->vmid == cur_process.vmid)
        nowned--;
    else
        noffered--;

    if (r->used)
        free(r->used);
    // Re-acquire the head; kind of ugly
    LISTP_TYPE(range) * head = range_table + RANGE_HASH(off);
    listp_del(r, head, hlist);

    /* Chia-Che Tsai 10/17/17: only when r->owner is non-NULL,
     * and r->owner->vmid == cur_process.vmid, r is on the
     * owned list, otherwise it is an offered. */
    if (r->owner && r->owner->vmid == cur_process.vmid)
        listp_del(r, &owned_ranges, list);
    else
        listp_del(r, &offered_ranges, list);

    put_ipc_info(r->owner);
    free(r);

    ret = 0;
failed:
    unlock(range_map_lock);
    return ret;
}

int CONCAT3(del, NS, subrange) (IDTYPE idx)
{
    int off = (idx - 1) / RANGE_SIZE;
    IDTYPE base = off * RANGE_SIZE + 1;
    int ret = -ESRCH;

    lock(range_map_lock);

    struct range * r = __get_range(off);
    if (!r)
        goto failed;

    if (!r->subranges || !r->subranges->map[idx - base])
        goto failed;

    CONCAT3(__del, NS, subrange) (&r->subranges->map[idx - base]);
    ret = 0;
failed:
    unlock(range_map_lock);
    return ret;
}

int CONCAT3(renew, NS, range) (IDTYPE idx, LEASETYPE * lease)
{
    int off = (idx - 1) / RANGE_SIZE;

    lock(range_map_lock);

    struct range * r = __get_range(off);
    if (!r) {
        unlock(range_map_lock);
        return -ESRCH;
    }

    r->lease = get_lease();
    if (lease)
        *lease = r->lease;
    unlock(range_map_lock);
    return 0;
}

int CONCAT3(renew, NS, subrange) (IDTYPE idx, LEASETYPE * lease)
{
    int off = (idx - 1) / RANGE_SIZE;
    IDTYPE base = off * RANGE_SIZE + 1;

    lock(range_map_lock);

    struct range * r = __get_range(off);
    if (!r) {
        unlock(range_map_lock);
        return -ESRCH;
    }

    if (!r->subranges || !r->subranges->map[idx - base]) {
        unlock(range_map_lock);
        return -ESRCH;
    }

    struct subrange * s = r->subranges->map[idx - base];
    s->lease = get_lease();
    if (lease)
        *lease = s->lease;
    unlock(range_map_lock);
    return 0;
}

IDTYPE CONCAT2(allocate, NS) (IDTYPE min, IDTYPE max)
{
    IDTYPE idx = min;
    struct range * r;
    lock(range_map_lock);

    listp_for_each_entry (r, &owned_ranges, list) {
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

        int i = (idx - base) / BITS;
        int j = (idx - base) - i * BITS;
        unsigned char * m = r->used->map + i;
        unsigned char f = 1U << j;

        for ( ; i < RANGE_SIZE / BITS ; i++, j = 0, f = 1U, m++) {
            unsigned char map = (*m) ^ (f - 1);

            if (map < 255U) {
                for ( ; j < BITS ; f <<= 1, j++)
                    if (!(map & f)) {
                        (*m) |= f;
                        idx = base + i * BITS + j;
                        debug("allocated " NS_STR ": %u\n", idx);
                        goto out;
                    }
            }
        }
    }
    idx = 0;

out:
    unlock(range_map_lock);
    return idx;
}

void CONCAT2(release, NS) (IDTYPE idx)
{
    int off = (idx - 1) / RANGE_SIZE;
    IDTYPE base = off * RANGE_SIZE + 1;

    lock(range_map_lock);

    struct range * r = __get_range(off);
    if (!r)
        goto out;

    if (r->subranges && r->subranges->map[idx - base])
         CONCAT3(__del, NS, subrange) (&r->subranges->map[idx - base]);

    if (!r->used)
        goto out;

    if (idx < base || idx >= base + RANGE_SIZE)
        goto out;

    int i = (idx - base) / BITS;
    int j = (idx - base) - i * BITS;
    unsigned char * m = r->used->map + i;
    unsigned char f = 1U << j;
    if ((*m) & f) {
        debug("released " NS_STR ": %u\n", idx);
        (*m) &= ~f;
    }

out:
    unlock(range_map_lock);
}


static inline void init_namespace (void)
{
    create_lock(range_map_lock);
}

#define _NS_ID(ns)     __NS_ID(ns)
#define __NS_ID(ns)    ns##_NS
#define NS_ID          _NS_ID(NS_CAP)
#define NS_LEADER      cur_process.ns[NS_ID]
#define NS_SEND(t)     CONCAT3(ipc, NS, t##_send)
#define NS_CALLBACK(t) CONCAT3(ipc, NS, t##_callback)
#define NS_CODE(t)     CONCAT3(IPC, NS_CAP, t)
#define NS_CODE_STR(t) "IPC_" NS_CAP_STR "_" #t
#define NS_MSG_TYPE(t) struct CONCAT3(shim_ipc, NS, t)
#define PORT(ns, t)    __PORT(ns, t)
#define __PORT(ns, t)  IPC_PORT_##ns##t
#define IPC_PORT_CLT   PORT(NS_CAP, CLT)
#define IPC_PORT_LDR   PORT(NS_CAP, LDR)
#define IPC_PORT_CON   PORT(NS_CAP, CON)
#define IPC_PORT_OWN   PORT(NS_CAP, OWN)

static void ipc_leader_exit (struct shim_ipc_port * port, IDTYPE vmid,
                             unsigned int exitcode)
{
    lock(cur_process.lock);

    if (!NS_LEADER || NS_LEADER->port != port) {
        unlock(cur_process.lock);
        return;
    }

    struct shim_ipc_info * info = NS_LEADER;
    NS_LEADER = NULL;
    unlock(cur_process.lock);

    debug("ipc port %p of process %u closed suggests " NS_STR " leader exits\n",
          port, vmid);

    put_ipc_info(info);
}

/*
 * __discover_ns(): Discover the leader of this namespace.
 * @block: Whether to block for discovery.
 * @need_locate: Need the location information of the leader.
 */
static void __discover_ns (bool block, bool need_locate)
{
    bool ipc_pending = false;
    lock(cur_process.lock);

    if (NS_LEADER) {
        if (NS_LEADER->vmid == cur_process.vmid) {
            if (need_locate && qstrempty(&NS_LEADER->uri)) {
                struct shim_ipc_info * info = create_ipc_port(cur_process.vmid,
                                                              true);
                if (info) {
                    put_ipc_info(NS_LEADER);
                    NS_LEADER = info;
                    add_ipc_port(info->port, 0, IPC_PORT_CLT,
                                 &ipc_leader_exit);
                }
            }
            goto out;
        }

        if (!qstrempty(&NS_LEADER->uri))
            goto out;
    }

    /*
     * Now we need to discover the leader through IPC. Because IPC calls can be blocking,
     * we need to temporarily release cur_process.lock to prevent deadlocks. If the discovery
     * succeeds, NS_LEADER will contain the IPC information of the namespace leader.
     */

    unlock(cur_process.lock);

    // Send out an IPC message to find out the namespace information.
    // If the call is non-blocking, can't expect the answer when the function finishes.
    if (!NS_SEND(findns)(block)) {
        ipc_pending = !block; // There is still some unfinished business with IPC
        lock(cur_process.lock);
        assert(NS_LEADER);
        goto out;
    }

    lock(cur_process.lock);

    if (NS_LEADER && (!need_locate || !qstrempty(&NS_LEADER->uri)))
        goto out;

    // If all other ways failed, the current process becomes the leader
    if (!need_locate) {
        NS_LEADER = get_new_ipc_info(cur_process.vmid, NULL, 0);
        goto out;
    }

    if (NS_LEADER)
        put_ipc_info(NS_LEADER);

    if (!(NS_LEADER = create_ipc_port(cur_process.vmid, true)))
        goto out;

    // Finally, set the IPC port as a leadership port
    add_ipc_port(NS_LEADER->port, 0, IPC_PORT_CLT, &ipc_leader_exit);

out:
    if (NS_LEADER && !ipc_pending) {
        // Assertions for checking the correctness of __discover_ns()
        assert(NS_LEADER->vmid == cur_process.vmid  // The current process is the leader;
               || NS_LEADER->port                   // Or there is a connected port
               || !qstrempty(&NS_LEADER->uri));     // Or there is a known URI
        if (need_locate)
            assert(!qstrempty(&NS_LEADER->uri));        // A known URI is needed
    }

    unlock(cur_process.lock);
}

static int connect_ns (IDTYPE * vmid, struct shim_ipc_port ** portptr)
{
    __discover_ns(true, false); // Should not hold cur_process.lock
    lock(cur_process.lock);

    if (!NS_LEADER) {
        unlock(cur_process.lock);
        return -ESRCH;
    }

    if (NS_LEADER->vmid == cur_process.vmid) {
        if (vmid)
            *vmid = NS_LEADER->vmid;
        unlock(cur_process.lock);
        return 0;
    }

    if (!NS_LEADER->port) {
        if (qstrempty(&NS_LEADER->uri)) {
            unlock(cur_process.lock);
            return -ESRCH;
        }

        PAL_HANDLE pal_handle = DkStreamOpen(qstrgetstr(&NS_LEADER->uri),
                                             0, 0, 0, 0);

        if (!pal_handle) {
            unlock(cur_process.lock);
            return -PAL_ERRNO;
        }

        add_ipc_port_by_id(NS_LEADER->vmid, pal_handle,
                           IPC_PORT_LDR|IPC_PORT_LISTEN, &ipc_leader_exit,
                           &NS_LEADER->port);
    }

    if (vmid)
        *vmid = NS_LEADER->vmid;
    if (portptr) {
        if (NS_LEADER->port)
            get_ipc_port(NS_LEADER->port);
        *portptr = NS_LEADER->port;
    }

    unlock(cur_process.lock);
    return 0;
}

// Turn off this function as it is not used
// Keep the code for future use
#if 0
static int disconnect_ns(struct shim_ipc_port * port)
{
    lock(cur_process.lock);
    if (NS_LEADER && NS_LEADER->port == port) {
        NS_LEADER->port = NULL;
        put_ipc_port(port);
    }
    unlock(cur_process.lock);
    del_ipc_port(port, IPC_PORT_LDR);
    return 0;
}
#endif

int CONCAT3(prepare, NS, leader) (void)
{
    lock(cur_process.lock);
    bool need_discover = (!NS_LEADER || qstrempty(&NS_LEADER->uri));
    unlock(cur_process.lock);

    if (need_discover)
        __discover_ns(true, true); // Should not hold cur_process.lock
    return 0;
}

static int connect_owner (IDTYPE idx, struct shim_ipc_port ** portptr,
                          IDTYPE * owner)
{
    struct shim_ipc_info * info = NULL;
    struct CONCAT2(NS, range) range;
    memset(&range, 0, sizeof(struct CONCAT2(NS, range)));

    int ret = CONCAT3(get, NS, range) (idx, &range, &info);
    if (ret == -ESRCH) {
        if ((ret = NS_SEND(query)(idx)) < 0)
            return -ESRCH;

        ret = CONCAT3(get, NS, range) (idx, &range, &info);
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

    int type = IPC_PORT_OWN|IPC_PORT_LISTEN;

    if (!range.port) {
        PAL_HANDLE pal_handle = DkStreamOpen(qstrgetstr(&range.uri),
                                             0, 0, 0, 0);

        if (!pal_handle) {
            ret = -PAL_ERRNO ? : -EACCES;
            goto out;
        }

        add_ipc_port_by_id(range.owner, pal_handle, type, NULL, &range.port);
        assert(range.port);
    }

    lock(range_map_lock);
    if (info->port)
        put_ipc_port(info->port);
    get_ipc_port(range.port);
    info->port = range.port;
    unlock(range_map_lock);

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

DEFINE_PROFILE_INTERVAL(NS_SEND(findns), ipc);
DEFINE_PROFILE_INTERVAL(NS_CALLBACK(findns), ipc);

int NS_SEND(findns) (bool block)
{
    BEGIN_PROFILE_INTERVAL();
    int ret = -ESRCH;
    lock(cur_process.lock);
    if (!cur_process.parent || !cur_process.parent->port) {
        unlock(cur_process.lock);
        goto out;
    }

    IDTYPE dest = cur_process.parent->vmid;
    struct shim_ipc_port * port = cur_process.parent->port;
    get_ipc_port(port);
    unlock(cur_process.lock);

    if (block) {
        struct shim_ipc_msg_obj * msg =
            create_ipc_msg_duplex_on_stack(NS_CODE(FINDNS), 0, dest);

        debug("ipc send to %u: " NS_CODE_STR(FINDNS) "\n", dest);

        ret = do_ipc_duplex(msg, port, NULL, NULL);
        goto out_port;
    }

    struct shim_ipc_msg * msg =
            create_ipc_msg_on_stack(NS_CODE(FINDNS), 0, dest);

    debug("ipc send to %u: " NS_CODE_STR(FINDNS) "\n", dest);

    ret = send_ipc_message(msg, port);
out_port:
    put_ipc_port(port);
out:
    SAVE_PROFILE_INTERVAL(NS_SEND(findns));
    return ret;
}

int NS_CALLBACK(findns) (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();

    debug("ipc callback from %u: " NS_CODE_STR(FINDNS) "\n",
          msg->src);

    int ret = 0;
    __discover_ns(false, true); // Non-blocking discovery; should not hold cur_process.lock
    lock(cur_process.lock);

    if (NS_LEADER && !qstrempty(&NS_LEADER->uri)) {
        // Got the answer! Send back the discovery now.
        ret = NS_SEND(tellns)(port, msg->src, NS_LEADER, msg->seq);
    } else {
        // Don't know the answer yet, set up a callback for sending the discovery later.
        struct ns_query * query = malloc(sizeof(struct ns_query));
        if (query) {
            query->dest = msg->src;
            query->seq  = msg->seq;
            get_ipc_port(port);
            query->port = port;
            INIT_LIST_HEAD(query, list);
            listp_add_tail(query, &ns_queries, list);
        } else {
            ret = -ENOMEM;
        }
    }
    unlock(cur_process.lock);
    SAVE_PROFILE_INTERVAL(NS_CALLBACK(findns));
    return ret;
}

DEFINE_PROFILE_INTERVAL(NS_SEND(tellns), ipc);
DEFINE_PROFILE_INTERVAL(NS_CALLBACK(tellns), ipc);

int NS_SEND(tellns) (struct shim_ipc_port * port, IDTYPE dest,
                     struct shim_ipc_info * leader, unsigned long seq)
{
    BEGIN_PROFILE_INTERVAL();
    struct shim_ipc_msg * msg =
        create_ipc_msg_on_stack(NS_CODE(TELLNS),
                                leader->uri.len + sizeof(NS_MSG_TYPE(tellns)),
                                dest);
    NS_MSG_TYPE(tellns) * msgin = (void *) &msg->msg;
    msgin->vmid = leader->vmid;
    memcpy(msgin->uri, qstrgetstr(&leader->uri), leader->uri.len + 1);
    msg->seq = seq;

    debug("ipc send to %u: " NS_CODE_STR(TELLNS) "(%u, %s)\n", dest,
          leader->vmid, msgin->uri);

    int ret = send_ipc_message(msg, port);
    SAVE_PROFILE_INTERVAL(NS_SEND(tellns));
    return ret;
}

int NS_CALLBACK(tellns) (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    NS_MSG_TYPE(tellns) * msgin = (void *) &msg->msg;
    int ret = 0;

    debug("ipc callback from %u: " NS_CODE_STR(TELLNS) "(%u, %s)\n",
          msg->src, msgin->vmid, msgin->uri);

    lock(cur_process.lock);

    if (NS_LEADER) {
        NS_LEADER->vmid = msgin->vmid;
        qstrsetstr(&NS_LEADER->uri, msgin->uri, strlen(msgin->uri));
    } else {
        NS_LEADER = get_new_ipc_info(msgin->vmid, msgin->uri,
                                      strlen(msgin->uri));
        if (!NS_LEADER) {
            ret = -ENOMEM;
            goto out;
        }
    }

    assert(NS_LEADER->vmid != 0);
    assert(!qstrempty(&NS_LEADER->uri));

    struct ns_query * query, * pos;

    listp_for_each_entry_safe(query, pos, &ns_queries, list) {
        listp_del(query, &ns_queries, list);
        NS_SEND(tellns)(query->port, query->dest, NS_LEADER, query->seq);
        put_ipc_port(query->port);
        free(query);
    }

    struct shim_ipc_msg_obj * obj = find_ipc_msg_duplex(port, msg->seq);
    if (obj && obj->thread)
        thread_wakeup(obj->thread);

out:
    unlock(cur_process.lock);
    SAVE_PROFILE_INTERVAL(NS_CALLBACK(tellns));
    return ret;
}

DEFINE_PROFILE_INTERVAL(NS_SEND(lease), ipc);
DEFINE_PROFILE_INTERVAL(NS_CALLBACK(lease), ipc);

int NS_SEND(lease) (LEASETYPE * lease)
{
    BEGIN_PROFILE_INTERVAL();
    IDTYPE leader;
    struct shim_ipc_port * port = NULL;
    struct shim_ipc_info * self = NULL;
    int ret = 0;

    if ((ret = connect_ns(&leader, &port)) < 0)
        goto out;

    if ((ret = create_ipc_location(&self)) < 0)
        goto out;

    if (leader == cur_process.vmid) {
        ret = CONCAT3(alloc, NS, range)(cur_process.vmid,
                                        qstrgetstr(&self->uri),
                                        NULL, NULL);
        put_ipc_info(self);
        goto out;
    }

    int len = self->uri.len;
    struct shim_ipc_msg_obj * msg = create_ipc_msg_duplex_on_stack(
                                        NS_CODE(LEASE),
                                        len + sizeof(NS_MSG_TYPE(lease)),
                                        leader);
    NS_MSG_TYPE(lease) * msgin = (void *) &msg->msg.msg;
    assert(!qstrempty(&self->uri));
    memcpy(msgin->uri, qstrgetstr(&self->uri), len + 1);
    put_ipc_info(self);

    debug("ipc send to %u: " NS_CODE_STR(LEASE) "(%s)\n", leader,
          msgin->uri);

    ret = do_ipc_duplex(msg, port, NULL, lease);
out:
    if (port)
        put_ipc_port(port);
    SAVE_PROFILE_INTERVAL(NS_SEND(lease));
    return ret;
}

int NS_CALLBACK(lease) (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    NS_MSG_TYPE(lease) * msgin = (void *) &msg->msg;

    debug("ipc callback from %u: " NS_CODE_STR(LEASE) "(%s)\n",
          msg->src, msgin->uri);

    IDTYPE base = 0;
    LEASETYPE lease = 0;

    int ret = CONCAT3(alloc, NS, range)(msg->src, msgin->uri, &base, &lease);
    if (ret < 0)
        goto out;

    ret = NS_SEND(offer)(port, msg->src, base, RANGE_SIZE, lease, msg->seq);

out:
    SAVE_PROFILE_INTERVAL(NS_CALLBACK(lease));
    return ret;
}

DEFINE_PROFILE_INTERVAL(NS_SEND(offer), ipc);
DEFINE_PROFILE_INTERVAL(NS_CALLBACK(offer), ipc);

int NS_SEND(offer) (struct shim_ipc_port * port, IDTYPE dest, IDTYPE base,
                    IDTYPE size, LEASETYPE lease, unsigned long seq)
{
    BEGIN_PROFILE_INTERVAL();
    int ret = 0;
    struct shim_ipc_msg * msg = create_ipc_msg_on_stack(NS_CODE(OFFER),
                                        sizeof(NS_MSG_TYPE(offer)), dest);
    NS_MSG_TYPE(offer) * msgin = (void *) &msg->msg;
    msgin->base  = base;
    msgin->size  = size;
    msgin->lease = lease;
    msg->seq     = seq;

    debug("ipc send to %u: " NS_CODE_STR(OFFER) "(%u, %u, %lu)\n",
          port->info.vmid, base, size, lease);
    ret = send_ipc_message(msg, port);
    SAVE_PROFILE_INTERVAL(NS_SEND(offer));
    return ret;
}

int NS_CALLBACK(offer) (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    NS_MSG_TYPE(offer) * msgin = (void *) &msg->msg;

    debug("ipc callback from %u: " NS_CODE_STR(OFFER) "(%u, %u, %lu)\n",
          msg->src, msgin->base, msgin->size, msgin->lease);

    struct shim_ipc_msg_obj * obj = find_ipc_msg_duplex(port, msg->seq);

    switch (msgin->size) {
        case RANGE_SIZE:
            CONCAT3(add, NS, range)(msgin->base, cur_process.vmid,
                                    qstrgetstr(&cur_process.self->uri),
                                    msgin->lease);
            LEASETYPE * priv = obj ? obj->private : NULL;
            if (priv)
                *priv = msgin->lease;
            break;
        case 1:
            if (obj) {
                NS_MSG_TYPE(sublease) * s = (void *) &obj->msg.msg;
                CONCAT3(add, NS, subrange)(s->idx, s->tenant, s->uri,
                                           &msgin->lease);

                LEASETYPE * priv = obj->private;
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
    SAVE_PROFILE_INTERVAL(NS_CALLBACK(offer));
    return 0;
}

DEFINE_PROFILE_INTERVAL(NS_SEND(renew), ipc);
DEFINE_PROFILE_INTERVAL(NS_CALLBACK(renew), ipc);

int NS_SEND(renew) (IDTYPE base, IDTYPE size)
{
    BEGIN_PROFILE_INTERVAL();
    IDTYPE leader;
    struct shim_ipc_port * port = NULL;
    int ret = 0;

    if ((ret = connect_ns(&leader, &port)) < 0)
        goto out;

    struct shim_ipc_msg * msg =
            create_ipc_msg_on_stack(NS_CODE(RENEW),
                                    sizeof(NS_MSG_TYPE(renew)), leader);
    NS_MSG_TYPE(renew) * msgin = (void *) &msg->msg;
    msgin->base = base;
    msgin->size = size;

    debug("ipc send to %u: " NS_CODE_STR(RENEW) "(%u, %u)\n", base, size);
    ret = send_ipc_message(msg, port);
    put_ipc_port(port);
out:
    SAVE_PROFILE_INTERVAL(NS_SEND(renew));
    return ret;
}

int NS_CALLBACK(renew) (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    NS_MSG_TYPE(renew) * msgin = (void *) &msg->msg;
    int ret = 0;

    debug("ipc callback from %u: " NS_CODE_STR(RENEW) "(%u, %u)\n",
          msg->src, msgin->base, msgin->size);

    if (msgin->size != 1 && msgin->size != RANGE_SIZE) {
        ret = -EINVAL;
        goto out;
    }

    LEASETYPE lease = 0;

    switch (msgin->size) {
        case RANGE_SIZE:
            ret = CONCAT3(renew, NS, range) (msgin->base, &lease);
            break;
        case 1:
            ret = CONCAT3(renew, NS, subrange) (msgin->size, &lease);
            break;
        default:
            ret = -EINVAL;
            break;
    }

    if (ret < 0)
        goto out;

    ret = NS_SEND(offer)(port, msg->src, msgin->base, msgin->size, lease,
                         msg->seq);

out:
    SAVE_PROFILE_INTERVAL(NS_CALLBACK(renew));
    return ret;
}

DEFINE_PROFILE_INTERVAL(NS_SEND(revoke), ipc);
DEFINE_PROFILE_INTERVAL(NS_CALLBACK(revoke), ipc);

int NS_SEND(revoke) (IDTYPE base, IDTYPE size)
{
    BEGIN_PROFILE_INTERVAL();
    IDTYPE leader;
    struct shim_ipc_port * port = NULL;
    int ret = 0;

    if ((ret = connect_ns(&leader, &port)) < 0)
        goto out;

    struct shim_ipc_msg * msg =
            create_ipc_msg_on_stack(NS_CODE(REVOKE),
                                    sizeof(NS_MSG_TYPE(revoke)), leader);
    NS_MSG_TYPE(revoke) * msgin = (void *) &msg->msg;
    msgin->base = base;
    msgin->size = size;

    debug("ipc send to %u: " NS_CODE_STR(REVOKE) "(%u, %u)\n",
          leader, base, size);

    ret = send_ipc_message(msg, port);
    put_ipc_port(port);
out:
    SAVE_PROFILE_INTERVAL(NS_SEND(revoke));
    return ret;
}

int NS_CALLBACK(revoke) (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    NS_MSG_TYPE(revoke) * msgin = (void *) &msg->msg;
    int ret = 0;

    debug("ipc callback from %u: " NS_CODE_STR(REVOKE) "(%u, %u)\n",
           msg->src, msgin->base, msgin->size);

    switch (msgin->size) {
        case RANGE_SIZE:
            ret = CONCAT3(del, NS, range)(msgin->base);
            break;
        case 1:
            ret = CONCAT3(del, NS, subrange)(msgin->size);
            break;
        default:
            ret = -EINVAL;
            break;
    }

    SAVE_PROFILE_INTERVAL(NS_CALLBACK(revoke));
    return ret;
}

DEFINE_PROFILE_INTERVAL(NS_SEND(sublease), ipc);
DEFINE_PROFILE_INTERVAL(NS_CALLBACK(sublease), ipc);

int NS_SEND(sublease) (IDTYPE tenant, IDTYPE idx, const char * uri,
                       LEASETYPE * lease)
{
    BEGIN_PROFILE_INTERVAL();
    IDTYPE leader;
    struct shim_ipc_port * port = NULL;
    int ret = 0;

    if ((ret = connect_ns(&leader, &port)) < 0)
        goto out;

    if (leader == cur_process.vmid) {
        ret = CONCAT3(add, NS, subrange)(idx, tenant, uri, NULL);
        goto out;
    }

    int len = strlen(uri);
    struct shim_ipc_msg_obj * msg = create_ipc_msg_duplex_on_stack(
                                            NS_CODE(SUBLEASE),
                                            len + sizeof(NS_MSG_TYPE(sublease)),
                                            leader);
    NS_MSG_TYPE(sublease) * msgin = (void *) &msg->msg.msg;
    msgin->tenant = tenant;
    msgin->idx = idx;
    memcpy(msgin->uri, uri, len + 1);

    debug("ipc send to %u: " NS_CODE_STR(SUBLEASE) "(%u, %u, %s)\n",
          leader, tenant, idx, msgin->uri);

    ret = do_ipc_duplex(msg, port, NULL, lease);
out:
    if (port)
        put_ipc_port(port);
    SAVE_PROFILE_INTERVAL(NS_SEND(sublease));
    return ret;
}

int NS_CALLBACK(sublease) (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    NS_MSG_TYPE(sublease) * msgin = (void *) &msg->msg;

    debug("ipc callback from %u: " NS_CODE_STR(SUBLEASE) "(%u, %u, %s)\n",
          msg->src, msgin->idx, msgin->tenant, msgin->uri);

    LEASETYPE lease = 0;
    int ret = CONCAT3(add, NS, subrange)(msgin->idx, msgin->tenant, msgin->uri,
                                         &lease);

    ret = NS_SEND(offer)(port, msg->src, msgin->idx, 1, lease, msg->seq);
    SAVE_PROFILE_INTERVAL(NS_CALLBACK(sublease));
    return ret;
}

DEFINE_PROFILE_INTERVAL(NS_SEND(query), ipc);
DEFINE_PROFILE_INTERVAL(NS_CALLBACK(query), ipc);

int NS_SEND(query) (IDTYPE idx)
{
    BEGIN_PROFILE_INTERVAL();
    struct CONCAT2(NS, range) range;
    IDTYPE leader;
    struct shim_ipc_port * port = NULL;
    int ret = 0;
    memset(&range, 0, sizeof(struct CONCAT2(NS, range)));

    if (!CONCAT3(get, NS, range)(idx, &range, NULL))
        goto out;

    if ((ret = connect_ns(&leader, &port)) < 0)
        goto out;

    if (cur_process.vmid == leader) {
        ret = -ESRCH;
        goto out;
    }

    struct shim_ipc_msg_obj * msg = create_ipc_msg_duplex_on_stack(
                                            NS_CODE(QUERY),
                                            sizeof(NS_MSG_TYPE(query)),
                                            leader);

    NS_MSG_TYPE(query) * msgin = (void *) &msg->msg.msg;
    msgin->idx = idx;

    debug("ipc send to %u: " NS_CODE_STR(QUERY) "(%u)\n", leader, idx);

    ret = do_ipc_duplex(msg, port, NULL, NULL);
out:
    if (port)
        put_ipc_port(port);
    SAVE_PROFILE_INTERVAL(NS_SEND(query));
    return ret;
}

int NS_CALLBACK(query) (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    NS_MSG_TYPE(query) * msgin = (void *) &msg->msg;

    debug("ipc callback from %u: " NS_CODE_STR(QUERY) "(%u)\n",
          msg->src, msgin->idx);

    struct CONCAT2(NS, range) range;
    int ret = 0;
    memset(&range, 0, sizeof(struct CONCAT2(NS, range)));

    ret = CONCAT3(get, NS, range)(msgin->idx, &range, NULL);
    if (ret < 0)
        goto out;

    assert(msgin->idx >= range.base && msgin->idx < range.base + range.size);
    assert(range.owner);
    assert(!qstrempty(&range.uri));

    struct ipc_ns_offered ans;
    ans.base = range.base;
    ans.size = range.size;
    ans.lease = range.lease;
    ans.owner_offset = 0;
    int ownerdatasz = sizeof(struct ipc_ns_client) + range.uri.len;
    struct ipc_ns_client * owner = __alloca(ownerdatasz);
    owner->vmid = range.owner;
    assert(!qstrempty(&range.uri));
    memcpy(owner->uri, qstrgetstr(&range.uri), range.uri.len + 1);

    ret = NS_SEND(answer)(port, msg->src, 1, &ans, 1, &owner, &ownerdatasz,
                          msg->seq);
out:
    SAVE_PROFILE_INTERVAL(NS_CALLBACK(query));
    return ret;
}

DEFINE_PROFILE_INTERVAL(NS_SEND(queryall), ipc);
DEFINE_PROFILE_INTERVAL(NS_CALLBACK(queryall), ipc);

int NS_SEND(queryall) (void)
{
    BEGIN_PROFILE_INTERVAL();
    IDTYPE leader;
    struct shim_ipc_port * port = NULL;
    int ret = 0;

    if ((ret = connect_ns(&leader, &port)) < 0)
        goto out;

    if (cur_process.vmid == leader)
        goto out;

    struct shim_ipc_msg_obj * msg = create_ipc_msg_duplex_on_stack(
                                            NS_CODE(QUERYALL), 0, leader);

    debug("ipc send to %u: " NS_CODE_STR(QUERYALL) "\n", leader);

    ret = do_ipc_duplex(msg, port, NULL, NULL);
    put_ipc_port(port);
out:
    SAVE_PROFILE_INTERVAL(NS_SEND(queryall));
    return ret;
}

int NS_CALLBACK(queryall) (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();

    debug("ipc callback from %u: " NS_CODE_STR(QUERYALL) "\n", msg->src);

    LISTP_TYPE(range) * list = &offered_ranges;
    struct range * r;
    int ret;

    lock(range_map_lock);

    int maxanswers = nowned + noffered + nsubed;
    int nanswers = 0, nowners = 0, i;
    struct ipc_ns_offered * answers =
            __alloca(sizeof(struct ipc_ns_offered) * maxanswers);
    struct ipc_ns_client ** ownerdata =
            __alloca(sizeof(struct ipc_ns_client *) * maxanswers);
    int * ownerdatasz = __alloca(sizeof(int) * maxanswers);
    int owner_offset = 0;

retry:
    listp_for_each_entry (r, list, list) {
        struct shim_ipc_info * p = r->owner;
        int datasz = sizeof(struct ipc_ns_client) + p->uri.len;
        struct ipc_ns_client * owner = __alloca(datasz);

        assert(!qstrempty(&p->uri));
        owner->vmid = p->vmid;
        memcpy(owner->uri, qstrgetstr(&p->uri), p->uri.len + 1);

        IDTYPE base = r->offset * RANGE_SIZE + 1;
        answers[nanswers].base = base;
        answers[nanswers].size = RANGE_SIZE;
        answers[nanswers].lease = r->lease;
        answers[nanswers].owner_offset = owner_offset;
        nanswers++;

        ownerdata[nowners] = owner;
        ownerdatasz[nowners] = datasz;
        nowners++;

        owner_offset += datasz;

        if (!r->subranges)
            continue;

        for (i = 0 ; i < RANGE_SIZE ; i++) {
            if (!r->subranges->map[i])
                continue;

            struct subrange * s = r->subranges->map[i];
            p = s->owner;
            datasz = sizeof(struct ipc_ns_client) + p->uri.len;
            owner = __alloca(datasz);

            assert(!qstrempty(&p->uri));
            owner->vmid = p->vmid;
            memcpy(owner->uri, qstrgetstr(&p->uri), p->uri.len + 1);

            answers[nanswers].base = base + i;
            answers[nanswers].size = 1;
            answers[nanswers].lease = s->lease;
            answers[nanswers].owner_offset = owner_offset;
            nanswers++;

            ownerdata[nowners] = owner;
            ownerdatasz[nowners] = datasz;
            nowners++;

            owner_offset += datasz;
        }
    }

    if (list == &offered_ranges) {
        list = &owned_ranges;
        goto retry;
    }

    unlock(range_map_lock);

    ret = NS_SEND(answer)(port, msg->src, nanswers, answers, nowners,
                          ownerdata, ownerdatasz, msg->seq);

    SAVE_PROFILE_INTERVAL(NS_CALLBACK(queryall));
    return ret;
}

DEFINE_PROFILE_INTERVAL(NS_SEND(answer), ipc);
DEFINE_PROFILE_INTERVAL(NS_CALLBACK(answer), ipc);

int NS_SEND(answer) (struct shim_ipc_port * port, IDTYPE dest,
                     int nanswers, struct ipc_ns_offered * answers,
                     int nowners, struct ipc_ns_client ** ownerdata,
                     int * ownerdatasz, unsigned long seq)
{
    BEGIN_PROFILE_INTERVAL();

    int owner_offset = sizeof(NS_MSG_TYPE(answer)) +
                       sizeof(struct ipc_ns_offered) * nanswers;
    int total_ownerdatasz = 0;
    for (int i = 0 ; i < nowners ; i++)
        total_ownerdatasz += ownerdatasz[i];

    struct shim_ipc_msg * msg =
            create_ipc_msg_on_stack(NS_CODE(ANSWER),
                                    owner_offset + total_ownerdatasz, dest);

    NS_MSG_TYPE(answer) * msgin = (void *) &msg->msg;
    msgin->nanswers = nanswers;
    for (int i = 0 ; i < nanswers ; i++) {
        msgin->answers[i] = answers[i];
        msgin->answers[i].owner_offset += owner_offset;
    }
    for (int i = 0 ; i < nowners ; i++) {
        memcpy((void *) msgin + owner_offset, ownerdata[i], ownerdatasz[i]);
        owner_offset += ownerdatasz[i];
    }
    msg->seq = seq;

    if (nanswers == 1)
        debug("ipc send to %u: " NS_CODE_STR(ANSWER) "([%u, %u])\n", dest,
              answers[0].base, answers[0].size);
    else if (nanswers)
        debug("ipc send to %u: " NS_CODE_STR(ANSWER) "([%u, %u], ...)\n", dest,
              answers[0].base, answers[0].size);

    int ret = send_ipc_message(msg, port);

    SAVE_PROFILE_INTERVAL(NS_SEND(answer));
    return ret;
}

int NS_CALLBACK(answer) (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    NS_MSG_TYPE(answer) * msgin = (void *) &msg->msg;

    if (msgin->nanswers == 1)
        debug("ipc callback from %u: " NS_CODE_STR(ANSWER) "([%u, %u])\n",
              msg->src, msgin->answers[0].base, msgin->answers[0].size);
    else if (msgin->nanswers)
        debug("ipc callback from %u: " NS_CODE_STR(ANSWER) "([%u, %u], ...)\n",
              msg->src, msgin->answers[0].base, msgin->answers[0].size);

    for (int i = 0 ; i < msgin->nanswers ; i++) {
        struct ipc_ns_offered * ans = &msgin->answers[i];
        struct ipc_ns_client * owner = (void *) msgin + ans->owner_offset;

        switch (ans->size) {
            case RANGE_SIZE:
                CONCAT3(add, NS, range)(ans->base, owner->vmid, owner->uri,
                                        ans->lease);
                break;
            case 1:
                CONCAT3(add, NS, subrange)(ans->base, owner->vmid, owner->uri,
                                           &ans->lease);
                break;
            default:
                break;
        }
    }

    struct shim_ipc_msg_obj * obj = find_ipc_msg_duplex(port, msg->seq);
    if (obj && obj->thread)
        thread_wakeup(obj->thread);

    SAVE_PROFILE_INTERVAL(NS_CALLBACK(answer));
    return 0;
}

#ifdef NS_KEY

#define KEY_HASH_LEN    8
#define KEY_HASH_NUM    (1 << KEY_HASH_LEN)
#define KEY_HASH_MASK   (KEY_HASH_NUM - 1)

DEFINE_LIST(key);
struct key {
    NS_KEY                key;
    IDTYPE                id;
    LIST_TYPE(key)        hlist;
};
DEFINE_LISTP(key);
static LISTP_TYPE(key) key_map [KEY_HASH_NUM];


int CONCAT2(NS, add_key) (NS_KEY * key, IDTYPE id)
{
    LISTP_TYPE(key) * head = &key_map[KEY_HASH(key) & KEY_HASH_MASK];
    struct key * k;
    int ret = -EEXIST;

    lock(range_map_lock);

    listp_for_each_entry(k, head, hlist)
        if (!KEY_COMP(&k->key, key))
            goto out;

    k = malloc(sizeof(struct key));
    if (!k) {
        ret = -ENOMEM;
        goto out;
    }

    KEY_COPY(&k->key, key);
    k->id  = id;
    INIT_LIST_HEAD(k, hlist);
    listp_add(k, head, hlist);

    debug("add key/id pair (%u, %u) to hash list: %p\n",
          KEY_HASH(key), id, head);
    ret = 0;
out:
    unlock(range_map_lock);
    return ret;
}

int CONCAT2(NS, get_key) (NS_KEY * key, bool delete)
{
    LISTP_TYPE(key) * head = &key_map[KEY_HASH(key) & KEY_HASH_MASK];
    struct key * k;
    int id = -ENOENT;

    lock(range_map_lock);

    listp_for_each_entry(k, head, hlist)
        if (!KEY_COMP(&k->key, key)) {
            id = k->id;
            if (delete) {
                listp_del(k, head, hlist);
                free(k);
            }
            break;
        }

    unlock(range_map_lock);
    return id;
}

DEFINE_PROFILE_INTERVAL(NS_SEND(findkey), ipc);
DEFINE_PROFILE_INTERVAL(NS_CALLBACK(findkey), ipc);

int NS_SEND(findkey) (NS_KEY * key)
{
    BEGIN_PROFILE_INTERVAL();
    int ret = 0;

    ret = CONCAT2(NS, get_key) (key, false);
    if (!ret)
        goto out;

    IDTYPE dest;
    struct shim_ipc_port * port = NULL;

    if ((ret = connect_ns(&dest, &port)) < 0)
        goto out;

    if (dest == cur_process.vmid) {
        ret = -ENOENT;
        goto out;
    }

    struct shim_ipc_msg_obj * msg = create_ipc_msg_duplex_on_stack(
                                        NS_CODE(FINDKEY),
                                        sizeof(NS_MSG_TYPE(findkey)),
                                        dest);
    NS_MSG_TYPE(findkey) * msgin = (void *) &msg->msg.msg;
    KEY_COPY(&msgin->key, key);

    debug("ipc send to %u: " NS_CODE_STR(FINDKEY) "(%u)\n",
          dest, KEY_HASH(key));

    ret = do_ipc_duplex(msg, port, NULL, NULL);
    put_ipc_port(port);

    if (!ret)
        ret = CONCAT2(NS, get_key) (key, false);
out:
    SAVE_PROFILE_INTERVAL(NS_SEND(findkey));
    return ret;
}

int NS_CALLBACK(findkey) (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    int ret = 0;
    NS_MSG_TYPE(findkey) * msgin  = (void *) &msg->msg;

    debug("ipc callback from %u: " NS_CODE_STR(FINDKEY) "(%u)\n",
          msg->src, KEY_HASH(&msgin->key));

    ret = CONCAT2(NS, get_key)(&msgin->key, false);
    if (ret < 0)
        goto out;

    ret = NS_SEND(tellkey)(port, msg->src, &msgin->key, ret, msg->seq);
out:
    SAVE_PROFILE_INTERVAL(NS_CALLBACK(findkey));
    return ret;
}

DEFINE_PROFILE_INTERVAL(NS_SEND(tellkey), ipc);
DEFINE_PROFILE_INTERVAL(NS_CALLBACK(tellkey), ipc);

int NS_SEND(tellkey) (struct shim_ipc_port * port, IDTYPE dest, NS_KEY * key,
                      IDTYPE id, unsigned long seq)
{
    BEGIN_PROFILE_INTERVAL();
    bool owned = true;
    int ret = 0;

    if (!dest) {
        if ((ret = CONCAT2(NS, add_key)(key, id)) < 0)
            goto out;

        if ((ret = connect_ns(&dest, &port)) < 0)
            goto out;

        if (dest == cur_process.vmid)
            goto out;

        owned = false;
    }

    if (owned) {
        struct shim_ipc_msg * msg = create_ipc_msg_on_stack(
                                        NS_CODE(TELLKEY),
                                        sizeof(NS_MSG_TYPE(tellkey)),
                                        dest);
        NS_MSG_TYPE(tellkey) * msgin = (void *) &msg->msg;
        KEY_COPY(&msgin->key, key);
        msgin->id = id;
        msg->seq  = seq;

        debug("ipc send to %u: IPC_SYSV_TELLKEY(%u, %u)\n", dest,
              KEY_HASH(key), id);

        ret = send_ipc_message(msg, port);
        goto out;
    }

    struct shim_ipc_msg_obj * msg = create_ipc_msg_duplex_on_stack(
                                        NS_CODE(TELLKEY),
                                        sizeof(NS_MSG_TYPE(tellkey)),
                                        dest);
    NS_MSG_TYPE(tellkey) * msgin = (void *) &msg->msg.msg;
    KEY_COPY(&msgin->key, key);
    msgin->id = id;

    debug("ipc send to %u: IPC_SYSV_TELLKEY(%u, %u)\n", dest,
          KEY_HASH(key), id);

    ret = do_ipc_duplex(msg, port, NULL, NULL);
    put_ipc_port(port);
out:
    SAVE_PROFILE_INTERVAL(NS_SEND(tellkey));
    return ret;
}

int NS_CALLBACK(tellkey) (IPC_CALLBACK_ARGS)
{
    BEGIN_PROFILE_INTERVAL();
    int ret = 0;
    NS_MSG_TYPE(tellkey) * msgin = (void *) &msg->msg;

    debug("ipc callback from %u: " NS_CODE_STR(TELLKEY) "(%u, %u)\n",
          msg->src, KEY_HASH(&msgin->key), msgin->id);

    ret = CONCAT2(NS, add_key)(&msgin->key, msgin->id);

    struct shim_ipc_msg_obj * obj = find_ipc_msg_duplex(port, msg->seq);
    if (!obj) {
        ret = RESPONSE_CALLBACK;
        goto out;
    }

    if (obj->thread)
        thread_wakeup(obj->thread);

out:
    SAVE_PROFILE_INTERVAL(ipc_sysv_tellkey_callback);
    return ret;
}

#endif /* NS_KEY */
