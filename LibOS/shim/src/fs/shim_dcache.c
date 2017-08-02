/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_dcache.c
 *
 * This file contains codes for maintaining directory cache in library OS.
 * The source codes are imported from Linux kernel, but simplified according
 * to the characteristic of library OS.
 */

#include <shim_types.h>
#include <shim_internal.h>
#include <shim_handle.h>
#include <shim_fs.h>
#include <shim_checkpoint.h>

#include <list.h>

/* As best I can tell, dentries are added to this list and then never touched
 * again */
/* Links to shim_dentry->list */
static LISTP_TYPE(shim_dentry) unused = LISTP_INIT;

/* Attaches to shim_dentry->hlist */
static LISTP_TYPE(shim_dentry) dcache_htable[DCACHE_HASH_SIZE] = { LISTP_INIT };

LOCKTYPE dcache_lock;

struct shim_dcache_stats {
    long memsize;
    long nentries;
};

static struct shim_dcache_stats dcache_stats;

long get_dcache_stats (const char * name)
{
    if (strcmp_static(name, "memsize"))
        return dcache_stats.memsize;

    if (strcmp_static(name, "nentries"))
        return dcache_stats.nentries;

    return 0;
}

#define DCACHE_MGR_ALLOC    64
#define PAGE_SIZE           allocsize

#define OBJ_TYPE struct shim_dentry
#include <memmgr.h>

static MEM_MGR dentry_mgr = NULL;

struct shim_dentry * dentry_root = NULL;

//#define DEBUG_DCACHE
//#define DEBUG_REF

static struct shim_dentry * alloc_dentry (void)
{
    struct shim_dentry * dent =
                get_mem_obj_from_mgr_enlarge(dentry_mgr,
                                             size_align_up(DCACHE_MGR_ALLOC));
    if (!dent)
        return NULL;

    dcache_stats.memsize += sizeof(struct shim_dentry);
    dcache_stats.nentries++;

    memset(dent, 0, sizeof(struct shim_dentry));

    dent->mode = NO_MODE;

    INIT_LIST_HEAD(dent, hlist);
    INIT_LIST_HEAD(dent, list);
    INIT_LISTP(&dent->children);
    INIT_LIST_HEAD(dent, siblings);

    return dent;
}

DEFINE_PROFILE_CATAGORY(dcache, );
DEFINE_PROFILE_INTERVAL(total_init_dcache, dcache);
DEFINE_PROFILE_CATAGORY(within_init_dcache, dcache);
DEFINE_PROFILE_INTERVAL(dcache_init_memory, within_init_dcache);
DEFINE_PROFILE_INTERVAL(dcache_init_lock, within_init_dcache);
DEFINE_PROFILE_INTERVAL(dcache_init_root_entry, within_init_dcache);

int init_dcache (void)
{
#ifdef PROFILE
    unsigned long begin_time = GET_PROFILE_INTERVAL();
    BEGIN_PROFILE_INTERVAL_SET(begin_time);
#endif

    dentry_mgr = create_mem_mgr(init_align_up(DCACHE_MGR_ALLOC));
    SAVE_PROFILE_INTERVAL(dcache_init_memory);

    create_lock(dcache_lock);
    SAVE_PROFILE_INTERVAL(dcache_init_lock);

    dentry_root = alloc_dentry();

    qstrsetstr(&dentry_root->rel_path, "", 0);
    qstrsetstr(&dentry_root->name,     "", 0);

    get_dentry(dentry_root);
    SAVE_PROFILE_INTERVAL(dcache_init_root_entry);

    SAVE_PROFILE_INTERVAL_SINCE(total_init_dcache, begin_time);
    return 0;
}

int reinit_dcache (void)
{
    create_lock(dcache_lock);

    return 0;
}

/* remove from the hash table, so that a lookup will fail. */
static void __del_dcache (struct shim_dentry * dent)
{
    if (!(dent->state & DENTRY_HASHED))
        return;

    /* DEP 5/15/17: I believe that, if a dentry is in the DENTRY_HASHED state,
     * that the hash field is always valid. */
    LISTP_TYPE(shim_dentry) * head = &dcache_htable[DCACHE_HASH(dent->rel_path.hash)];
    dent->state &= ~DENTRY_HASHED;
    listp_del_init(dent, head, hlist);

#ifdef DEBUG_DCACHE
    debug("del dcache %p(%s/%s) (mount = %p)\n",
          dent, dent->fs ? qstrgetstr(&dent->fs->path) : "",
          qstrgetstr(&dent->rel_path), dent->fs);
#endif
}

static int __internal_put_dentry (struct shim_dentry * dent);

/* Release a dentry whose ref count has gone to zero. */
static inline void __dput_dentry (struct shim_dentry * dent)
{
    while (1) {
        /* if the dentry is never in the hash table, we are happy to
           drop it */
        if (!(dent->state & DENTRY_HASHED))
            goto kill;

        /* move the node to unused list unless it is persistent */
        if (!(dent->state & DENTRY_PERSIST)) {
            dent->state |= DENTRY_RECENTLY;
            /* DEP: The only reference I see to this field is being placed on 
             * the unused list. It seems that sometimes the dent is not
             * on a list; just hack this for now; this code will be reworked
             * soon anyway.
             */
            if (!list_empty(dent, list))
                listp_del_init(dent, &unused, list);
            listp_add(dent, &unused, list);
        }

        /* we don't delete the dentry from dcache because it might
           be acquired and used again, unless it gets recycled due
           to memory pressure */
        break;

kill:   {
            if (dent->fs && dent->fs->d_ops && dent->fs->d_ops->dput)
                dent->fs->d_ops->dput(dent);

            struct shim_dentry * parent = dent->parent;

            if (!parent)
                break;

            listp_del_init(dent, &parent->children, siblings); /* remove from parent's list of children */
            dent->parent = NULL;
            dent = parent;

            if (__internal_put_dentry(dent))
                break;
        }
    }
}

static int __internal_put_dentry (struct shim_dentry * dent)
{
    int count = REF_DEC(dent->ref_count);

#ifdef DEBUG_REF
    debug("put dentry %p(%s/%s) (ref_count = %d)\n", dent,
          dent->fs ?
          qstrgetstr(&dent->fs->path) : "",
          qstrgetstr(&dent->rel_path), count);
#endif

    return count;
}

void get_dentry (struct shim_dentry * dent)
{
#ifdef DEBUG_REF
    int count = REF_INC(dent->ref_count);

    debug("get dentry %p(%s/%s) (ref_count = %d)\n", dent,
          dent->fs ?
          qstrgetstr(&dent->fs->path) : "",
          qstrgetstr(&dent->rel_path), count);
#else
    REF_INC(dent->ref_count);
#endif
}

void put_dentry (struct shim_dentry * dent)
{
    if (__internal_put_dentry(dent))
        return;

    if (locked(dcache_lock)) {
        __dput_dentry(dent);
    } else {
        lock(dcache_lock);
        __dput_dentry(dent);
        unlock(dcache_lock);
    }
}

struct shim_dentry * get_new_dentry (struct shim_dentry * parent,
                                     const char * name, int namelen)
{
    struct shim_dentry * dent = alloc_dentry();

    if (!dent)
        return NULL;

    REF_SET(dent->ref_count, 0);
    qstrsetstr(&dent->name, name, namelen);

    if (!parent) {
        qstrsetstr(&dent->rel_path, name, namelen);
        return dent;
    }

    if (!qstrempty(&parent->rel_path)) {
        const char * strs[] = { qstrgetstr(&parent->rel_path), "/", name };
        size_t lens[] = { parent->rel_path.len, 1, namelen };
        qstrsetstrs(&dent->rel_path, 3, strs, lens);
    } else
        qstrsetstr(&dent->rel_path, name, namelen);

    return dent;
}

void __set_parent_dentry (struct shim_dentry * child,
                          struct shim_dentry * parent)
{
    if (child->parent == parent)
        return;

    assert(!child->parent);
    get_dentry(parent);
    listp_add_tail(child, &parent->children, siblings);
    child->parent = parent;
    parent->nchildren++;
}

void __unset_parent_dentry (struct shim_dentry * child,
                            struct shim_dentry * parent)
{
    if (child->parent != parent)
        return;

    assert(child->parent);
    listp_del_init(child, &parent->children, siblings);
    child->parent = NULL;

    parent->nchildren--;
    put_dentry(parent);
}

static inline
HASHTYPE hash_dentry (struct shim_dentry * start, const char * path, int len)
{
    return rehash_path(start ? start->rel_path.hash : 0,
                       path, len, NULL);
}

void __add_dcache (struct shim_dentry * dent, HASHTYPE * hashptr)
{
    LISTP_TYPE(shim_dentry) * head;

    if (hashptr) {
        dent->rel_path.hash = *hashptr;
        goto add_hash;
    }

    if (!dent->parent) {
        dent->rel_path.hash = dent->fs ? dent->fs->path.hash : 0;
        goto add_hash;
    }

    dent->rel_path.hash = hash_dentry(dent->parent, dentry_get_name(dent),
                                      dent->name.len);

add_hash:
    head = &dcache_htable[DCACHE_HASH(dent->rel_path.hash)];
    listp_add(dent, head, hlist);
    dent->state |= DENTRY_HASHED;

#ifdef DEBUG_DCACHE
    debug("add dcache %p(%s/%s) (mount = %p)\n",
          dent, dent->fs ? qstrgetstr(&dent->fs->path) : "",
          qstrgetstr(&dent->rel_path), dent->fs);
#endif
}

void add_dcache (struct shim_dentry * dent, HASHTYPE * hashptr)
{
    lock(dcache_lock);
    __add_dcache(dent, hashptr);
    unlock(dcache_lock);
}

struct shim_dentry *
__lookup_dcache (struct shim_dentry * start, const char * name, int namelen,
                 const char * path, int pathlen, HASHTYPE * hashptr)
{
    HASHTYPE hash = hash_dentry(start, name, namelen);
    struct shim_dentry * dent, * found = NULL;
    LISTP_TYPE(shim_dentry) * head = &dcache_htable[DCACHE_HASH(hash)];

    /* walk through all the nodes in the hash bucket, find the droids we're
       looking for */
    listp_for_each_entry(dent, head, hlist) {
        if ((dent->state & DENTRY_MOUNTPOINT) ||
            dent->rel_path.hash != hash)
            continue;

        /* first we compare the filename */
        const char * filename = get_file_name(name, namelen);
        if (memcmp(dentry_get_name(dent), filename, name + namelen - filename))
            continue;

        if (filename == name) {
            struct shim_dentry * d = dent;
            while (d && !d->parent && d->fs)
                d = d->fs->mount_point;
            if (d && d->parent && d->parent != start)
                continue;
        }

        if (path && pathlen && filename != path) {
            const char * fullpath;
            int fullpathlen;
            fullpath = dentry_get_path(dent, true, &fullpathlen);
            if (pathlen > fullpathlen)
                continue;
            fullpath += fullpathlen - pathlen;
            if (fullpath[-1] != '/')
                continue;
            if (memcmp(fullpath, path, pathlen))
                continue;
        }

        get_dentry(dent);
        found = dent;
        break;
    }

    if (hashptr)
        *hashptr = hash;

    return found;
}

/* after lookup_dcache, the dentry is popped to prevent recycling */
struct shim_dentry *
lookup_dcache (struct shim_dentry * start, const char * name, int namelen,
               const char * path, int pathlen, HASHTYPE * hashptr)
{
    lock(dcache_lock);
    struct shim_dentry * dent = __lookup_dcache(start, name, namelen, path,
                                                pathlen, hashptr);
    unlock(dcache_lock);
    return dent;
}

int __del_dentry_tree (struct shim_dentry * root)
{
    struct shim_dentry * this_parent = root;
    struct shim_dentry * next;

repeat:
    next = this_parent->children.first;

resume:
    while (next != this_parent->children.first) {
        struct shim_dentry *d, * tmp;
        d = tmp = next;
        next = tmp->siblings.next;
        if (d->state & DENTRY_MOUNTPOINT) {
            this_parent = d->mounted->root;
            goto repeat;
        }

        if (!listp_empty(&d->children)) {
            this_parent = d;
            goto repeat;
        }

        __unset_parent_dentry(d, this_parent);
        __del_dcache(d);
    }

    if (this_parent != root) {
        struct shim_dentry * child = this_parent;
        if (!this_parent->parent) {
            this_parent = this_parent->fs->mount_point;
            __del_dcache(child);
            child = this_parent;
        }
        this_parent = this_parent->parent;
        next = child->siblings.next;
        __del_dcache(child);
        __unset_parent_dentry(child, this_parent);
        goto resume;
    }

    return 0;
}

BEGIN_CP_FUNC(dentry)
{
    assert(size == sizeof(struct shim_dentry));

    struct shim_dentry * dent = (struct shim_dentry *) obj;
    struct shim_dentry * new_dent = NULL;

    ptr_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_dentry));
        ADD_TO_CP_MAP(obj, off);
        new_dent = (struct shim_dentry *) (base + off);

        lock(dent->lock);
        *new_dent = *dent;
        INIT_LIST_HEAD(new_dent, hlist);
        INIT_LIST_HEAD(new_dent, list);
        INIT_LISTP(&new_dent->children);
        INIT_LIST_HEAD(new_dent, siblings);
        new_dent->data = NULL;
        clear_lock(new_dent->lock);
        REF_SET(new_dent->ref_count, 0);

        DO_CP_IN_MEMBER(qstr, new_dent, rel_path);
        DO_CP_IN_MEMBER(qstr, new_dent, name);

        if (dent->fs)
            DO_CP_MEMBER(mount, dent, new_dent, fs);

        if (dent->parent)
            DO_CP_MEMBER(dentry, dent, new_dent, parent);

        if (dent->mounted)
            DO_CP_MEMBER(mount, dent, new_dent, mounted);

        unlock(dent->lock);
        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_dent = (struct shim_dentry *) (base + off);
    }

    if (objp)
        *objp = (void *) new_dent;
}
END_CP_FUNC(dentry)

BEGIN_RS_FUNC(dentry)
{
    struct shim_dentry * dent = (void *) (base + GET_CP_FUNC_ENTRY());
    BEGIN_PROFILE_INTERVAL();

    CP_REBASE(dent->hlist);
    CP_REBASE(dent->list);
    CP_REBASE(dent->children);
    CP_REBASE(dent->siblings);
    CP_REBASE(dent->fs);
    CP_REBASE(dent->parent);
    CP_REBASE(dent->mounted);

    create_lock(dent->lock);

    if (dent->parent)
        __set_parent_dentry(dent, dent->parent);

    LISTP_TYPE(shim_dentry) * head = &dcache_htable[DCACHE_HASH(dent->rel_path.hash)];
    listp_add(dent, head, hlist);
    dent->state |= DENTRY_HASHED;

    DEBUG_RS("hash=%08x,path=%s,fs=%s", dent->rel_path.hash,
             dentry_get_path(dent, true, NULL),
             dent->fs ? qstrgetstr(&dent->fs->path) : NULL);
}
END_RS_FUNC(dentry)
