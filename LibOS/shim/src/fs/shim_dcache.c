/* Copyright (C) 2014 Stony Brook University,
   2017 University of North Carolina at Chapel Hill and Fortanix, Inc.
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
 * shim_dcache.c
 *
 * This file contains codes for maintaining directory cache in library OS.
 */

#include <list.h>
#include <shim_checkpoint.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_types.h>

static struct shim_lock dcache_mgr_lock;

#define SYSTEM_LOCK()   lock(&dcache_mgr_lock)
#define SYSTEM_UNLOCK() unlock(&dcache_mgr_lock)
#define SYSTEM_LOCKED() locked(&dcache_mgr_lock)

#define DCACHE_MGR_ALLOC 64

#define OBJ_TYPE struct shim_dentry
#include <memmgr.h>

struct shim_lock dcache_lock;

static MEM_MGR dentry_mgr = NULL;

struct shim_dentry* dentry_root = NULL;

static inline HASHTYPE hash_dentry(struct shim_dentry* start, const char* path, int len) {
    return rehash_path(start ? start->rel_path.hash : 0, path, len);
}

static struct shim_dentry* alloc_dentry(void) {
    struct shim_dentry* dent =
        get_mem_obj_from_mgr_enlarge(dentry_mgr, size_align_up(DCACHE_MGR_ALLOC));
    if (!dent)
        return NULL;

    memset(dent, 0, sizeof(struct shim_dentry));

    REF_SET(dent->ref_count, 0);
    dent->mode = NO_MODE;

    INIT_LIST_HEAD(dent, hlist);
    INIT_LIST_HEAD(dent, list);
    INIT_LISTP(&dent->children);
    INIT_LIST_HEAD(dent, siblings);

    if (!create_lock(&dent->lock)) {
        free_mem_obj_to_mgr(dentry_mgr, dent);
        return NULL;
    }

    return dent;
}

int init_dcache(void) {
    if (!create_lock(&dcache_mgr_lock) || !create_lock(&dcache_lock)) {
        return -ENOMEM;
    }

    dentry_mgr = create_mem_mgr(init_align_up(DCACHE_MGR_ALLOC));

    dentry_root = alloc_dentry();

    /* The root is special; we assume it won't change or be freed, and
     * set its refcount to 1. */
    get_dentry(dentry_root);

    /* Initialize the root to a valid state, as a low-level lookup
     *  will fail. */
    dentry_root->state |= DENTRY_VALID;

    /* The root should be a directory too*/
    dentry_root->state |= DENTRY_ISDIRECTORY;

    qstrsetstr(&dentry_root->name, "", 0);
    qstrsetstr(&dentry_root->rel_path, "", 0);

    get_dentry(dentry_root);
    return 0;
}

/* Increment the reference count for a dentry */
void get_dentry(struct shim_dentry* dent) {
#ifdef DEBUG_REF
    int count = REF_INC(dent->ref_count);

    debug("get dentry %p(%s/%s) (ref_count = %d)\n", dent,
          dent->fs ? qstrgetstr(&dent->fs->path) : "", qstrgetstr(&dent->rel_path), count);
#else
    REF_INC(dent->ref_count);
#endif
}

static void free_dentry(struct shim_dentry* dent) {
    destroy_lock(&dent->lock);
    free_mem_obj_to_mgr(dentry_mgr, dent);
}

/* Decrement the reference count on dent.
 *
 * For now, we don't have an eviction policy, so just
 * keep everything.
 *
 * If a dentry is on the children list of a parent, it has
 * a refcount of at least 1.
 *
 * If the ref count ever hits zero, we free the dentry.
 *
 */
void put_dentry(struct shim_dentry* dent) {
    int count = REF_DEC(dent->ref_count);
    assert(count >= 0);
    // We don't expect this to commonly free a dentry, and may represent a
    // reference counting bug.
    if (count == 0) {
        debug("XXX Churn Warning: Freeing dentry %p; may not be expected\n", dent);
        // Add some assertions that the dentry is properly cleaned up, like it
        // isn't on a parent's children list
        assert(LIST_EMPTY(dent, siblings));
        free_dentry(dent);
    }

    return;
}

/* Allocate and initialize a new dentry for path name, under
 * parent.  Return the dentry.
 *
 * mount is the mountpoint the dentry is under; this is typically
 * the parent->fs, but is passed explicitly for initializing
 * the dentry of a mountpoint.
 *
 * If hashptr is passed (as an optimization), this is a hash
 * of the name.
 *
 * If parent is non-null, the ref count is 2; else it is 1.
 *
 * This function also sets up both a name and a relative path
 */
struct shim_dentry* get_new_dentry(struct shim_mount* mount, struct shim_dentry* parent,
                                   const char* name, int namelen, HASHTYPE* hashptr) {
    assert(locked(&dcache_lock));

    struct shim_dentry* dent = alloc_dentry();
    HASHTYPE hash;

    if (!dent)
        return NULL;

    get_dentry(dent);

    if (hashptr) {
#ifdef DEBUG
        // For debug builds, assert that the hash passed in is correct.
        assert(*hashptr == hash_dentry(parent, name, namelen));
#endif
        hash = *hashptr;
    } else {
        hash = hash_dentry(parent, name, namelen);
    }

    qstrsetstr(&dent->name, name, namelen);
    dent->rel_path.hash = hash;
    /* DEP 6/16/17: Not sure this flag is strictly necessary.
     * But keeping it for now.
     */
    dent->state |= DENTRY_HASHED;

    if (mount) {
        get_mount(mount);
        dent->fs = mount;
    }

    if (parent) {
        // Increment both dentries' ref counts once they are linked
        get_dentry(parent);
        get_dentry(dent);
        LISTP_ADD_TAIL(dent, &parent->children, siblings);
        dent->parent = parent;
        parent->nchildren++;

        if (!qstrempty(&parent->rel_path)) {
            const char* strs[] = {qstrgetstr(&parent->rel_path), "/", name};
            size_t lens[]      = {parent->rel_path.len, 1, namelen};
            assert(lens[0] + lens[1] + lens[2] < STR_SIZE);
            qstrsetstrs(&dent->rel_path, 3, strs, lens);
        } else {
            qstrsetstr(&dent->rel_path, name, namelen);
        }
    } else {
        qstrsetstr(&dent->rel_path, name, namelen);
    }

    return dent;
}

/* This function searches for name/namelen (as the relative path) under
 * the parent directory (start).
 *
 * If requested, the expected hash of the dentry is returned in hashptr,
 * primarily so that the hashing can be reused to add the dentry later.
 *
 * The reference count on the found dentry is incremented by one.
 *
 * Used only by shim_namei.c
 */
struct shim_dentry* __lookup_dcache(struct shim_dentry* start, const char* name, int namelen,
                                    HASHTYPE* hashptr) {
    assert(locked(&dcache_lock));

    /* In this implementation, we just look at the children
     * under the parent and see if there are matches.  It so,
     * return it; if not, don't.
     *
     * To minimize disruption (and possibly for future optimization)
     * we are keeping hashes, so let's start with that for a marginally
     * faster comparison
     */
    HASHTYPE hash = hash_dentry(start, name, namelen);
    struct shim_dentry *dent, *found = NULL;

    /* If start is NULL, there will be no hit in the cache.
     * This mainly happens when boostrapping; in general, we assume the
     * caller will use the current root or cwd.
     */
    if (!start)
        return NULL;

    /* If we are looking up an empty string, return start */
    if (namelen == 0) {
        get_dentry(start);
        found = start;
        goto out;
    }

    LISTP_FOR_EACH_ENTRY(dent, &start->children, siblings) {
        /* DEP 6/20/XX: The old code skipped mountpoints; I don't see any good
         * reason for mount point lookup to fail, at least in this code.
         * Keeping a note just in case.  That is why you always leave a note.
         */
        // if (dent->state & DENTRY_MOUNTPOINT)
        //     continue;

        // Check for memory corruption
        assert((dent->state & DENTRY_INVALID_FLAGS) == 0);

        /* Compare the hash first */
        if (dent->rel_path.hash != hash)
            continue;

        /* I think comparing the relative path is adequate; with a global
         * hash table, a full path comparison may be needed, but I think
         * we can assume a parent has children with unique names */
        const char* filename = get_file_name(name, namelen);
        const char* dname    = dentry_get_name(dent);
        int dname_len        = strlen(dname);
        int fname_len        = name + namelen - filename;
        if (dname_len != fname_len || memcmp(dname, filename, fname_len))
            continue;

        /* If we get this far, we have a match */
        get_dentry(dent);
        found = dent;
        break;
    }

out:
    if (hashptr)
        *hashptr = hash;

    return found;
}

/* This function recursively removes children and drops the reference count
 * under root (but not the root itself).
 *
 * For memory-constrained systems (arguably SGX enclaves), there is a
 * legitimate concern that this could overflow the stack, as a path can have
 * as many as 4096 characters, leading to as many as 2048 stack frames.  It
 * may be preferable to rewrite this using tail recursion or allocating a
 * structure on the heap to track progress.
 */
int __del_dentry_tree(struct shim_dentry* root) {
    assert(locked(&dcache_lock));

    struct shim_dentry *cursor, *n;

    LISTP_FOR_EACH_ENTRY_SAFE(cursor, n, &root->children, siblings) {
        // Recur if this is a non-empty directory
        if (!LISTP_EMPTY(&cursor->children))
            __del_dentry_tree(cursor);

        LISTP_DEL_INIT(cursor, &root->children, siblings);
        cursor->parent = NULL;
        root->nchildren--;
        // Clear the hashed flag, in case there is any vestigial code based
        //  on this state machine (where hased == valid).
        cursor->state &= ~DENTRY_HASHED;
        put_dentry(cursor);
    }

    return 0;
}

bool dentry_is_ancestor(struct shim_dentry* anc, struct shim_dentry* dent) {
    while (dent) {
        if (dent == anc) {
            return true;
        }
        dent = dent->parent;
    }
    return false;
}

BEGIN_CP_FUNC(dentry) {
    __UNUSED(size);
    assert(size == sizeof(struct shim_dentry));

    struct shim_dentry* dent     = (struct shim_dentry*)obj;
    struct shim_dentry* new_dent = NULL;

    ptr_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_dentry));
        ADD_TO_CP_MAP(obj, off);
        new_dent = (struct shim_dentry*)(base + off);

        lock(&dent->lock);
        *new_dent = *dent;
        INIT_LIST_HEAD(new_dent, hlist);
        INIT_LIST_HEAD(new_dent, list);
        INIT_LISTP(&new_dent->children);
        INIT_LIST_HEAD(new_dent, siblings);
        new_dent->data = NULL;
        clear_lock(&new_dent->lock);
        REF_SET(new_dent->ref_count, 0);

        DO_CP_IN_MEMBER(qstr, new_dent, rel_path);
        DO_CP_IN_MEMBER(qstr, new_dent, name);

        if (dent->fs)
            DO_CP_MEMBER(mount, dent, new_dent, fs);

        if (dent->parent)
            DO_CP_MEMBER(dentry, dent, new_dent, parent);

        if (dent->mounted)
            DO_CP_MEMBER(mount, dent, new_dent, mounted);

        unlock(&dent->lock);
        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_dent = (struct shim_dentry*)(base + off);
    }

    if (objp)
        *objp = (void*)new_dent;
}
END_CP_FUNC(dentry)

BEGIN_RS_FUNC(dentry) {
    __UNUSED(offset);
    struct shim_dentry* dent = (void*)(base + GET_CP_FUNC_ENTRY());

    CP_REBASE(dent->hlist);
    CP_REBASE(dent->list);
    CP_REBASE(dent->children);
    CP_REBASE(dent->siblings);
    CP_REBASE(dent->fs);
    CP_REBASE(dent->parent);
    CP_REBASE(dent->mounted);

    if (!create_lock(&dent->lock)) {
        return -ENOMEM;
    }

    /* DEP 6/16/17: I believe the point of this line is to
     * fix up the children linked list.  Presumably the ref count and
     * child count is already correct in the checkpoint. */
    if (dent->parent) {
        get_dentry(dent->parent);
        get_dentry(dent);
        LISTP_ADD_TAIL(dent, &dent->parent->children, siblings);
    }

    DEBUG_RS("hash=%08lx,path=%s,fs=%s", dent->rel_path.hash, dentry_get_path(dent, true, NULL),
             dent->fs ? qstrgetstr(&dent->fs->path) : NULL);
}
END_RS_FUNC(dentry)
