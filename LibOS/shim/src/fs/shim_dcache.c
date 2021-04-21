/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University,
 * 2017 University of North Carolina at Chapel Hill and Fortanix, Inc.
 */

/*
 * This file contains code for maintaining directory cache in library OS.
 */

#include "list.h"
#include "shim_checkpoint.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_types.h"

static struct shim_lock dcache_mgr_lock;

#define SYSTEM_LOCK()   lock(&dcache_mgr_lock)
#define SYSTEM_UNLOCK() unlock(&dcache_mgr_lock)
#define SYSTEM_LOCKED() locked(&dcache_mgr_lock)

#define DCACHE_MGR_ALLOC 64

#define OBJ_TYPE struct shim_dentry
#include "memmgr.h"

struct shim_lock dcache_lock;

static MEM_MGR dentry_mgr = NULL;

struct shim_dentry* dentry_root = NULL;

static struct shim_dentry* alloc_dentry(void) {
    struct shim_dentry* dent =
        get_mem_obj_from_mgr_enlarge(dentry_mgr, size_align_up(DCACHE_MGR_ALLOC));
    if (!dent)
        return NULL;

    memset(dent, 0, sizeof(struct shim_dentry));

    REF_SET(dent->ref_count, 1);
    dent->mode = NO_MODE;

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
    if (!dentry_root) {
        return -ENOMEM;
    }

    /* The root is special; we assume it won't change or be freed, so we artificially increase its
     * refcount by 1. */
    get_dentry(dentry_root);

    /* Initialize the root to a valid state, as a low-level lookup
     *  will fail. */
    dentry_root->state |= DENTRY_VALID;

    /* The root should be a directory too*/
    dentry_root->state |= DENTRY_ISDIRECTORY;

    qstrsetstr(&dentry_root->name, "", 0);
    qstrsetstr(&dentry_root->rel_path, "", 0);

    return 0;
}

/* Increment the reference count for a dentry */
void get_dentry(struct shim_dentry* dent) {
#ifdef DEBUG_REF
    int count = REF_INC(dent->ref_count);

    log_debug("get dentry %p(%s/%s) (ref_count = %d)\n", dent,
              dent->fs ? qstrgetstr(&dent->fs->path) : "", qstrgetstr(&dent->rel_path), count);
#else
    REF_INC(dent->ref_count);
#endif
}

static void free_dentry(struct shim_dentry* dent) {
    if (dent->fs) {
        put_mount(dent->fs);
    }

    qstrfree(&dent->rel_path);
    qstrfree(&dent->name);

    if (dent->parent) {
        put_dentry(dent->parent);
    }

    assert(dent->nchildren == 0);
    assert(LISTP_EMPTY(&dent->children));
    assert(LIST_EMPTY(dent, siblings));

    if (dent->mounted) {
        put_mount(dent->mounted);
    }

    /* XXX: We are leaking `data` field here. This field seems to have different meaning for
     * different dentries and how to free it is a mystery to me. */

    destroy_lock(&dent->lock);

    free_mem_obj_to_mgr(dentry_mgr, dent);
}

static int __put_dentry(struct shim_dentry* dent) {
    int count = REF_DEC(dent->ref_count);
#ifdef DEBUG_REF
    log_debug("put dentry %p(%s/%s) (ref_count = %d)\n", dent,
              dent->fs ? qstrgetstr(&dent->fs->path) : "", qstrgetstr(&dent->rel_path), count);
#endif
    assert(count >= 0);

    if (count == 0) {
        assert(LIST_EMPTY(dent, siblings));
        assert(LISTP_EMPTY(&dent->children));
        free_dentry(dent);
    }
    return count;
}

static void maybe_delete_dentry(struct shim_dentry* dent) {
    assert(locked(&dcache_lock));

    if (REF_GET(dent->ref_count) != 2)
        return;

    if (!dent->parent)
        return;

    if ((dent->state & DENTRY_VALID) && !(dent->state & DENTRY_NEGATIVE))
        return;

    LISTP_DEL_INIT(dent, &dent->parent->children, siblings);
    dent->parent->nchildren--;
    __put_dentry(dent);
}

void put_dentry(struct shim_dentry* dent) {
    int count = REF_GET(dent->ref_count);

    if (count == 2) {
        /* If the ref count is exactly 2, we are holding the last reference to dentry (except for parent
         * or filesystem, in case of root). Try to delete it. Make sure we check the conditions while
         * holding `dcache_lock`, as someone might have acquired a reference in meantime. */
        if (locked(&dcache_lock)) {
            maybe_delete_dentry(dent);
        } else {
            lock(&dcache_lock);
            maybe_delete_dentry(dent);
            unlock(&dcache_lock);
        }
    }
    __put_dentry(dent);
}

struct shim_dentry* get_new_dentry(struct shim_mount* fs, struct shim_dentry* parent,
                                   const char* name, size_t name_len) {
    assert(locked(&dcache_lock));

    struct shim_dentry* dent = alloc_dentry();

    if (!dent)
        return NULL;

    qstrsetstr(&dent->name, name, name_len);

    if (fs) {
        get_mount(fs);
        dent->fs = fs;
    }

    if (parent) {
        /* Increment both dentries' ref counts, because they will be linked (through `dent->parent`
         * and `parent->children`) */
        get_dentry(parent);
        get_dentry(dent);
        LISTP_ADD_TAIL(dent, &parent->children, siblings);
        dent->parent = parent;
        parent->nchildren++;

        if (!qstrempty(&parent->rel_path)) {
            const char* strs[] = {qstrgetstr(&parent->rel_path), "/", name};
            size_t lens[]      = {parent->rel_path.len, 1, name_len};
            assert(lens[0] + lens[1] + lens[2] < STR_SIZE);
            qstrsetstrs(&dent->rel_path, 3, strs, lens);
        } else {
            qstrsetstr(&dent->rel_path, name, name_len);
        }
    } else {
        qstrsetstr(&dent->rel_path, name, name_len);
    }

    return dent;
}

struct shim_dentry* lookup_dcache(struct shim_dentry* parent, const char* name, size_t name_len) {
    assert(locked(&dcache_lock));

    assert(parent);
    assert(name_len > 0);

    struct shim_dentry* dent;
    LISTP_FOR_EACH_ENTRY(dent, &parent->children, siblings) {
        if (qstrcmpstr(&dent->name, name, name_len) == 0) {
            get_dentry(dent);
            return dent;
        }
    }

    return NULL;
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

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_dentry));
        ADD_TO_CP_MAP(obj, off);
        new_dent = (struct shim_dentry*)(base + off);

        lock(&dent->lock);
        *new_dent = *dent;
        INIT_LISTP(&new_dent->children);
        INIT_LIST_HEAD(new_dent, siblings);
        clear_lock(&new_dent->lock);
        REF_SET(new_dent->ref_count, 0);

        /* we don't checkpoint children dentries, so need to list directory again */
        new_dent->state &= ~DENTRY_LISTED;

        if (new_dent->fs == &fifo_builtin_fs) {
            /* FIFO pipe, do not try to checkpoint its fs */
            new_dent->fs = NULL;
        } else {
            /* not FIFO, no need to keep data (FIFOs stash internal FDs into data field) */
            new_dent->data = NULL;
        }

        DO_CP_IN_MEMBER(qstr, new_dent, rel_path);
        DO_CP_IN_MEMBER(qstr, new_dent, name);

        if (new_dent->fs)
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

    CP_REBASE(dent->children);
    CP_REBASE(dent->siblings);
    CP_REBASE(dent->fs);
    CP_REBASE(dent->parent);
    CP_REBASE(dent->mounted);

    if (!create_lock(&dent->lock)) {
        return -ENOMEM;
    }

    if (!dent->fs) {
        /* special case of FIFO pipe: use built-in FIFO FS */
        dent->fs = &fifo_builtin_fs;
    } else {
        get_mount(dent->fs);
    }

    /* DEP 6/16/17: I believe the point of this line is to
     * fix up the children linked list.  Presumably the ref count and
     * child count is already correct in the checkpoint. */
    if (dent->parent) {
        get_dentry(dent->parent);
        get_dentry(dent);
        LISTP_ADD_TAIL(dent, &dent->parent->children, siblings);
    }

    if (dent->mounted) {
        get_mount(dent->mounted);
    }

#if DEBUG_RESUME == 1
    char buffer[dentry_get_path_size(dent)];
#endif
    DEBUG_RS("path=%s,fs=%s", dentry_get_path(dent, buffer),
             dent->fs ? qstrgetstr(&dent->fs->path) : NULL);
}
END_RS_FUNC(dentry)
