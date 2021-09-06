/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University,
 * 2017 University of North Carolina at Chapel Hill and Fortanix, Inc.
 */

/*
 * This file contains code for maintaining directory cache in library OS.
 */

#include "list.h"
#include "perm.h"
#include "shim_checkpoint.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_types.h"
#include "stat.h"

static struct shim_lock dcache_mgr_lock;

#define SYSTEM_LOCK()   lock(&dcache_mgr_lock)
#define SYSTEM_UNLOCK() unlock(&dcache_mgr_lock)
#define SYSTEM_LOCKED() locked(&dcache_mgr_lock)

#define DCACHE_MGR_ALLOC 64

#define OBJ_TYPE struct shim_dentry
#include "memmgr.h"

struct shim_lock g_dcache_lock;

static MEM_MGR dentry_mgr = NULL;

struct shim_dentry* g_dentry_root = NULL;

static struct shim_dentry* alloc_dentry(void) {
    struct shim_dentry* dent =
        get_mem_obj_from_mgr_enlarge(dentry_mgr, size_align_up(DCACHE_MGR_ALLOC));
    if (!dent)
        return NULL;

    memset(dent, 0, sizeof(struct shim_dentry));

    REF_SET(dent->ref_count, 1);

    INIT_LISTP(&dent->children);
    INIT_LIST_HEAD(dent, siblings);

    if (!create_lock(&dent->lock)) {
        free_mem_obj_to_mgr(dentry_mgr, dent);
        return NULL;
    }

    return dent;
}

static void free_dentry(struct shim_dentry* dentry);

int init_dcache(void) {
    if (!create_lock(&dcache_mgr_lock) || !create_lock(&g_dcache_lock)) {
        return -ENOMEM;
    }

    dentry_mgr = create_mem_mgr(init_align_up(DCACHE_MGR_ALLOC));

    if (g_pal_control->parent_process) {
        /* In a child process, `g_dentry_root` will be restored from a checkpoint. */
        return 0;
    }

    g_dentry_root = alloc_dentry();
    if (!g_dentry_root) {
        return -ENOMEM;
    }

    /* The root is special; we assume it won't change or be freed, so we artificially increase its
     * refcount by 1. */
    get_dentry(g_dentry_root);

    /* Initialize the root to a valid state, as a low-level lookup
     *  will fail. */
    g_dentry_root->state |= DENTRY_VALID;

    /* The root should be a directory too */
    g_dentry_root->perm = PERM_rwx______;
    g_dentry_root->type = S_IFDIR;

    char* name = strdup("");
    if (!name) {
        free_dentry(g_dentry_root);
        g_dentry_root = NULL;
        return -ENOMEM;
    }
    g_dentry_root->name = name;
    g_dentry_root->name_len = 0;

    return 0;
}

/* Increment the reference count for a dentry */
void get_dentry(struct shim_dentry* dent) {
#ifdef DEBUG_REF
    int64_t count = REF_INC(dent->ref_count);

    const char* path = NULL;
    dentry_abs_path(dent, &path, /*size=*/NULL);
    log_debug("get dentry %p(%s) (ref_count = %lld)", dent, path, count);
    free(path);
#else
    REF_INC(dent->ref_count);
#endif
}

static void free_dentry(struct shim_dentry* dent) {
    if (dent->mount) {
        put_mount(dent->mount);
    }

    free(dent->name);

    if (dent->parent) {
        put_dentry(dent->parent);
    }

    assert(dent->nchildren == 0);
    assert(LISTP_EMPTY(&dent->children));
    assert(LIST_EMPTY(dent, siblings));

    if (dent->attached_mount) {
        put_mount(dent->attached_mount);
    }

    /* XXX: We are leaking `data` field here. This field seems to have different meaning for
     * different dentries and how to free it is a mystery to me. */

    destroy_lock(&dent->lock);

    free_mem_obj_to_mgr(dentry_mgr, dent);
}

void put_dentry(struct shim_dentry* dent) {
    int64_t count = REF_DEC(dent->ref_count);
#ifdef DEBUG_REF
    const char* path = NULL;
    dentry_abs_path(dent, &path, /*size=*/NULL);
    log_debug("put dentry %p(%s) (ref_count = %lld)", dent, path, count);
    free(path);
#endif
    assert(count >= 0);

    if (count == 0) {
        assert(LIST_EMPTY(dent, siblings));
        assert(LISTP_EMPTY(&dent->children));
        free_dentry(dent);
    }
}

void dentry_gc(struct shim_dentry* dent) {
    assert(locked(&g_dcache_lock));
    assert(dent->parent);

    if (REF_GET(dent->ref_count) != 1)
        return;

    if ((dent->state & DENTRY_VALID) && !(dent->state & DENTRY_NEGATIVE))
        return;

    LISTP_DEL_INIT(dent, &dent->parent->children, siblings);
    dent->parent->nchildren--;
    /* This should delete `dent` */
    put_dentry(dent);
}

struct shim_dentry* get_new_dentry(struct shim_mount* mount, struct shim_dentry* parent,
                                   const char* name, size_t name_len) {
    assert(locked(&g_dcache_lock));
    assert(mount);

    struct shim_dentry* dent = alloc_dentry();

    if (!dent)
        return NULL;

    dent->name = alloc_substr(name, name_len);
    if (!dent->name) {
        free_dentry(dent);
        return NULL;
    }
    dent->name_len = name_len;

    if (parent && parent->nchildren >= DENTRY_MAX_CHILDREN) {
        log_warning("get_new_dentry: nchildren limit reached");
        free_dentry(dent);
        return NULL;
    }

    if (mount) {
        get_mount(mount);
        dent->mount = mount;
        dent->fs = mount->fs;
    }

    if (parent) {
        get_dentry(parent);
        dent->parent = parent;

        get_dentry(dent);
        LISTP_ADD_TAIL(dent, &parent->children, siblings);
        parent->nchildren++;
    }

    return dent;
}

struct shim_dentry* dentry_up(struct shim_dentry* dent) {
    while (!dent->parent && dent->mount) {
        dent = dent->mount->mount_point;
    }
    return dent->parent;
}

struct shim_dentry* lookup_dcache(struct shim_dentry* parent, const char* name, size_t name_len) {
    assert(locked(&g_dcache_lock));

    assert(parent);
    assert(name_len > 0);

    struct shim_dentry* tmp;
    struct shim_dentry* dent;
    LISTP_FOR_EACH_ENTRY_SAFE(dent, tmp, &parent->children, siblings) {
        if (dent->name_len == name_len && memcmp(dent->name, name, dent->name_len) == 0) {
            get_dentry(dent);
            return dent;
        }
        dentry_gc(dent);
    }

    return NULL;
}

bool dentry_is_ancestor(struct shim_dentry* anc, struct shim_dentry* dent) {
    assert(anc->mount == dent->mount);

    while (dent) {
        if (dent == anc) {
            return true;
        }
        dent = dent->parent;
    }
    return false;
}

ino_t dentry_ino(struct shim_dentry* dent) {
    return hash_abs_path(dent);
}

static size_t dentry_path_size(struct shim_dentry* dent, bool relative) {
    /* The following code should mirror `dentry_path_into_buf`. */

    bool first = true;
    /* initial size is 1 for null terminator */
    size_t size = 1;

    while (true) {
        struct shim_dentry* up = relative ? dent->parent : dentry_up(dent);
        if (!up)
            break;

        /* Add '/' after name, except the first one */
        if (!first)
            size++;
        first = false;

        /* Add name */
        size += dent->name_len;

        dent = up;
    }

    /* Add beginning '/' if absolute path */
    if (!relative)
        size++;

    return size;
}

/* Compute dentry path, filling an existing buffer. Returns a pointer inside `buf`, possibly after
 * the beginning, because it constructs the path from the end. */
static char* dentry_path_into_buf(struct shim_dentry* dent, bool relative, char* buf, size_t size) {
    if (size == 0)
        return NULL;

    bool first = true;
    size_t pos = size - 1;

    buf[pos] = '\0';

    /* Add names, starting from the last one, until we encounter root */
    while (true) {
        struct shim_dentry* up = relative ? dent->parent : dentry_up(dent);
        if (!up)
            break;

        /* Add '/' after name, except the first one */
        if (!first) {
            if (pos == 0)
                return NULL;
            pos--;
            buf[pos] = '/';
        }
        first = false;

        /* Add name */
        if (pos < dent->name_len)
            return NULL;
        pos -= dent->name_len;
        memcpy(&buf[pos], dent->name, dent->name_len);

        dent = up;
    }

    /* Add beginning '/' if absolute path */
    if (!relative) {
        if (pos == 0)
            return NULL;
        pos--;
        buf[pos] = '/';
    }

    return &buf[pos];
}

static int dentry_path(struct shim_dentry* dent, bool relative, char** path, size_t* size) {
    size_t _size = dentry_path_size(dent, relative);
    char* buf = malloc(_size);
    if (!buf)
        return -ENOMEM;

    char* _path = dentry_path_into_buf(dent, relative, buf, _size);
    assert(_path == buf);

    *path = _path;
    if (size)
        *size = _size;
    return 0;
}

int dentry_abs_path(struct shim_dentry* dent, char** path, size_t* size) {
    return dentry_path(dent, /*relative=*/false, path, size);
}

int dentry_rel_path(struct shim_dentry* dent, char** path, size_t* size) {
    return dentry_path(dent, /*relative=*/true, path, size);
}

void lock_two_dentries(struct shim_dentry* dent1, struct shim_dentry* dent2) {
    assert(dent1 != dent2);
    if ((uintptr_t)dent1 < (uintptr_t)dent2) {
        lock(&dent1->lock);
        lock(&dent2->lock);
    } else {
        lock(&dent2->lock);
        lock(&dent1->lock);
    }
}

void unlock_two_dentries(struct shim_dentry* dent1, struct shim_dentry* dent2) {
    assert(dent1 != dent2);
    if ((uintptr_t)dent1 < (uintptr_t)dent2) {
        unlock(&dent2->lock);
        unlock(&dent1->lock);
    } else {
        unlock(&dent1->lock);
        unlock(&dent2->lock);
    }
}

struct shim_inode* get_new_inode(struct shim_mount* mount, mode_t type, mode_t perm) {
    assert(mount);

    struct shim_inode* inode = calloc(1, sizeof(*inode));
    if (!inode)
        return NULL;

    if (!create_lock(&inode->lock)) {
        free(inode);
        return NULL;
    }

    inode->type = type;
    inode->perm = perm;
    inode->size = 0;
    inode->ctime = 0;
    inode->mtime = 0;
    inode->atime = 0;

    inode->mount = mount;
    get_mount(mount);
    inode->fs = mount->fs;

    REF_SET(inode->ref_count, 1);
    return inode;
}

void get_inode(struct shim_inode* inode) {
    REF_INC(inode->ref_count);
}

void put_inode(struct shim_inode* inode) {
    if (REF_DEC(inode->ref_count) == 0) {
        put_mount(inode->mount);

        destroy_lock(&inode->lock);
        free(inode);
    }
}

static int dump_dentry_write_all(const char* str, size_t size, void* arg) {
    __UNUSED(arg);
    log_always("%.*s", (int)size, str);
    return 0;
}

static void dump_dentry_mode(struct print_buf* buf, mode_t type, mode_t perm) {
    buf_printf(buf, "%06o ", type | perm);

    char c;
    switch (type) {
        case S_IFSOCK: c = 's'; break;
        case S_IFLNK: c = 'l'; break;
        case S_IFREG: c = '-'; break;
        case S_IFBLK: c = 'b'; break;
        case S_IFDIR: c = 'd'; break;
        case S_IFCHR: c = 'c'; break;
        case S_IFIFO: c = 'f'; break;
        default: c = '?'; break;
    }
    buf_putc(buf, c);

    /* ignore suid/sgid bits; display just user permissions */
    buf_putc(buf, (perm & 0400) ? 'r' : '-');
    buf_putc(buf, (perm & 0200) ? 'w' : '-');
    buf_putc(buf, (perm & 0100) ? 'x' : '-');
    buf_putc(buf, ' ');
}

#define DUMP_FLAG(flag, s, empty) buf_puts(&buf, (dent->state & (flag)) ? (s) : (empty))

static void dump_dentry(struct shim_dentry* dent, unsigned int level) {
    assert(locked(&g_dcache_lock));

    struct print_buf buf = INIT_PRINT_BUF(dump_dentry_write_all);

    buf_printf(&buf, "[%6.6s ", dent->mount ? dent->mount->fs->name : "");

    DUMP_FLAG(DENTRY_VALID, "V", ".");
    DUMP_FLAG(DENTRY_LISTED, "L", ".");
    DUMP_FLAG(DENTRY_SYNTHETIC, "S", ".");
    buf_printf(&buf, "%3d] ", (int)REF_GET(dent->ref_count));

    dump_dentry_mode(&buf, dent->type, dent->perm);

    if (dent->attached_mount) {
        buf_puts(&buf, "M");
    } else if (!dent->parent) {
        buf_puts(&buf, "*");
    } else {
        buf_puts(&buf, " ");
    }
    DUMP_FLAG(DENTRY_NEGATIVE, "-", " ");

    for (unsigned int i = 0; i < level; i++)
        buf_puts(&buf, "  ");

    buf_puts(&buf, dent->name);
    switch (dent->type) {
        case S_IFDIR: buf_puts(&buf, "/"); break;
        case S_IFLNK: buf_puts(&buf, " -> "); break;
        default: break;
    }
    buf_flush(&buf);

    if (dent->attached_mount) {
        struct shim_dentry* root = dent->attached_mount->root;
        dump_dentry(root, level + 1);
    } else {
        struct shim_dentry* child;
        LISTP_FOR_EACH_ENTRY(child, &dent->children, siblings) {
            dump_dentry(child, level + 1);
        }
    }
}

#undef DUMP_FLAG

void dump_dcache(struct shim_dentry* dent) {
    lock(&g_dcache_lock);

    if (!dent)
        dent = g_dentry_root;

    dump_dentry(dent, 0);
    unlock(&g_dcache_lock);
}

BEGIN_CP_FUNC(dentry_root) {
    __UNUSED(obj);
    __UNUSED(size);
    __UNUSED(objp);

    /* Checkpoint the root dentry */
    struct shim_dentry* new_dent;
    DO_CP(dentry, g_dentry_root, &new_dent);

    /* Add an entry for it, so that RS_FUNC(dentry_root) is triggered on restore */
    size_t off = ADD_CP_OFFSET(sizeof(struct shim_dentry*));
    struct shim_dentry** new_dentry_root = (void*)(base + off);
    *new_dentry_root = new_dent;
    ADD_CP_FUNC_ENTRY(off);
}
END_CP_FUNC(dentry_root)

BEGIN_RS_FUNC(dentry_root) {
    __UNUSED(offset);

    assert(!g_dentry_root);

    struct shim_dentry** dentry_root = (void*)(base + GET_CP_FUNC_ENTRY());
    CP_REBASE(*dentry_root);
    g_dentry_root = *dentry_root;
}
END_RS_FUNC(dentry_root)

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

        if (new_dent->type != S_IFIFO) {
            /* not FIFO, no need to keep data (FIFOs stash internal FDs into data field) */
            new_dent->data = NULL;
        }

        /* `fs_lock` is used only by process leader. */
        new_dent->fs_lock = NULL;

        DO_CP_MEMBER(str, dent, new_dent, name);

        if (new_dent->mount)
            DO_CP_MEMBER(mount, dent, new_dent, mount);

        if (new_dent->fs)
            DO_CP_MEMBER(fs, dent, new_dent, fs);

        if (dent->parent)
            DO_CP_MEMBER(dentry, dent, new_dent, parent);

        if (dent->attached_mount)
            DO_CP_MEMBER(mount, dent, new_dent, attached_mount);

        if (dent->inode)
            DO_CP_MEMBER(inode, dent, new_dent, inode);

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

    CP_REBASE(dent->name);
    CP_REBASE(dent->children);
    CP_REBASE(dent->siblings);
    CP_REBASE(dent->mount);
    CP_REBASE(dent->fs);
    CP_REBASE(dent->parent);
    CP_REBASE(dent->attached_mount);
    CP_REBASE(dent->inode);

    if (!create_lock(&dent->lock)) {
        return -ENOMEM;
    }

    if (dent->mount) {
        get_mount(dent->mount);
    }

    /* DEP 6/16/17: I believe the point of this line is to
     * fix up the children linked list.  Presumably the ref count and
     * child count is already correct in the checkpoint. */
    if (dent->parent) {
        get_dentry(dent->parent);
        get_dentry(dent);
        LISTP_ADD_TAIL(dent, &dent->parent->children, siblings);
    }

    if (dent->attached_mount) {
        get_mount(dent->attached_mount);
    }

    if (dent->inode) {
        get_inode(dent->inode);
    }
}
END_RS_FUNC(dentry)

BEGIN_CP_FUNC(inode) {
    __UNUSED(size);
    assert(size == sizeof(struct shim_inode));

    struct shim_inode* inode = obj;
    struct shim_inode* new_inode = NULL;

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_inode));
        ADD_TO_CP_MAP(obj, off);
        new_inode = (struct shim_inode*)(base + off);
        memset(new_inode, 0, sizeof(*new_inode));

        lock(&inode->lock);

        new_inode->type = inode->type;
        new_inode->perm = inode->perm;
        new_inode->size = inode->size;

        new_inode->ctime = inode->ctime;
        new_inode->mtime = inode->mtime;
        new_inode->atime = inode->atime;

        DO_CP_MEMBER(mount, inode, new_inode, mount);
        DO_CP_MEMBER(fs, inode, new_inode, fs);

        /* `lock` will be initialized during restore */

        REF_SET(new_inode->ref_count, 0);

        unlock(&inode->lock);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_inode = (struct shim_inode*)(base + off);
    }

    if (objp)
        *objp = (void*)new_inode;
}
END_CP_FUNC(inode)

BEGIN_RS_FUNC(inode) {
    struct shim_inode* inode = (void*)(base + GET_CP_FUNC_ENTRY());
    __UNUSED(offset);

    CP_REBASE(inode->mount);
    CP_REBASE(inode->fs);

    get_mount(inode->mount);

    if (!create_lock(&inode->lock)) {
        return -ENOMEM;
    }
}
END_RS_FUNC(inode)
