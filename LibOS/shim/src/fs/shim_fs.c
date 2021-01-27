/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains code for creating filesystems in library OS.
 */

#include <linux/fcntl.h>

#include "api.h"
#include "list.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "shim_checkpoint.h"
#include "shim_fs.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_utils.h"
#include "toml.h"

struct shim_fs {
    char name[8];
    struct shim_fs_ops* fs_ops;
    struct shim_d_ops* d_ops;
};

struct shim_fs mountable_fs[] = {
    {
        .name   = "chroot",
        .fs_ops = &chroot_fs_ops,
        .d_ops  = &chroot_d_ops,
    },
    {
        .name   = "proc",
        .fs_ops = &proc_fs_ops,
        .d_ops  = &proc_d_ops,
    },
    {
        .name   = "dev",
        .fs_ops = &dev_fs_ops,
        .d_ops  = &dev_d_ops,
    },
    {
        .name   = "sys",
        .fs_ops = &sys_fs_ops,
        .d_ops  = &sys_d_ops,
    },
};

struct shim_mount* builtin_fs[] = {
    &chroot_builtin_fs,
    &pipe_builtin_fs,
    &fifo_builtin_fs,
    &socket_builtin_fs,
    &epoll_builtin_fs,
    &eventfd_builtin_fs,
};

static struct shim_lock mount_mgr_lock;

#define SYSTEM_LOCK()   lock(&mount_mgr_lock)
#define SYSTEM_UNLOCK() unlock(&mount_mgr_lock)
#define SYSTEM_LOCKED() locked(&mount_mgr_lock)

#define MOUNT_MGR_ALLOC 64

#define OBJ_TYPE struct shim_mount
#include "memmgr.h"

static MEM_MGR mount_mgr = NULL;
DEFINE_LISTP(shim_mount);
/* Links to mount->list */
static LISTP_TYPE(shim_mount) mount_list;
static struct shim_lock mount_list_lock;

int init_fs(void) {
    mount_mgr = create_mem_mgr(init_align_up(MOUNT_MGR_ALLOC));
    if (!mount_mgr)
        return -ENOMEM;

    if (!create_lock(&mount_mgr_lock) || !create_lock(&mount_list_lock)) {
        destroy_mem_mgr(mount_mgr);
        return -ENOMEM;
    }
    return 0;
}

static struct shim_mount* alloc_mount(void) {
    return get_mem_obj_from_mgr_enlarge(mount_mgr, size_align_up(MOUNT_MGR_ALLOC));
}

static bool mount_migrated = false;

static int __mount_root(struct shim_dentry** root) {
    int ret = 0;
    char* fs_root_type = NULL;
    char* fs_root_uri  = NULL;

    assert(g_manifest_root);

    ret = toml_string_in(g_manifest_root, "fs.root.type", &fs_root_type);
    if (ret < 0) {
        debug("Cannot parse 'fs.root.type' (the value must be put in double quotes!)\n");
        ret = -EINVAL;
        goto out;
    }

    ret = toml_string_in(g_manifest_root, "fs.root.uri", &fs_root_uri);
    if (ret < 0) {
        debug("Cannot parse 'fs.root.uri' (the value must be put in double quotes!)\n");
        ret = -EINVAL;
        goto out;
    }

    if (fs_root_type && fs_root_uri) {
        debug("Mounting root as %s filesystem: from %s to /\n", fs_root_type, fs_root_uri);
        if ((ret = mount_fs(fs_root_type, fs_root_uri, "/", NULL, root, 0)) < 0) {
            debug("Mounting root filesystem failed (%d)\n", ret);
            goto out;
        }
    } else {
        debug("Mounting root as chroot filesystem: from file:. to /\n");
        if ((ret = mount_fs("chroot", URI_PREFIX_FILE, "/", NULL, root, 0)) < 0) {
            debug("Mounting root filesystem failed (%d)\n", ret);
            goto out;
        }
    }

    ret = 0;
out:
    free(fs_root_type);
    free(fs_root_uri);
    return ret;
}

static int __mount_sys(struct shim_dentry* root) {
    int ret;

    debug("Mounting special proc filesystem: /proc\n");
    if ((ret = mount_fs("proc", NULL, "/proc", root, NULL, 0)) < 0) {
        debug("Mounting /proc filesystem failed (%d)\n", ret);
        return ret;
    }

    debug("Mounting special dev filesystem: /dev\n");
    struct shim_dentry* dev_dent = NULL;
    if ((ret = mount_fs("dev", NULL, "/dev", root, &dev_dent, 0)) < 0) {
        debug("Mounting dev filesystem failed (%d)\n", ret);
        return ret;
    }

    debug("Mounting terminal device /dev/tty under /dev\n");
    if ((ret = mount_fs("chroot", URI_PREFIX_DEV "tty", "/dev/tty", dev_dent, NULL, 0)) < 0) {
        debug("Mounting terminal device /dev/tty failed (%d)\n", ret);
        return ret;
    }

    debug("Mounting special sys filesystem: /sys\n");

    if ((ret = mount_fs("sys", NULL, "/sys", root, NULL, 0)) < 0) {
        debug("Mounting sys filesystem failed (%d)\n", ret);
        return ret;
    }

    return 0;
}

static int __mount_one_other(toml_table_t* mount) {
    assert(mount);

    int ret;
    const char* key = toml_table_key(mount);

    toml_raw_t mount_type_raw = toml_raw_in(mount, "type");
    if (!mount_type_raw) {
        debug("Cannot find 'fs.mount.%s.type'\n", key);
        return -EINVAL;
    }

    toml_raw_t mount_path_raw = toml_raw_in(mount, "path");
    if (!mount_path_raw) {
        debug("Cannot find 'fs.mount.%s.path'\n", key);
        return -EINVAL;
    }

    toml_raw_t mount_uri_raw = toml_raw_in(mount, "uri");
    if (!mount_uri_raw) {
        debug("Cannot find 'fs.mount.%s.uri'\n", key);
        return -EINVAL;
    }

    char* mount_type = NULL;
    char* mount_path = NULL;
    char* mount_uri  = NULL;

    ret = toml_rtos(mount_type_raw, &mount_type);
    if (ret < 0) {
        debug("Cannot parse 'fs.mount.%s.type' (the value must be put in double quotes!)\n", key);
        ret = -EINVAL;
        goto out;
    }

    ret = toml_rtos(mount_path_raw, &mount_path);
    if (ret < 0) {
        debug("Cannot parse 'fs.mount.%s.path' (the value must be put in double quotes!)\n", key);
        ret = -EINVAL;
        goto out;
    }

    ret = toml_rtos(mount_uri_raw, &mount_uri);
    if (ret < 0) {
        debug("Cannot parse 'fs.mount.%s.uri' (the value must be put in double quotes!)\n", key);
        ret = -EINVAL;
        goto out;
    }

    debug("Mounting as %s filesystem: from %s to %s\n", mount_type, mount_uri, mount_path);

    if (!strcmp(mount_path, "/")) {
        debug("Root mount / already exists, verify that there are no duplicate mounts in manifest\n"
              "(note that root / is automatically mounted in Graphene and can be changed via "
              "'fs.root' manifest entry).\n");
        ret = -EEXIST;
        goto out;
    }

    if (!strcmp(mount_path, ".") || !strcmp(mount_path, "..")) {
        debug("Mount points '.' and '..' are not allowed, remove them from manifest.\n");
        ret = -EINVAL;
        goto out;
    }

    if ((ret = mount_fs(mount_type, mount_uri, mount_path, NULL, NULL, 1)) < 0) {
        debug("Mounting %s on %s (type=%s) failed (%d)\n", mount_uri, mount_path, mount_type,
              -ret);
        goto out;
    }

    ret = 0;
out:
    free(mount_type);
    free(mount_path);
    free(mount_uri);
    return ret;
}

static int __mount_others(void) {
    int ret = 0;

    assert(g_manifest_root);
    toml_table_t* manifest_fs = toml_table_in(g_manifest_root, "fs");
    if (!manifest_fs)
        return 0;

    toml_table_t* manifest_fs_mounts = toml_table_in(manifest_fs, "mount");
    if (!manifest_fs_mounts)
        return 0;

    ssize_t mounts_cnt = toml_table_ntab(manifest_fs_mounts);
    if (mounts_cnt <= 0)
        return 0;

    for (ssize_t i = 0; i < mounts_cnt; i++) {
        const char* mount_key = toml_key_in(manifest_fs_mounts, i);
        assert(mount_key);

        toml_table_t* mount = toml_table_in(manifest_fs_mounts, mount_key);
        ret = __mount_one_other(mount);
        if (ret < 0)
            return ret;
    }
    return 0;
}

int init_mount_root(void) {
    if (mount_migrated)
        return 0;

    int ret;
    struct shim_dentry* root = NULL;

    if ((ret = __mount_root(&root)) < 0)
        return ret;

    if ((ret = __mount_sys(root)) < 0)
        return ret;

    return 0;
}

int init_mount(void) {
    if (mount_migrated)
        return 0;

    int ret;

    if ((ret = __mount_others()) < 0)
        return ret;

    assert(g_manifest_root);

    char* fs_start_dir = NULL;
    ret = toml_string_in(g_manifest_root, "fs.start_dir", &fs_start_dir);
    if (ret < 0) {
        debug("Can't parse 'fs.start_dir' (note that the value must be put in double quotes)!\n");
        return ret;
    }

    if (fs_start_dir) {
        struct shim_dentry* dent = NULL;
        ret = path_lookupat(NULL, fs_start_dir, 0, &dent, NULL);
        free(fs_start_dir);
        if (ret < 0) {
            debug("Invalid 'fs.start_dir' in manifest.\n");
            return ret;
        }
        lock(&g_process.fs_lock);
        put_dentry(g_process.cwd);
        g_process.cwd = dent;
        unlock(&g_process.fs_lock);
    }
    /* Otherwise `cwd` is already initialized. */

    return 0;
}

static inline struct shim_fs* find_fs(const char* type) {
    struct shim_fs* fs = NULL;
    size_t len = strlen(type);

    for (size_t i = 0; i < ARRAY_SIZE(mountable_fs); i++)
        if (!memcmp(type, mountable_fs[i].name, len + 1)) {
            fs = &mountable_fs[i];
            break;
        }

    return fs;
}

int search_builtin_fs(const char* type, struct shim_mount** fs) {
    size_t len = strlen(type);

    for (size_t i = 0; i < ARRAY_SIZE(builtin_fs); i++)
        if (!memcmp(type, builtin_fs[i]->type, len + 1)) {
            *fs = builtin_fs[i];
            return 0;
        }

    return -ENOENT;
}

static int __mount_fs(struct shim_mount* mount, struct shim_dentry* dent) {
    assert(locked(&dcache_lock));

    int ret = 0;

    dent->state |= DENTRY_MOUNTPOINT;
    get_dentry(dent);
    mount->mount_point = dent;
    dent->mounted      = mount;

    struct shim_dentry* mount_root = mount->root;

    if (!mount_root) {
        /* mount_root->state |= DENTRY_VALID; */
        mount_root = get_new_dentry(mount, NULL, "", 0, NULL);
        assert(mount->d_ops && mount->d_ops->lookup);
        ret = mount->d_ops->lookup(mount_root);
        if (ret < 0) {
            put_dentry(mount_root);
            return ret;
        }
        mount->root = mount_root;
    }

    /* DEP 7/1/17: If the mount is a directory, make sure the mount
     * point is marked as a directory */
    if (mount_root->state & DENTRY_ISDIRECTORY)
        dent->state |= DENTRY_ISDIRECTORY;

    /* DEP 6/16/17: In the dcache redesign, we don't use the *REACHABLE flags, but
     * leaving this commented for documentation, in case there is a problem
     * I over-simplified */
    // mount_root->state |= dent->state & (DENTRY_REACHABLE|DENTRY_UNREACHABLE);

    /* DEP 6/16/17: In the dcache redesign, I don't believe we need to manually
     * rehash the path; this should be handled by get_new_dentry, or already be
     * hashed if mount_root exists.  I'm going to leave this line here for now
     * as documentation in case there is a problem later.
     */
    //__add_dcache(mount_root, &mount->path.hash);

    if ((ret = __del_dentry_tree(dent)) < 0)
        return ret;

    lock(&mount_list_lock);
    get_mount(mount);
    LISTP_ADD_TAIL(mount, &mount_list, list);
    unlock(&mount_list_lock);

    do {
        struct shim_dentry* parent = dent->parent;

        if (dent->state & DENTRY_ANCESTOR) {
            put_dentry(dent);
            break;
        }

        dent->state |= DENTRY_ANCESTOR;
        if (parent)
            get_dentry(parent);
        put_dentry(dent);
        dent = parent;
    } while (dent);

    return 0;
}

/* Extracts the last component of the `path`. If there's none, `*last_elem_len` is set to 0 and
 * `*last_elem` is set to NULL. */
static void find_last_component(const char* path, const char** last_comp, size_t* last_comp_len) {
    *last_comp = NULL;
    size_t last_len = 0;
    size_t path_len = strlen(path);
    if (path_len == 0)
        goto out;

    // Drop any trailing slashes.
    const char* last = path + path_len - 1;
    while (last > path && *last == '/')
        last--;
    if (*last == '/')
        goto out;

    // Skip the last component.
    last_len = 1;
    while (last > path && *(last - 1) != '/') {
        last--;
        last_len++;
    }
    *last_comp = last;
out:
    *last_comp_len = last_len;
}

/* Parent is optional, but helpful.
 * dentp (optional) memoizes the dentry of the newly-mounted FS, on success.
 *
 * The make_ancestor flag creates pseudo-dentries for any missing paths (passed to __path_lookupat).
 * This is only intended for use to connect mounts specified in the manifest when an intervening
 * path is missing.
 */
int mount_fs(const char* type, const char* uri, const char* mount_point, struct shim_dentry* parent,
             struct shim_dentry** dentp, bool make_ancestor) {
    int ret = 0;
    struct shim_fs* fs = find_fs(type);

    if (!fs || !fs->fs_ops || !fs->fs_ops->mount) {
        ret = -ENODEV;
        goto out;
    }

    /* Split the mount point into the prefix and atom */
    size_t mount_point_len = strlen(mount_point);
    if (mount_point_len == 0) {
        ret = -EINVAL;
        goto out;
    }
    const char* last;
    size_t last_len;
    find_last_component(mount_point, &last, &last_len);

    bool need_parent_put = false;
    lock(&dcache_lock);

    if (!parent) {
        // See if we are not at the root mount
        if (last_len > 0) {
            // Look up the parent
            size_t parent_len = last - mount_point;
            char* parent_path = __alloca(parent_len + 1);
            memcpy(parent_path, mount_point, parent_len);
            parent_path[parent_len] = 0;
            if ((ret = __path_lookupat(dentry_root, parent_path, 0, &parent, 0, dentry_root->fs,
                                       make_ancestor)) < 0) {
                debug("Path lookup failed %d\n", ret);
                goto out_with_unlock;
            }
            need_parent_put = true;
        }
    }

    if (parent && last_len > 0) {
        /* Newly created dentry's relative path will be a concatenation of parent
         * + last strings (see get_new_dentry), make sure it fits into qstr */
        if (parent->rel_path.len + 1 + last_len >= STR_SIZE) { /* +1 for '/' */
            debug("Relative path exceeds the limit %d\n", STR_SIZE);
            ret = -ENAMETOOLONG;
            goto out_with_unlock;
        }
    }

    struct shim_mount* mount = alloc_mount();
    void* mount_data         = NULL;

    /* call fs-specific mount to allocate mount_data */
    if ((ret = fs->fs_ops->mount(uri, &mount_data)) < 0)
        goto out_with_unlock;

    size_t uri_len = uri ? strlen(uri) : 0;
    qstrsetstr(&mount->path, mount_point, mount_point_len);
    qstrsetstr(&mount->uri, uri, uri_len);
    memcpy(mount->type, fs->name, sizeof(fs->name));
    mount->fs_ops = fs->fs_ops;
    mount->d_ops  = fs->d_ops;
    mount->data   = mount_data;

    /* Get the negative dentry from the cache, if one exists */
    struct shim_dentry* dent;
    struct shim_dentry* dent2;
    /* Special case the root */
    if (last_len == 0)
        dent = dentry_root;
    else {
        dent = __lookup_dcache(parent, last, last_len, NULL);

        if (!dent) {
            dent = get_new_dentry(mount, parent, last, last_len, NULL);
        }
    }

    if (dent != dentry_root && dent->state & DENTRY_VALID) {
        debug("Mount %s already exists, verify that there are no duplicate mounts in manifest\n"
              "(note that /proc and /dev are automatically mounted in Graphene).\n", mount_point);
        ret = -EEXIST;
        goto out_with_unlock;
    }

    // We need to fix up the relative path to this mount, but only for
    // directories.
    qstrsetstr(&dent->rel_path, "", 0);
    mount->path.hash = dent->rel_path.hash;

    /*Now go ahead and do a lookup so the dentry is valid */
    if ((ret = __path_lookupat(dentry_root, mount_point, 0, &dent2, 0, parent ? parent->fs : mount,
                               make_ancestor)) < 0)
        goto out_with_unlock;

    assert(dent == dent2);

    /* We want the net impact of mounting to increment the ref count on the
     * entry (until the unmount).  But we shouldn't also hold the reference on
     * dent from the validation step.  Drop it here */
    put_dentry(dent2);

    ret = __mount_fs(mount, dent);

    // If we made it this far and the dentry is still negative, clear
    // the negative flag from the denry.
    if (!ret && (dent->state & DENTRY_NEGATIVE))
        dent->state &= ~DENTRY_NEGATIVE;

    /* Set the file system at the mount point properly */
    dent->fs = mount;

    if (dentp && !ret) {
        *dentp = dent;
    } else {
        put_dentry(dent);
    }

out_with_unlock:
    unlock(&dcache_lock);
    if (need_parent_put) {
        put_dentry(parent);
    }
out:
    return ret;
}

/*
 * XXX: These two functions are useless - `mount` is not freed even if refcount reaches 0.
 * Unfortunately Graphene is not keeping track of this refcount correctly, so we cannot free
 * the object. Fixing this would require revising whole filesystem implementation - but this code
 * is, uhm, not the best achievement of humankind and probably requires a complete rewrite.
 */
void get_mount(struct shim_mount* mount) {
    __UNUSED(mount);
    // REF_INC(mount->ref_count);
}

void put_mount(struct shim_mount* mount) {
    __UNUSED(mount);
    // REF_DEC(mount->ref_count);
}

int walk_mounts(int (*walk)(struct shim_mount* mount, void* arg), void* arg) {
    struct shim_mount* mount;
    struct shim_mount* n;
    int ret = 0;
    int nsrched = 0;

    lock(&mount_list_lock);

    LISTP_FOR_EACH_ENTRY_SAFE(mount, n, &mount_list, list) {
        if ((ret = (*walk)(mount, arg)) < 0)
            break;

        if (ret > 0)
            nsrched++;
    }

    unlock(&mount_list_lock);
    return ret < 0 ? ret : (nsrched ? 0 : -ESRCH);
}

struct shim_mount* find_mount_from_uri(const char* uri) {
    struct shim_mount* mount;
    struct shim_mount* found = NULL;
    size_t longest_path = 0;

    lock(&mount_list_lock);
    LISTP_FOR_EACH_ENTRY(mount, &mount_list, list) {
        if (qstrempty(&mount->uri))
            continue;

        if (!memcmp(qstrgetstr(&mount->uri), uri, mount->uri.len)) {
            if (mount->path.len > longest_path) {
                longest_path = mount->path.len;
                found = mount;
            }
        }
    }

    if (found)
        get_mount(found);

    unlock(&mount_list_lock);
    return found;
}

BEGIN_CP_FUNC(mount) {
    __UNUSED(size);
    assert(size == sizeof(struct shim_mount));

    struct shim_mount* mount     = (struct shim_mount*)obj;
    struct shim_mount* new_mount = NULL;

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_mount));
        ADD_TO_CP_MAP(obj, off);

        mount->cpdata = NULL;
        if (mount->fs_ops && mount->fs_ops->checkpoint) {
            void* cpdata = NULL;
            int bytes = mount->fs_ops->checkpoint(&cpdata, mount->data);
            if (bytes > 0) {
                mount->cpdata = cpdata;
                mount->cpsize = bytes;
            }
        }

        new_mount  = (struct shim_mount*)(base + off);
        *new_mount = *mount;

        if (mount->cpdata) {
            size_t cp_off = ADD_CP_OFFSET(mount->cpsize);
            memcpy((char*)base + cp_off, mount->cpdata, mount->cpsize);
            new_mount->cpdata = (char*)base + cp_off;
        }

        new_mount->data        = NULL;
        new_mount->mount_point = NULL;
        new_mount->root        = NULL;
        INIT_LIST_HEAD(new_mount, list);
        REF_SET(new_mount->ref_count, 0);

        DO_CP_IN_MEMBER(qstr, new_mount, path);
        DO_CP_IN_MEMBER(qstr, new_mount, uri);

        if (mount->mount_point)
            DO_CP_MEMBER(dentry, mount, new_mount, mount_point);

        if (mount->root)
            DO_CP_MEMBER(dentry, mount, new_mount, root);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_mount = (struct shim_mount*)(base + off);
    }

    if (objp)
        *objp = (void*)new_mount;
}
END_CP_FUNC(mount)

BEGIN_RS_FUNC(mount) {
    __UNUSED(offset);
    struct shim_mount* mount = (void*)(base + GET_CP_FUNC_ENTRY());

    CP_REBASE(mount->cpdata);
    CP_REBASE(mount->list);
    CP_REBASE(mount->mount_point);
    CP_REBASE(mount->root);

    if (mount->mount_point) {
        get_dentry(mount->mount_point);
    }

    if (mount->root) {
        get_dentry(mount->root);
    }

    struct shim_fs* fs = find_fs(mount->type);

    if (fs && fs->fs_ops && fs->fs_ops->migrate && mount->cpdata) {
        void* mount_data = NULL;
        if (fs->fs_ops->migrate(mount->cpdata, &mount_data) == 0)
            mount->data = mount_data;
        mount->cpdata = NULL;
    }

    mount->fs_ops = fs->fs_ops;
    mount->d_ops  = fs->d_ops;

    LISTP_ADD_TAIL(mount, &mount_list, list);

    if (!qstrempty(&mount->path)) {
        DEBUG_RS("type=%s,uri=%s,path=%s", mount->type, qstrgetstr(&mount->uri),
                 qstrgetstr(&mount->path));
    } else {
        DEBUG_RS("type=%s,uri=%s", mount->type, qstrgetstr(&mount->uri));
    }
}
END_RS_FUNC(mount)

BEGIN_CP_FUNC(all_mounts) {
    __UNUSED(obj);
    __UNUSED(size);
    __UNUSED(objp);
    struct shim_mount* mount;
    lock(&mount_list_lock);
    LISTP_FOR_EACH_ENTRY(mount, &mount_list, list) {
        DO_CP(mount, mount, NULL);
    }
    unlock(&mount_list_lock);

    /* add an empty entry to mark as migrated */
    ADD_CP_FUNC_ENTRY(0UL);
}
END_CP_FUNC(all_mounts)

BEGIN_RS_FUNC(all_mounts) {
    __UNUSED(entry);
    __UNUSED(base);
    __UNUSED(offset);
    __UNUSED(rebase);
    /* to prevent file system from being mount again */
    mount_migrated = true;
}
END_RS_FUNC(all_mounts)

const char* get_file_name(const char* path, size_t len) {
    const char* c = path + len - 1;
    while (c > path && *c != '/')
        c--;
    return *c == '/' ? c + 1 : c;
}

size_t dentry_get_path_size(struct shim_dentry* dent) {
    size_t size = 0;
    bool slash = false;

    if (dent->fs && dent->fs->path.len) {
        size += dent->fs->path.len;
        slash = qstrgetstr(&dent->fs->path)[dent->fs->path.len - 1] == '/';
    }

    if (dent->rel_path.len) {
        const char* path = qstrgetstr(&dent->rel_path);
        size_t len = dent->rel_path.len;

        // Ensure exactly 1 slash (see dentry_get_path())
        if (slash && *path == '/')
            size += len - 1;
        else if (!slash && *path != '/')
            size += len + 1;
        else
            size += len;
    }

    // 1 for null terminator
    size++;

    return size;
}

char* dentry_get_path(struct shim_dentry* dent, char* buffer) {
    struct shim_mount* fs = dent->fs;
    bool slash = false;
    char* c;

    assert(buffer);
    c = buffer;

    if (fs && fs->path.len) {
        memcpy(c, qstrgetstr(&fs->path), fs->path.len);
        c += fs->path.len;

        slash = *(c - 1) == '/';
    }

    if (dent->rel_path.len) {
        const char* path = qstrgetstr(&dent->rel_path);
        size_t len = dent->rel_path.len;

        // Ensure there is exactly 1 slash between fs path and rel_path.
        if (slash && *path == '/') {
            memcpy(c, path + 1, len - 1);
            c += len - 1;
        } else if (!slash && *path != '/') {
            *c = '/';
            memcpy(c + 1, path, len);
            c += len + 1;
        } else {
            memcpy(c, path, len);
            c += len;
        }
    }

    assert(c - buffer == (ssize_t)(dentry_get_path_size(dent) - 1));

    *c = 0;
    return buffer;
}
