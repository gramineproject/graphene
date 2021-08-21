/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains code for creating filesystems in library OS.
 */

#include <linux/fcntl.h>

#include "api.h"
#include "list.h"
#include "pal.h"
#include "pal_error.h"
#include "shim_checkpoint.h"
#include "shim_fs.h"
#include "shim_fs_pseudo.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_utils.h"
#include "toml.h"

struct shim_fs* builtin_fs[] = {
    &chroot_builtin_fs,
    &tmp_builtin_fs,
    &pipe_builtin_fs,
    &fifo_builtin_fs,
    &socket_builtin_fs,
    &epoll_builtin_fs,
    &eventfd_builtin_fs,
    &pseudo_builtin_fs,
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

    int ret;
    if (!create_lock(&mount_mgr_lock) || !create_lock(&mount_list_lock)) {
        ret = -ENOMEM;
        goto err;
    }

    if ((ret = init_procfs()) < 0)
        goto err;
    if ((ret = init_devfs()) < 0)
        goto err;
    if ((ret = init_sysfs()) < 0)
        goto err;

    return 0;

err:
    destroy_mem_mgr(mount_mgr);
    if (lock_created(&mount_mgr_lock))
        destroy_lock(&mount_mgr_lock);
    if (lock_created(&mount_list_lock))
        destroy_lock(&mount_list_lock);
    return ret;
}

static struct shim_mount* alloc_mount(void) {
    return get_mem_obj_from_mgr_enlarge(mount_mgr, size_align_up(MOUNT_MGR_ALLOC));
}

static void free_mount(struct shim_mount* mount) {
    free_mem_obj_to_mgr(mount_mgr, mount);
}

static bool mount_migrated = false;

static int __mount_root(void) {
    int ret = 0;
    char* fs_root_type = NULL;
    char* fs_root_uri  = NULL;

    assert(g_manifest_root);

    ret = toml_string_in(g_manifest_root, "fs.root.type", &fs_root_type);
    if (ret < 0) {
        log_error("Cannot parse 'fs.root.type'");
        ret = -EINVAL;
        goto out;
    }

    ret = toml_string_in(g_manifest_root, "fs.root.uri", &fs_root_uri);
    if (ret < 0) {
        log_error("Cannot parse 'fs.root.uri'");
        ret = -EINVAL;
        goto out;
    }

    if (fs_root_type && fs_root_uri) {
        log_debug("Mounting root as %s filesystem: from %s to /", fs_root_type, fs_root_uri);
        if ((ret = mount_fs(fs_root_type, fs_root_uri, "/")) < 0) {
            log_error("Mounting root filesystem failed (%d)", ret);
            goto out;
        }
    } else {
        log_debug("Mounting root as chroot filesystem: from file:. to /");
        if ((ret = mount_fs("chroot", URI_PREFIX_FILE, "/")) < 0) {
            log_error("Mounting root filesystem failed (%d)", ret);
            goto out;
        }
    }

    ret = 0;
out:
    free(fs_root_type);
    free(fs_root_uri);
    return ret;
}

static int __mount_sys(void) {
    int ret;

    log_debug("Mounting special proc filesystem: /proc");
    if ((ret = mount_fs("pseudo", "proc", "/proc")) < 0) {
        log_error("Mounting proc filesystem failed (%d)", ret);
        return ret;
    }

    log_debug("Mounting special dev filesystem: /dev");
    if ((ret = mount_fs("pseudo", "dev", "/dev")) < 0) {
        log_error("Mounting dev filesystem failed (%d)", ret);
        return ret;
    }

    log_debug("Mounting terminal device /dev/tty under /dev");
    if ((ret = mount_fs("chroot", URI_PREFIX_DEV "tty", "/dev/tty")) < 0) {
        log_error("Mounting terminal device /dev/tty failed (%d)", ret);
        return ret;
    }

    log_debug("Mounting special sys filesystem: /sys");
    if ((ret = mount_fs("pseudo", "sys", "/sys")) < 0) {
        log_error("Mounting sys filesystem failed (%d)", ret);
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
        log_error("Cannot find 'fs.mount.%s.type'", key);
        return -EINVAL;
    }

    toml_raw_t mount_path_raw = toml_raw_in(mount, "path");
    if (!mount_path_raw) {
        log_error("Cannot find 'fs.mount.%s.path'", key);
        return -EINVAL;
    }

    toml_raw_t mount_uri_raw = toml_raw_in(mount, "uri");
    if (!mount_uri_raw) {
        log_error("Cannot find 'fs.mount.%s.uri'", key);
        return -EINVAL;
    }

    char* mount_type = NULL;
    char* mount_path = NULL;
    char* mount_uri  = NULL;

    ret = toml_rtos(mount_type_raw, &mount_type);
    if (ret < 0) {
        log_error("Cannot parse 'fs.mount.%s.type'", key);
        ret = -EINVAL;
        goto out;
    }

    ret = toml_rtos(mount_path_raw, &mount_path);
    if (ret < 0) {
        log_error("Cannot parse 'fs.mount.%s.path'", key);
        ret = -EINVAL;
        goto out;
    }

    ret = toml_rtos(mount_uri_raw, &mount_uri);
    if (ret < 0) {
        log_error("Cannot parse 'fs.mount.%s.uri'", key);
        ret = -EINVAL;
        goto out;
    }

    log_debug("Mounting as %s filesystem: from %s to %s", mount_type, mount_uri, mount_path);

    if (!strcmp(mount_path, "/")) {
        log_error(
            "Root mount / already exists, verify that there are no duplicate mounts in manifest\n"
            "(note that root / is automatically mounted in Graphene and can be changed via "
            "'fs.root' manifest entry).\n");
        ret = -EEXIST;
        goto out;
    }

    if (!strcmp(mount_path, ".") || !strcmp(mount_path, "..")) {
        log_error("Mount points '.' and '..' are not allowed, remove them from manifest.");
        ret = -EINVAL;
        goto out;
    }

    if (!strcmp(mount_uri, "file:/proc") ||
            !strcmp(mount_uri, "file:/sys") ||
            !strcmp(mount_uri, "file:/dev") ||
            !strncmp(mount_uri, "file:/proc/", strlen("file:/proc/")) ||
            !strncmp(mount_uri, "file:/sys/", strlen("file:/sys/")) ||
            !strncmp(mount_uri, "file:/dev/", strlen("file:/dev/"))) {
        log_error("Mounting %s may expose unsanitized, unsafe files to unsuspecting application. "
                  "Graphene will continue application execution, but this configuration is not "
                  "recommended for use in production!", mount_uri);
    }

    if ((ret = mount_fs(mount_type, mount_uri, mount_path)) < 0) {
        log_error("Mounting %s on %s (type=%s) failed (%d)", mount_uri, mount_path, mount_type,
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

    /* *** Warning: A _very_ ugly hack below (hopefully only temporary) ***
     *
     * Currently we don't use proper TOML syntax for declaring mountpoints, instead, we use a syntax
     * which resembles the pre-TOML one used in Graphene. As a result, the entries are not ordered,
     * but Graphene actually relies on the specific mounting order (e.g. you can't mount /lib/asdf
     * first and then /lib, but the other way around works). The problem is, that TOML structure is
     * just a dictionary, so the order of keys is not preserved.
     *
     * The correct solution is to change the manifest syntax for mounts, but this will be a huge,
     * breaking change. For now, just to fix the issue, we use an ugly heuristic - we apply mounts
     * sorted by the path length, which in most cases should result in a proper mount order.
     *
     * We do this in O(n^2) because we don't have a sort function, but that shouldn't be an issue -
     * usually there are around 5 mountpoints with ~30 chars in paths, so it should still be quite
     * fast.
     *
     * Corresponding issue: https://github.com/oscarlab/graphene/issues/2214.
     */
    const char** keys = malloc(mounts_cnt * sizeof(*keys));
    size_t* lengths = malloc(mounts_cnt * sizeof(*lengths));
    size_t longest = 0;
    for (ssize_t i = 0; i < mounts_cnt; i++) {
        keys[i] = toml_key_in(manifest_fs_mounts, i);
        assert(keys[i]);

        toml_table_t* mount = toml_table_in(manifest_fs_mounts, keys[i]);
        assert(mount);
        char* mount_path;
        ret = toml_string_in(mount, "path", &mount_path);
        if (ret < 0 || !mount_path) {
            if (!ret)
                ret = -ENOENT;
            goto out;
        }
        lengths[i] = strlen(mount_path);
        longest = MAX(longest, lengths[i]);
        free(mount_path);
    }

    for (size_t i = 0; i <= longest; i++) {
        for (ssize_t j = 0; j < mounts_cnt; j++) {
            if (lengths[j] != i)
                continue;
            toml_table_t* mount = toml_table_in(manifest_fs_mounts, keys[j]);
            ret = __mount_one_other(mount);
            if (ret < 0)
                goto out;
        }
    }
out:
    free(keys);
    free(lengths);
    return ret;
}

int init_mount_root(void) {
    if (mount_migrated)
        return 0;

    int ret;

    if ((ret = __mount_root()) < 0)
        return ret;

    if ((ret = __mount_sys()) < 0)
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
        log_error("Can't parse 'fs.start_dir'");
        return ret;
    }

    if (fs_start_dir) {
        struct shim_dentry* dent = NULL;
        ret = path_lookupat(/*start=*/NULL, fs_start_dir, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dent);
        free(fs_start_dir);
        if (ret < 0) {
            log_error("Invalid 'fs.start_dir' in manifest.");
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

struct shim_fs* find_fs(const char* name) {
    for (size_t i = 0; i < ARRAY_SIZE(builtin_fs); i++) {
        struct shim_fs* fs = builtin_fs[i];
        if (!strncmp(fs->name, name, sizeof(fs->name)))
            return fs;
    }

    return NULL;
}

static int mount_fs_at_dentry(const char* type, const char* uri, const char* mount_path,
                              struct shim_dentry* mount_point) {
    assert(locked(&g_dcache_lock));
    assert(!mount_point->attached_mount);

    int ret;
    struct shim_fs* fs = find_fs(type);
    if (!fs || !fs->fs_ops || !fs->fs_ops->mount)
        return -ENODEV;

    if (!fs->d_ops || !fs->d_ops->lookup)
        return -ENODEV;

    void* mount_data = NULL;

    /* Call filesystem-specific mount operation */
    if ((ret = fs->fs_ops->mount(uri, &mount_data)) < 0)
        return ret;

    /* Allocate and set up `shim_mount` object */

    struct shim_mount* mount = alloc_mount();
    if (!mount) {
        ret = -ENOMEM;
        goto err;
    }
    memset(mount, 0, sizeof(*mount));

    mount->path = strdup(mount_path);
    if (!mount->path) {
        ret = -ENOMEM;
        goto err;
    }
    if (uri) {
        mount->uri = strdup(uri);
        if (!mount->uri) {
            ret = -ENOMEM;
            goto err;
        }
    } else {
        mount->uri = NULL;
    }
    mount->fs = fs;
    mount->data = mount_data;

    /* Attach mount to mountpoint, and the other way around */

    mount->mount_point = mount_point;
    get_dentry(mount_point);
    mount_point->attached_mount = mount;
    get_mount(mount);

    /* Initialize root dentry of the new filesystem */

    mount->root = get_new_dentry(mount, /*parent=*/NULL, mount_point->name, mount_point->name_len);
    if (!mount->root) {
        ret = -ENOMEM;
        goto err;
    }

    /* Trigger filesystem lookup for the root dentry, so that it's already valid. If there is a
     * problem looking up the root, we want the mount operation to fail. */

    struct shim_dentry* root;
    if ((ret = _path_lookupat(g_dentry_root, mount_path, LOOKUP_NO_FOLLOW, &root))) {
        log_warning("error looking up mount root %s: %d", mount_path, ret);
        goto err;
    }
    assert(root == mount->root);
    put_dentry(root);

    /* Add `mount` to the global list */

    lock(&mount_list_lock);
    LISTP_ADD_TAIL(mount, &mount_list, list);
    get_mount(mount);
    unlock(&mount_list_lock);

    return 0;

err:
    if (mount_point->attached_mount)
        mount_point->attached_mount = NULL;

    if (mount) {
        if (mount->mount_point)
            put_dentry(mount_point);

        if (mount->root)
            put_dentry(mount->root);

        free_mount(mount);
    }

    if (fs->fs_ops->unmount) {
        int ret_unmount = fs->fs_ops->unmount(mount_data);
        if (ret_unmount < 0) {
            log_warning("error unmounting %s: %d", mount_path, ret_unmount);
        }
    }

    return ret;
}

int mount_fs(const char* type, const char* uri, const char* mount_path) {
    int ret;
    struct shim_dentry* mount_point = NULL;

    lock(&g_dcache_lock);

    int lookup_flags = LOOKUP_NO_FOLLOW | LOOKUP_MAKE_SYNTHETIC;
    if ((ret = _path_lookupat(g_dentry_root, mount_path, lookup_flags, &mount_point)) < 0) {
        log_warning("error looking up mountpoint %s: %d", mount_path, ret);
        goto out;
    }

    if ((ret = mount_fs_at_dentry(type, uri, mount_path, mount_point)) < 0)
        goto out;

    ret = 0;
out:
    if (mount_point)
        put_dentry(mount_point);
    unlock(&g_dcache_lock);

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
        if (!mount->uri)
            continue;

        if (strcmp(mount->uri, uri) == 0) {
            size_t path_len = strlen(mount->path);
            if (path_len > longest_path) {
                longest_path = path_len;
                found = mount;
            }
        }
    }

    if (found)
        get_mount(found);

    unlock(&mount_list_lock);
    return found;
}

/*
 * Note that checkpointing the `shim_fs` structure copies it, instead of using a pointer to
 * corresponding global object on the remote side. This does not waste too much memory (because each
 * global object is only copied once), but it means that `shim_fs` objects cannot be compared by
 * pointer.
 */
BEGIN_CP_FUNC(fs) {
    __UNUSED(size);
    assert(size == sizeof(struct shim_fs));

    struct shim_fs* fs = (struct shim_fs*)obj;
    struct shim_fs* new_fs = NULL;

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_fs));
        ADD_TO_CP_MAP(obj, off);

        new_fs = (struct shim_fs*)(base + off);

        memcpy(new_fs->name, fs->name, sizeof(new_fs->name));
        new_fs->fs_ops = NULL;
        new_fs->d_ops = NULL;

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_fs = (struct shim_fs*)(base + off);
    }

    if (objp)
        *objp = (void*)new_fs;
}
END_CP_FUNC(fs)

BEGIN_RS_FUNC(fs) {
    __UNUSED(offset);
    __UNUSED(rebase);
    struct shim_fs* fs = (void*)(base + GET_CP_FUNC_ENTRY());

    struct shim_fs* builtin_fs = find_fs(fs->name);
    if (!builtin_fs)
        return -EINVAL;

    fs->fs_ops = builtin_fs->fs_ops;
    fs->d_ops = builtin_fs->d_ops;
}
END_RS_FUNC(fs)

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
        if (mount->fs->fs_ops && mount->fs->fs_ops->checkpoint) {
            void* cpdata = NULL;
            int bytes = mount->fs->fs_ops->checkpoint(&cpdata, mount->data);
            if (bytes > 0) {
                mount->cpdata = cpdata;
                mount->cpsize = bytes;
            }
        }

        new_mount  = (struct shim_mount*)(base + off);
        *new_mount = *mount;

        DO_CP(fs, mount->fs, &new_mount->fs);

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

        DO_CP_MEMBER(str, mount, new_mount, path);

        if (mount->uri)
            DO_CP_MEMBER(str, mount, new_mount, uri);

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
    CP_REBASE(mount->path);
    CP_REBASE(mount->uri);

    if (mount->mount_point) {
        get_dentry(mount->mount_point);
    }

    if (mount->root) {
        get_dentry(mount->root);
    }

    CP_REBASE(mount->fs);
    if (mount->fs->fs_ops && mount->fs->fs_ops->migrate && mount->cpdata) {
        void* mount_data = NULL;
        if (mount->fs->fs_ops->migrate(mount->cpdata, &mount_data) == 0)
            mount->data = mount_data;
        mount->cpdata = NULL;
    }

    LISTP_ADD_TAIL(mount, &mount_list, list);

    if (mount->path) {
        DEBUG_RS("type=%s,uri=%s,path=%s", mount->type, mount->uri, mount->path);
    } else {
        DEBUG_RS("type=%s,uri=%s", mount->type, mount->uri);
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
