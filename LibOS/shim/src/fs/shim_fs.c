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
 * shim_fs.c
 *
 * This file contains codes for creating filesystems in library OS.
 */

#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_fs.h>
#include <shim_checkpoint.h>

#include <pal.h>
#include <pal_error.h>
#include <pal_debug.h>
#include <list.h>

#include <linux/fcntl.h>

struct shim_fs {
    char name[8];
    struct shim_fs_ops * fs_ops;
    struct shim_d_ops * d_ops;
};

#define NUM_MOUNTABLE_FS    3

struct shim_fs mountable_fs [NUM_MOUNTABLE_FS] = {
        { .name = "chroot", .fs_ops = &chroot_fs_ops, .d_ops = &chroot_d_ops, },
        { .name = "proc",   .fs_ops = &proc_fs_ops,   .d_ops = &proc_d_ops,   },
        { .name = "dev",    .fs_ops = &dev_fs_ops,    .d_ops = &dev_d_ops,    },
    };

#define NUM_BUILTIN_FS      4

struct shim_mount * builtin_fs [NUM_BUILTIN_FS] = {
                &chroot_builtin_fs,
                &pipe_builtin_fs,
                &socket_builtin_fs,
                &epoll_builtin_fs,
        };

static LOCKTYPE mount_mgr_lock;

#define system_lock()       lock(mount_mgr_lock)
#define system_unlock()     unlock(mount_mgr_lock)

#define MOUNT_MGR_ALLOC     64
#define PAGE_SIZE           allocsize

#define OBJ_TYPE struct shim_mount
#include <memmgr.h>

static MEM_MGR mount_mgr = NULL;
DEFINE_LISTP(shim_mount);
/* Links to mount->list */
static LISTP_TYPE(shim_mount) mount_list;
static LOCKTYPE mount_list_lock;

int init_fs (void)
{
    mount_mgr = create_mem_mgr(init_align_up(MOUNT_MGR_ALLOC));
    if (!mount_mgr)
        return -ENOMEM;

    create_lock(mount_mgr_lock);
    create_lock(mount_list_lock);
    return 0;
}

static struct shim_mount * alloc_mount (void)
{
    return get_mem_obj_from_mgr_enlarge(mount_mgr,
                                        size_align_up(MOUNT_MGR_ALLOC));
}

static bool mount_migrated = false;

static int __mount_root (struct shim_dentry ** root)
{
    char type[CONFIG_MAX], uri[CONFIG_MAX];
    int ret = 0;

    if (root_config &&
            get_config(root_config, "fs.root.type", type, CONFIG_MAX) > 0 &&
            get_config(root_config, "fs.root.uri", uri, CONFIG_MAX) > 0) {
        debug("mounting root filesystem: %s from %s\n", type, uri);
        if ((ret = mount_fs(type, uri, "/", NULL, root, 0)) < 0) {
            debug("mounting root filesystem failed (%d)\n", ret);
            goto out;
        }
        goto out;
    }

    debug("mounting default root filesystem\n");
    if ((ret = mount_fs("chroot", "file:", "/", NULL, root, 0)) < 0) {
        debug("mounting root filesystem failed (%d)\n", ret);
        goto out;
    }

out:
    return ret;
}

static int __mount_sys (struct shim_dentry *root)
{
    int ret;

    debug("mounting as proc filesystem: /proc\n");

    if ((ret = mount_fs("proc", NULL, "/proc", root, NULL, 0)) < 0) {
        debug("mounting proc filesystem failed (%d)\n", ret);
        return ret;
    }

    debug("mounting as dev filesystem: /dev\n");

    struct shim_dentry *dev_dent = NULL;
    if ((ret = mount_fs("dev", NULL, "/dev", root, &dev_dent, 0)) < 0) {
        debug("mounting dev filesystem failed (%d)\n", ret);
        return ret;
    }

    debug("mounting as chroot filesystem: from dev:tty to /dev\n");

    if ((ret = mount_fs("chroot", "dev:tty", "/dev/tty", dev_dent, NULL, 0)) < 0) {
        debug("mounting terminal device failed (%d)\n", ret);
        return ret;
    }

    return 0;
}

static int __mount_one_other (const char * key, int keylen)
{
    if (!root_config)
        return 0;

    char k[CONFIG_MAX], p[CONFIG_MAX], u[CONFIG_MAX],
         t[CONFIG_MAX];
    char * uri = NULL;
    int ret;

    memcpy(k, "fs.mount.", 9);
    memcpy(k + 9, key, keylen);
    char * kp = k + 9 + keylen;

    memcpy(kp, ".path", 6);
    if (get_config(root_config, k, p, CONFIG_MAX) <= 0)
        return -EINVAL;

    memcpy(kp, ".type", 6);
    if (get_config(root_config, k, t, CONFIG_MAX) <= 0)
        return -EINVAL;

    memcpy(kp, ".uri", 5);
    if (get_config(root_config, k, u, CONFIG_MAX) > 0)
        uri = u;

    debug("mounting as %s filesystem: from %s to %s\n", t, uri, p);

    if ((ret = mount_fs(t, uri, p, NULL, NULL, 1)) < 0) {
        debug("mounting %s on %s (type=%s) failed (%e)\n", uri, p, t,
              -ret);
        return ret;
    }

    return 0;
}

static int __mount_others (void)
{
    if (!root_config)
        return 0;

    int nkeys;
    ssize_t keybuf_size;
    keybuf_size = get_config_entries_size(root_config, "fs.mount");
    if (keybuf_size < 0)
        return 0;

    char * keybuf = __alloca(keybuf_size);
    nkeys = get_config_entries(root_config, "fs.mount", keybuf, keybuf_size);

    if (nkeys < 0)
        return 0;

    const char * key = keybuf, * next = NULL;
    for (int n = 0 ; n < nkeys ; key = next, n++) {
        for (next = key ; *next ; next++);
        next++;
        int ret = __mount_one_other(key, next - key - 1);
        if (ret < 0)
            return ret;
    }

    return 0;
}

int init_mount_root (void)
{
    if (mount_migrated)
        return 0;

    int ret;
    struct shim_dentry *root = NULL;
    
    if ((ret = __mount_root(&root)) < 0)
        return ret;

    if ((ret = __mount_sys(root)) < 0)
        return ret;

    return 0;
}

int init_mount (void)
{
    if (mount_migrated)
        return 0;

    int ret;

    if ((ret = __mount_others()) < 0)
        return ret;

    return 0;
}

static inline struct shim_fs * find_fs (const char * type)
{
    struct shim_fs * fs = NULL;
    int len = strlen(type);

    for (int i = 0 ; i < NUM_MOUNTABLE_FS ; i++)
        if (!memcmp(type, mountable_fs[i].name, len + 1)) {
            fs = &mountable_fs[i];
            break;
        }

    return fs;
}

int search_builtin_fs (const char * type, struct shim_mount ** fs)
{
    int len = strlen(type);

    for (int i = 0 ; i < NUM_BUILTIN_FS ; i++)
        if (!memcmp(type, builtin_fs[i]->type, len + 1)) {
            *fs = builtin_fs[i];
            return 0;
        }

    return -ENOENT;
}

int __mount_fs (struct shim_mount * mount, struct shim_dentry * dent)
{
    int ret = 0;

    dent->state |= DENTRY_MOUNTPOINT;
    get_dentry(dent);
    mount->mount_point = dent;
    dent->mounted = mount;

    struct shim_dentry * mount_root = mount->root;

    if (!mount_root) {
        /* mount_root->state |= DENTRY_VALID; */
        mount_root = get_new_dentry(mount, NULL, "", 0, NULL);
        assert(mount->d_ops && mount->d_ops->lookup);
        ret = mount->d_ops->lookup(mount_root, 0);
        if (ret < 0) {
            /* Try getting rid of ESKIPPED case */
            assert (ret != -ESKIPPED);
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
    //mount_root->state |= dent->state & (DENTRY_REACHABLE|DENTRY_UNREACHABLE);

    /* DEP 6/16/17: In the dcache redesign, I don't believe we need to manually
     * rehash the path; this should be handled by get_new_dentry, or already be 
     * hashed if mount_root exists.  I'm going to leave this line here for now
     * as documentation in case there is a problem later.
     */
    //__add_dcache(mount_root, &mount->path.hash);

    if ((ret = __del_dentry_tree(dent)) < 0)
        return ret;

    lock(mount_list_lock);
    get_mount(mount);
    listp_add_tail(mount, &mount_list, list);
    unlock(mount_list_lock);

    do {
        struct shim_dentry * parent = dent->parent;

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

/* Parent is optional, but helpful.
 * dentp (optional) memoizes the dentry of the newly-mounted FS, on success. 
 *
 * The make_ancestor flag creates pseudo-dentries for any missing paths (passed to
 * __path_lookupat).  This is only intended for use to connect mounts specified in the manifest
 * when an intervening path is missing.
 */
int mount_fs (const char * type, const char * uri, const char * mount_point,
              struct shim_dentry *parent, struct shim_dentry **dentp,
              int make_ancestor)
{
    int ret = 0;
    struct shim_fs * fs = find_fs(type);

    if (!fs || !fs->fs_ops || !fs->fs_ops->mount) {
        ret = -ENODEV;
        goto out;
    }

    /* Split the mount point into the prefix and atom */
    int mount_point_len = strlen(mount_point);
    const char * last = &mount_point[mount_point_len - 1];
    int left = mount_point_len;
    int last_len = 1;
    // Drop any trailing slashes
    while (left && *last == '/') {
        left--;
        last--;
        if (last_len != 0)
            last_len--;
    }
    // Skip the atom
    while (left && *last != '/') {
        left--;
        last--;
        last_len++;
    }
    if (*last == '/') {
        // Move forward one
        last++;
        last_len--;
    }

    if (!parent) {
        // See if we are not at the root mount
        if (mount_point_len != 1 || mount_point[0] != '/') {
            // Look up the parent
            char * parent_path = __alloca(mount_point_len);
            memset(parent_path, 0, mount_point_len);
            assert(last_len >= 1 && (mount_point_len - last_len) >= 0);
            memcpy(parent_path, mount_point, mount_point_len - last_len);
            if ((ret = __path_lookupat(dentry_root, parent_path, 0, &parent, 0,
                                       dentry_root->fs, make_ancestor)) < 0) {
                debug("Path lookup failed %d\n", ret);
                goto out;
            }
        }
    }
    
    lock(dcache_lock);

    struct shim_mount * mount = alloc_mount();
    void * mount_data = NULL;

    /* call fs-specific mount to allocate mount_data */
    if ((ret = fs->fs_ops->mount(uri, mount_point, &mount_data)) < 0)
        goto out;


    int uri_len = uri ? strlen(uri) : 0;
    qstrsetstr(&mount->path, mount_point, mount_point_len);
    qstrsetstr(&mount->uri, uri, uri_len);
    memcpy(mount->type, fs->name, sizeof(fs->name));
    mount->fs_ops    = fs->fs_ops;
    mount->d_ops     = fs->d_ops;
    mount->data      = mount_data;

    /* Get the negative dentry from the cache, if one exists */
    struct shim_dentry * dent, *dent2;
    /* Special case the root */
    if (mount_point_len == 1 && mount_point[0] == '/')
        dent = dentry_root;
    else {
        dent = __lookup_dcache(parent, last,
                               last_len,
                               NULL, 0, NULL);

        if(!dent) {
            dent = get_new_dentry(mount, parent, last, last_len, NULL);
            get_dentry(dent);
        }
    }
    
    assert(dent == dentry_root || !(dent->state & DENTRY_VALID));    

    // We need to fix up the relative path to this mount, but only for
    // directories.  
    qstrsetstr(&dent->rel_path, "", 0);
    mount->path.hash = dent->rel_path.hash;

    /*Now go ahead and do a lookup so the dentry is valid */
    if ((ret = __path_lookupat(dentry_root, mount_point, 0, &dent2, 0,
                               parent ? parent->fs : mount, make_ancestor)) < 0) 
        goto out;

    assert(dent == dent2);

    /* We want the net impact of mounting to increment the ref count on the
     * entry (until the unmount).  But we shouldn't also hold the reference on
     * dent from the validation step.  Drop it here */
    put_dentry(dent2);

    ret = __mount_fs(mount, dent);

    // If we made it this far and the dentry is still negative, clear
    // the negative flag from the denry. 
    if ((!ret) && (dent->state & DENTRY_NEGATIVE)) 
        dent->state &= ~DENTRY_NEGATIVE;
    
    /* Set the file system at the mount point properly */
    dent->fs = mount;
    
    if (dentp && !ret)
        *dentp = dent;
out:
    unlock(dcache_lock);
    return ret;
}

void get_mount (struct shim_mount * mount)
{
    REF_INC(mount->ref_count);
}

void put_mount (struct shim_mount * mount)
{
    REF_DEC(mount->ref_count);
}

int walk_mounts (int (*walk) (struct shim_mount * mount, void * arg),
                 void * arg)
{
    struct shim_mount * mount, * n;
    int ret;
    int nsrched = 0;

    lock(mount_list_lock);

    listp_for_each_entry_safe(mount, n, &mount_list, list) {
        if ((ret = (*walk) (mount, arg)) < 0)
            break;

        if (ret > 0)
            nsrched++;
    }

    unlock(mount_list_lock);
    return ret < 0 ? ret : (nsrched ? 0 : -ESRCH);
}

struct shim_mount * find_mount_from_uri (const char * uri)
{
    struct shim_mount * mount, * found = NULL;
    int longest_path = 0;

    lock(mount_list_lock);
    listp_for_each_entry(mount, &mount_list, list) {
        if (qstrempty(&mount->uri))
            continue;

        if (!memcmp(qstrgetstr(&mount->uri), uri, mount->uri.len) &&
            (uri[mount->uri.len] == '/' || uri[mount->uri.len] == '/')) {
            if (mount->path.len > longest_path) {
                longest_path = mount->path.len;
                found = mount;
            }
        }
    }

    if (found)
        get_mount(found);

    unlock(mount_list_lock);
    return found;
}

BEGIN_CP_FUNC(mount)
{
    assert(size == sizeof(struct shim_mount));

    struct shim_mount * mount = (struct shim_mount *) obj;
    struct shim_mount * new_mount = NULL;

    ptr_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_mount));
        ADD_TO_CP_MAP(obj, off);

        if (!mount->cpdata &&
            mount->fs_ops &&
            mount->fs_ops->checkpoint) {
            void * cpdata = NULL;
            int bytes = mount->fs_ops->checkpoint(&cpdata, mount->data);
            if (bytes > 0) {
                mount->cpdata = cpdata;
                mount->cpsize = bytes;
            }
        }

        new_mount = (struct shim_mount *) (base + off);
        *new_mount = *mount;

        if (mount->cpdata) {
            struct shim_mem_entry * entry;
            DO_CP_SIZE(memory, mount->cpdata, mount->cpsize, &entry);
            new_mount->cpdata = NULL;
            entry->paddr = &new_mount->cpdata;
        }

        new_mount->data = NULL;
        new_mount->mount_point = NULL;
        new_mount->root = NULL;
        INIT_LIST_HEAD(new_mount, list);

        DO_CP_IN_MEMBER(qstr, new_mount, path);
        DO_CP_IN_MEMBER(qstr, new_mount, uri);

        if (mount->mount_point)
            DO_CP_MEMBER(dentry, mount, new_mount, mount_point);

        if (mount->root)
            DO_CP_MEMBER(dentry, mount, new_mount, root);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_mount = (struct shim_mount *) (base + off);
    }

    if (objp)
        *objp = (void *) new_mount;
}
END_CP_FUNC(mount)

BEGIN_RS_FUNC(mount)
{
    struct shim_mount * mount = (void *) (base + GET_CP_FUNC_ENTRY());

    CP_REBASE(mount->cpdata);
    CP_REBASE(mount->list);
    CP_REBASE(mount->mount_point);
    CP_REBASE(mount->root);

    struct shim_fs * fs = find_fs(mount->type);

    if (fs && fs->fs_ops && fs->fs_ops->migrate && mount->cpdata) {
        void * mount_data = NULL;
        if (fs->fs_ops->migrate(mount->cpdata, &mount_data) == 0)
            mount->data = mount_data;
        mount->cpdata = NULL;
    }

    mount->fs_ops = fs->fs_ops;
    mount->d_ops = fs->d_ops;

    listp_add_tail(mount, &mount_list, list);

    if (!qstrempty(&mount->path)) {
        DEBUG_RS("type=%s,uri=%s,path=%s", mount->type, qstrgetstr(&mount->uri),
                 qstrgetstr(&mount->path));
    } else {
        DEBUG_RS("type=%s,uri=%s", mount->type, qstrgetstr(&mount->uri));
    }
}
END_RS_FUNC(mount)

BEGIN_CP_FUNC(all_mounts)
{
    struct shim_mount * mount;
    lock(mount_list_lock);
    listp_for_each_entry(mount, &mount_list, list)
        DO_CP(mount, mount, NULL);
    unlock(mount_list_lock);

    /* add an empty entry to mark as migrated */
    ADD_CP_FUNC_ENTRY(0);
}
END_CP_FUNC(all_mounts)

BEGIN_RS_FUNC(all_mounts)
{
    /* to prevent file system from being mount again */
    mount_migrated = true;
}
END_RS_FUNC(all_mounts)

const char * get_file_name (const char * path, size_t len)
{
    const char * c = path + len - 1;
    while (c > path && *c != '/')
        c--;
    return *c == '/' ? c + 1 : c;
}
