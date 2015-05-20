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
#include <linux_list.h>

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
static LIST_HEAD(mount_list);
static LOCKTYPE mount_list_lock;

int init_fs (void)
{
    mount_mgr = create_mem_mgr(init_align_up(MOUNT_MGR_ALLOC));
    if (!mount_mgr)
        return -ENOMEM;

    create_lock(mount_mgr_lock);
    create_lock(mount_list_lock);

    return init_dcache();
}

static struct shim_mount * alloc_mount (void)
{
    return get_mem_obj_from_mgr_enlarge(mount_mgr,
                                        size_align_up(MOUNT_MGR_ALLOC));
}

static bool mount_migrated = false;

static int __mount_root (void)
{
    const char * root_type = "chroot", * root_uri = "file:";
    int ret;

    if (root_config) {
        char t[CONFIG_MAX], u[CONFIG_MAX];

        if (get_config(root_config, "fs.mount.root.type", t, CONFIG_MAX) > 0)
            root_type = t;
        if (get_config(root_config, "fs.mount.root.uri",  u, CONFIG_MAX) > 0)
            root_uri  = u;
    }

    debug("mounting as %s filesystem: from %s to root\n", root_type, root_uri);

    if ((ret = mount_fs(root_type, root_uri, "/")) < 0) {
        debug("mounting root filesystem failed( %e)\n", ret);
        return ret;
    }

    return 0;
}

static int __mount_sys (void)
{
    int ret;

    debug("mounting as proc filesystem: /proc\n");

    if ((ret = mount_fs("proc", NULL, "/proc")) < 0) {
        debug("mounting proc filesystem failed (%e)\n", ret);
        return ret;
    }

    debug("mounting as dev filesystem: /dev\n");

    if ((ret = mount_fs("dev", NULL, "/dev")) < 0) {
        debug("mounting dev filesystem failed (%e)\n", ret);
        return ret;
    }

    debug("mounting as chroot filesystem: from dev:tty to /dev\n");

    if ((ret = mount_fs("chroot", "dev:tty", "/dev/tty")) < 0) {
        debug("mounting terminal device failed (%e)\n", ret);
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

    memcpy(k, "fs.mount.other.", 15);
    memcpy(k + 15, key, keylen);
    char * kp = k + 15 + keylen;

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

    if ((ret = mount_fs(t, uri, p)) < 0) {
        debug("mounting %s on %s (type=%s) failed (%e)\n", t, uri, p,
              -ret);
        return ret;
    }

    return 0;
}

static int __mount_others (void)
{
    if (!root_config)
        return 0;

    int nkeys, keybuf_size = CONFIG_MAX;
    char * keybuf = __alloca(keybuf_size);

    while ((nkeys = get_config_entries(root_config, "fs.mount.other", keybuf,
                                       keybuf_size)) == -ENAMETOOLONG) {
        keybuf = __alloca(keybuf_size);
        keybuf_size *= 2;
    }

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

    if ((ret = __mount_root()) < 0)
        return ret;

    if ((ret = __mount_sys()) < 0)
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
        mount_root = get_new_dentry(NULL, "", 0);
        mount_root->fs = mount;
        /* mount_root->state |= DENTRY_VALID; */
        qstrsetstr(&mount_root->name, dentry_get_name(dent),
                   dent->name.len);

        if (mount->d_ops && mount->d_ops->lookup &&
            (ret = mount->d_ops->lookup(mount_root, 0)) < 0 &&
            ret != -ESKIPPED)
            return ret;

        mount->root = mount_root;
    }

    mount_root->state |= dent->state & (DENTRY_REACHABLE|DENTRY_UNREACHABLE);
    __add_dcache(mount_root, &mount->path.hash);

    if ((ret = __del_dentry_tree(dent)) < 0)
        return ret;

    lock(mount_list_lock);
    get_mount(mount);
    list_add_tail(&mount->list, &mount_list);
    unlock(mount_list_lock);

    do {
        struct shim_dentry * parent = dent->parent;

        if (dent->state & DENTRY_ANCESTER) {
            put_dentry(dent);
            break;
        }

        dent->state |= DENTRY_ANCESTER;
        if (parent)
            get_dentry(parent);
        put_dentry(dent);
        dent = parent;
    } while (dent);

    return 0;
}

int mount_fs (const char * type, const char * uri, const char * mount_point)
{
    int ret = 0;
    struct shim_fs * fs = find_fs(type);

    if (!fs || !fs->fs_ops || !fs->fs_ops->mount) {
        ret = -ENODEV;
        goto out;
    }

    lock(dcache_lock);

    struct shim_dentry * dent;
    if ((ret = __path_lookupat(NULL, mount_point, 0, &dent)) < 0)
        goto out;

    struct shim_mount * mount = alloc_mount();
    void * mount_data = NULL;

    /* call fs-specific mount to allocate mount_data */
    if ((ret = fs->fs_ops->mount(uri, mount_point, &mount_data)) < 0)
        goto out;

    int uri_len = uri ? strlen(uri) : 0;
    qstrsetstr(&mount->path, mount_point, strlen(mount_point));
    qstrsetstr(&mount->uri, uri, uri_len);
    memcpy(mount->type, fs->name, sizeof(fs->name));
    mount->fs_ops    = fs->fs_ops;
    mount->d_ops     = fs->d_ops;
    mount->data      = mount_data;
    mount->path.hash = dent->rel_path.hash;

    ret = __mount_fs(mount, dent);
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

    list_for_each_entry_safe(mount, n, &mount_list, list) {
        if ((ret = (*walk) (mount, arg)) < 0)
            break;

        if (ret > 0)
            nsrched++;
    }

    unlock(mount_list_lock);
    return ret < 0 ? ret : (nsrched ? 0 : -ESRCH);
}

DEFINE_MIGRATE_FUNC(mount)

MIGRATE_FUNC_BODY(mount)
{
    assert(size == sizeof(struct shim_mount));

    struct shim_mount * mount = (struct shim_mount *) obj;
    struct shim_mount * new_mount = NULL;

    unsigned long off = ADD_TO_MIGRATE_MAP(obj, *offset,
                                           sizeof(struct shim_mount));

    if (ENTRY_JUST_CREATED(off)) {
        off = ADD_OFFSET(sizeof(struct shim_mount));

        if (dry) {
            mount->cpdata = NULL;
            mount->cpsize = 0;

            if (mount->fs_ops &&
                mount->fs_ops->checkpoint) {
                void * cpdata = NULL;
                int bytes = mount->fs_ops->checkpoint(&cpdata, mount->data);
                if (bytes > 0 && cpdata) {
                    mount->cpdata = cpdata;
                    mount->cpsize = bytes;
                    ADD_OFFSET(bytes);
                }
            }
        } else {
            new_mount = (struct shim_mount *) (base + off);
            memcpy(new_mount, mount, sizeof(struct shim_mount));

            if (mount->cpdata) {
                ADD_OFFSET(mount->cpsize);
                new_mount->cpdata = (void *) (base + *offset);
                memcpy(new_mount->cpdata, mount->cpdata, mount->cpsize);
            }

            new_mount->data = NULL;
            new_mount->mount_point = NULL;
            new_mount->root = NULL;
            INIT_LIST_HEAD(&new_mount->list);
        }

        DO_MIGRATE_IN_MEMBER(qstr, mount, new_mount, path, false);
        DO_MIGRATE_IN_MEMBER(qstr, mount, new_mount, uri,  false);

        ADD_FUNC_ENTRY(off);
        ADD_ENTRY(SIZE, sizeof(struct shim_mount));

    } else if (!dry) {
        new_mount = (struct shim_mount *) (base + off);
    }

    if (new_mount && objp)
        *objp = (void *) new_mount;
}
END_MIGRATE_FUNC

RESUME_FUNC_BODY(mount)
{
    unsigned long off = GET_FUNC_ENTRY();
    assert((size_t) GET_ENTRY(SIZE) == sizeof(struct shim_mount));
    struct shim_mount * mount = (struct shim_mount *) (base + off);

    RESUME_REBASE(mount->cpdata);
    RESUME_REBASE(mount->list);

    struct shim_fs * fs = find_fs(mount->type);

    if (fs && fs->fs_ops && fs->fs_ops->migrate && mount->cpdata) {
        void * mount_data = NULL;
        if (fs->fs_ops->migrate(mount->cpdata, &mount_data) == 0)
            mount->data = mount_data;
        mount->cpdata = NULL;
    }

    mount->fs_ops = fs->fs_ops;
    mount->d_ops = fs->d_ops;

    if (!qstrempty(&mount->path)) {
        struct shim_dentry * dent = NULL;
        const char * mount_point = qstrgetstr(&mount->path);

        int err = path_lookupat(NULL, mount_point, 0, &dent);

        if (!err && dent) {
            err = __mount_fs(mount, dent);
            assert(err == 0);
        }

#ifdef DEBUG_RESUME
        debug("mount: type=%s,uri=%s,path=%s\n", mount->type,
              qstrgetstr(&mount->uri), mount_point);
#endif
    }
#ifdef DEBUG_RESUME
    else {
        debug("mount: type=%s,uri=%s\n", mount->type,
              qstrgetstr(&mount->uri));
    }
#endif
}
END_RESUME_FUNC

DEFINE_MIGRATE_FUNC(all_mounts)

MIGRATE_FUNC_BODY(all_mounts)
{
    struct shim_mount * mount;

    lock(mount_list_lock);
    list_for_each_entry(mount, &mount_list, list)
        DO_MIGRATE(mount, mount, NULL, recursive);

    unlock(mount_list_lock);

    /* add an empty entry to mark as migrated */
    ADD_FUNC_ENTRY(0);
}
END_MIGRATE_FUNC

RESUME_FUNC_BODY(all_mounts)
{
    GET_FUNC_ENTRY();
    /* to prevent file system from being mount again */
    mount_migrated = true;
}
END_RESUME_FUNC

const char * get_file_name (const char * path, size_t len)
{
    const char * c = path + len - 1;
    while (c > path && *c != '/')
        c--;
    return *c == '/' ? c + 1 : c;
}

int get_abs_path (const char * cwd, const char * path, char * buf, int size)
{
    int cnt = 0;
    char c, c1;
    const char * p = path;

    if (*p != '/') {
        cnt = strlen(cwd);
        while (cnt >= 0 && cwd[cnt - 1] == '/')
            cnt--;
        memcpy(buf, cwd, cnt);
    }

    for (c = '/' ; c ; c = c1, p++) {
        c1 = *p;
        if (c == '/') {
            if (c1 == 0)
                break;
            if (c1 == '/')
                continue;
            if (c1 == '.') {
                c1 = *(++p);
                if (c1 == 0)
                    break;
                if (c1 == '/')
                    continue;
                if (c1 == '.') {
                    c1 = *(++p);
                    if (c1 == 0) {
                        while (cnt > 0 && buf[--cnt] != '/');
                        break;
                    }
                    if (c1 == '/') {
                        while (cnt > 0 && buf[--cnt] != '/');
                        continue;
                    }
                    return -EINVAL;
                }
                if (cnt >= size-1)
                    return -ENAMETOOLONG;
                buf[cnt++] = c;
                c = '.';
            }
        }
        if (cnt >= size-1)
            return -ENAMETOOLONG;
        buf[cnt++] = c;
    }

    if (cnt) {
        buf[cnt] = 0;
    } else {
        buf[0] = '/';
        buf[1] = 0;
    }

    return cnt;
}

int get_norm_path (const char * path, char * buf, int size)
{
    int cnt = 0;
    char c, c1;
    const char * p = path;

    for (c = '/' ; c ; c = c1, p++) {
        c1 = *p;
        if (c == '/') {
            if (c1 == 0)
                break;
            if (c1 == '/')
                continue;
            if (c1 == '.') {
                c1 = *(++p);
                if (c1 == 0)
                    break;
                if (c1 == '/')
                    continue;
                if (c1 == '.') {
                    c1 = *(++p);
                    if (c1 != 0 && c1 != '/')
                        return -EINVAL;
                    if (cnt) {
                        while (cnt > 0 && buf[--cnt] != '/');
                    } else {
                        if (cnt >= size-2)
                            return -ENAMETOOLONG;
                        buf[cnt++] = '.';
                        buf[cnt++] = '.';
                    }
                    c = c1;
                    continue;
                }
                if (cnt || c != '/') {
                    if (cnt >= size-1)
                        return -ENAMETOOLONG;
                    buf[cnt++] = c;
                }
                c = '.';
            }
        }
        if (cnt || c != '/') {
            if (cnt >= size-1)
                return -ENAMETOOLONG;
            buf[cnt++] = c;
        }
    }

    buf[cnt] = 0;
    return cnt;
}
