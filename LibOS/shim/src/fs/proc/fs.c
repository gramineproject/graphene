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
 * fs.c
 *
 * This file contains codes for implementation of 'proc' filesystem.
 */

#include <shim_internal.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_fs.h>
#include <shim_utils.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>

#include <linux/stat.h>
#include <linux/fcntl.h>

#include <asm/fcntl.h>
#include <asm/mman.h>
#include <asm/unistd.h>
#include <asm/prctl.h>

extern const struct proc_nm_ops nm_thread;
extern const struct proc_fs_ops fs_thread;
extern const struct proc_dir dir_thread;
extern const struct proc_nm_ops nm_ipc_thread;
extern const struct proc_fs_ops fs_ipc_thread;
extern const struct proc_dir dir_ipc_thread;
extern const struct proc_fs_ops fs_meminfo;
extern const struct proc_fs_ops fs_cpuinfo;

const struct proc_dir proc_root = {
    .size = 5,
    .ent = {
        { .name = "self", .fs_ops = &fs_thread, .dir = &dir_thread, },
        { .nm_ops = &nm_thread, .fs_ops = &fs_thread, .dir = &dir_thread, },
        { .nm_ops = &nm_ipc_thread, .fs_ops = &fs_ipc_thread,
          .dir = &dir_ipc_thread, },
        { .name = "meminfo", .fs_ops = &fs_meminfo, },
        { .name = "cpuinfo", .fs_ops = &fs_cpuinfo, },
    }, };

#define PROC_INO_BASE      1

static int proc_root_mode (const char * name, mode_t * mode)
{
    *mode = 0555;
    return 0;
}

static int proc_root_stat (const char * name, struct stat * buf)
{
    memset(buf, 0, sizeof(struct stat));

    buf->st_dev = buf->st_ino = 1;
    buf->st_mode = 0555|S_IFDIR;
    buf->st_uid = 0;
    buf->st_gid = 0;
    buf->st_size = 4096;

    return 0;
}

struct proc_fs_ops fs_proc_root = {
        .mode     = &proc_root_mode,
        .stat     = &proc_root_stat,
    };

const struct proc_ent proc_root_ent =
    { .name = "", .fs_ops = &fs_proc_root, .dir = &proc_root, };

static inline int token_len (const char * str, const char ** next_str)
{
    const char * t = str;

    while (*t && *t != '/')
        t++;

    if (next_str)
        *next_str = *t ? t + 1 : NULL;

    return t - str;
}

static int proc_match_name (const char * trim_name,
                            const struct proc_ent ** ent)
{
    if (!trim_name || !trim_name[0]) {
        *ent = &proc_root_ent;
        return 0;
    }

    const char * token = trim_name, * next_token;
    const struct proc_ent * tmp = proc_root.ent;
    const struct proc_ent * last = NULL;

    if (*token == '/')
        token++;

    while (token) {
        int tlen = token_len(token, &next_token);

        for ( ; tmp->name || tmp->nm_ops ; tmp++) {
            if (tmp->name && !memcmp(tmp->name, token, tlen))
                goto found;

            if (tmp->nm_ops && tmp->nm_ops->match_name &&
                tmp->nm_ops->match_name(trim_name))
                goto found;
        }

        return -ENOENT;

found:
        if (!tmp->dir && next_token)
            return -ENOENT;

        last = tmp;
        tmp = tmp->dir->ent;
        token = next_token;
    }

    *ent = last;
    return 0;
}

static int proc_mode (struct shim_dentry * dent, mode_t * mode, bool force)
{
    if (qstrempty(&dent->rel_path)) {
        dent->ino = PROC_INO_BASE;
        *mode = 0555|S_IFDIR;
        return 0;
    }

    /* don't care about forced or not */
    const char * rel_path = qstrgetstr(&dent->rel_path);
    const struct proc_ent * ent;
    int ret = proc_match_name(rel_path, &ent);

    if (ret < 0)
        return ret;

    if (!ent->fs_ops || !ent->fs_ops->mode)
        return -EACCES;

    return ent->fs_ops->mode(rel_path, mode);
}

static int proc_lookup (struct shim_dentry * dent, bool force)
{
    if (qstrempty(&dent->rel_path)) {
        dent->ino = PROC_INO_BASE;
        dent->state |= DENTRY_ISDIRECTORY;
        return 0;
    }

    /* don't care about forced or not */
    const struct proc_ent * ent = NULL;
    int ret = proc_match_name(qstrgetstr(&dent->rel_path), &ent);

    if (!ret && ent->dir)
        dent->state |= DENTRY_ISDIRECTORY;

    if (ent && ent->fs_ops && ent->fs_ops->follow_link)
        dent->state |= DENTRY_ISLINK;

     return ret;
}

static int proc_mount (const char * uri, const char * root, void ** mount_data)
{
    /* do nothing */
    return 0;
}

static int proc_unmount (void * mount_data)
{
    /* do nothing */
    return 0;
}

static int proc_open (struct shim_handle * hdl, struct shim_dentry * dent,
                      int flags)
{
    const char * rel_path = qstrgetstr(&dent->rel_path);

    if (flags & (O_CREAT|O_EXCL))
        return -EACCES;

    const struct proc_ent * ent;
    int ret;

    if ((ret = proc_match_name(rel_path, &ent)) < 0)
        return ret;

    if (ent->dir)
        return -EISDIR;

    if (!ent->fs_ops || !ent->fs_ops->open)
        return -EACCES;

    hdl->flags = flags;

    return ent->fs_ops->open(hdl, rel_path, flags);
}

static int proc_readdir (struct shim_dentry * dent,
                         struct shim_dirent ** dirent)
{
    const char * rel_path = qstrgetstr(&dent->rel_path);
    const struct proc_ent * ent;
    int ret;

    if ((ret = proc_match_name(rel_path, &ent)) < 0)
        return ret;

    if (!ent->dir)
        return -ENOTDIR;

    const struct proc_ent * tmp = ent->dir->ent;
    const struct proc_ent * end = tmp + ent->dir->size;

    HASHTYPE self_hash = hash_path(rel_path,
                                   dent->rel_path.len, NULL);
    HASHTYPE new_hash;
    struct shim_dirent * buf, * ptr;
    int buf_size = MAX_PATH;

retry:
    buf = malloc(buf_size);
    *dirent = ptr = buf;
    struct shim_dirent ** last = dirent;

    for ( ; tmp < end ; tmp++) {
        if (tmp->name) {
            int name_len = strlen(tmp->name);

            if ((void *) (ptr + 1) + name_len + 1 > (void *) buf + buf_size)
                goto enlarge;

            new_hash = rehash_name(self_hash,
                                   tmp->name, name_len);

            ptr->next = (void *) (ptr + 1) + name_len + 1;
            ptr->ino = new_hash;
            ptr->type = tmp->dir ? LINUX_DT_DIR : (
                        tmp->fs_ops && tmp->fs_ops->follow_link ?
                        LINUX_DT_LNK : LINUX_DT_REG);
            memcpy(ptr->name, tmp->name, name_len + 1);
            last = &ptr->next;
            ptr = *last;
            continue;
        }

        if (tmp->nm_ops && tmp->nm_ops->list_name) {
            struct shim_dirent * d = ptr;
            int ret = tmp->nm_ops->list_name(rel_path,
                                             &ptr,
                                             (void *) buf + buf_size -
                                             (void *) ptr);

            if (ret == -ENOBUFS)
                goto enlarge;

            if (ret < 0)
                ptr = d;
            else
                for ( ; d && d != ptr ; d = d->next)
                    last = &d->next;
            continue;
        }
    }

    *last = NULL;
    if (!(*dirent))
        free(buf);
    return 0;

enlarge:
    buf_size *= 2;
    free(buf);
    goto retry;
}

static int proc_stat (struct shim_dentry * dent, struct stat * buf)
{
    const char * rel_path = qstrgetstr(&dent->rel_path);
    const struct proc_ent * ent;
    int ret;

    if ((ret = proc_match_name(rel_path, &ent)) < 0)
        return ret;

    if (!ent->fs_ops || !ent->fs_ops->stat)
        return -EACCES;

    return ent->fs_ops->stat(rel_path, buf);
}

static int proc_follow_link (struct shim_dentry * dent,
                             struct shim_qstr * link)
{
    const char * rel_path = qstrgetstr(&dent->rel_path);
    const struct proc_ent * ent;
    int ret;

    if ((ret = proc_match_name(rel_path, &ent)) < 0)
        return ret;

    if (!ent->fs_ops || !ent->fs_ops->follow_link)
        return -EINVAL;

    return ent->fs_ops->follow_link(rel_path, link);
}

static int proc_hstat (struct shim_handle * hdl, struct stat * buf)
{
    struct shim_dentry * dent = hdl->dentry;
    assert(dent);

    const char * rel_path = qstrgetstr(&dent->rel_path);
    const struct proc_ent * ent;
    int ret;

    if ((ret = proc_match_name(rel_path, &ent)) < 0)
        return ret;

    if (!ent->fs_ops || !ent->fs_ops->stat)
        return -EACCES;

    return ent->fs_ops->stat(rel_path, buf);
}

struct shim_fs_ops proc_fs_ops = {
        .mount          = &proc_mount,
        .unmount        = &proc_unmount,
        .close          = &str_close,
        .read           = &str_read,
        .write          = &str_write,
        .seek           = &str_seek,
        .flush          = &str_flush,
        .hstat          = &proc_hstat,
    };

struct shim_d_ops proc_d_ops = {
        .open           = &proc_open,
        .stat           = &proc_stat,
        .mode           = &proc_mode,
        .lookup         = &proc_lookup,
        .follow_link    = &proc_follow_link,
        .readdir        = &proc_readdir,
    };
