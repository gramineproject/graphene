/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system calls "stat", "lstat", "fstat" and "readlink".
 */

#include <errno.h>
#include <linux/fcntl.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_process.h"
#include "shim_table.h"

long shim_do_stat(const char* file, struct stat* stat) {
    if (!file || test_user_string(file))
        return -EFAULT;

    if (!stat || test_user_memory(stat, sizeof(*stat), true))
        return -EFAULT;

    int ret;
    struct shim_dentry* dent = NULL;

    if ((ret = path_lookupat(NULL, file, LOOKUP_ACCESS | LOOKUP_FOLLOW, &dent, NULL)) < 0)
        goto out;

    struct shim_mount* fs = dent->fs;

    if (!fs->d_ops || !fs->d_ops->stat) {
        ret = -EACCES;
        goto out_dentry;
    }

    ret = fs->d_ops->stat(dent, stat);
out_dentry:
    put_dentry(dent);
out:
    return ret;
}

long shim_do_lstat(const char* file, struct stat* stat) {
    if (!file || test_user_string(file))
        return -EFAULT;

    if (!stat || test_user_memory(stat, sizeof(*stat), true))
        return -EFAULT;

    int ret;
    struct shim_dentry* dent = NULL;

    if ((ret = path_lookupat(NULL, file, LOOKUP_ACCESS, &dent, NULL)) < 0)
        goto out;

    struct shim_mount* fs = dent->fs;

    if (!fs->d_ops || !fs->d_ops->stat) {
        ret = -EACCES;
        goto out_dentry;
    }

    ret = fs->d_ops->stat(dent, stat);
out_dentry:
    put_dentry(dent);
out:
    return ret;
}

long shim_do_fstat(int fd, struct stat* stat) {
    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret = -EACCES;
    struct shim_mount* fs = hdl->fs;

    if (!fs || !fs->fs_ops)
        goto out;

    if (!fs->fs_ops->hstat)
        goto out;

    ret = fs->fs_ops->hstat(hdl, stat);
out:
    put_handle(hdl);
    return ret;
}

long shim_do_readlinkat(int dirfd, const char* file, char* buf, int bufsize) {
    int ret;
    if (!file || test_user_string(file))
        return -EFAULT;

    if (bufsize <= 0)
        return -EINVAL;

    if (test_user_memory(buf, bufsize, true))
        return -EFAULT;

    struct shim_dentry* dent = NULL;
    struct shim_dentry* dir = NULL;

    if (*file != '/' && (ret = get_dirfd_dentry(dirfd, &dir)) < 0)
        goto out;

    struct shim_qstr qstr = QSTR_INIT;

    if ((ret = path_lookupat(dir, file, LOOKUP_ACCESS, &dent, NULL)) < 0)
        goto out;

    ret = -EINVAL;
    /* The correct behavior is to return -EINVAL if file is not a
       symbolic link */
    if (!(dent->state & DENTRY_ISLINK))
        goto out;

    if (!dent->fs || !dent->fs->d_ops || !dent->fs->d_ops->follow_link)
        goto out;

    ret = dent->fs->d_ops->follow_link(dent, &qstr);
    if (ret < 0)
        goto out;

    ret = bufsize;
    if (qstr.len < (size_t)bufsize)
        ret = qstr.len;

    memcpy(buf, qstrgetstr(&qstr), ret);
out:
    if (dent) {
        put_dentry(dent);
    }
    if (dir) {
        put_dentry(dir);
    }
    return ret;
}

long shim_do_readlink(const char* file, char* buf, int bufsize) {
    return shim_do_readlinkat(AT_FDCWD, file, buf, bufsize);
}

static int __do_statfs(struct shim_mount* fs, struct statfs* buf) {
    __UNUSED(fs);
    if (!buf || test_user_memory(buf, sizeof(*buf), true))
        return -EFAULT;

    memset(buf, 0, sizeof(*buf));

    buf->f_bsize  = 4096;
    buf->f_blocks = 20000000;
    buf->f_bfree  = 10000000;
    buf->f_bavail = 10000000;

    debug("statfs: %ld %ld %ld\n", buf->f_blocks, buf->f_bfree, buf->f_bavail);

    return 0;
}

long shim_do_statfs(const char* path, struct statfs* buf) {
    if (!path || test_user_string(path))
        return -EFAULT;

    int ret;
    struct shim_dentry* dent = NULL;

    if ((ret = path_lookupat(NULL, path, LOOKUP_ACCESS | LOOKUP_FOLLOW, &dent, NULL)) < 0)
        return ret;

    struct shim_mount* fs = dent->fs;
    put_dentry(dent);
    return __do_statfs(fs, buf);
}

long shim_do_fstatfs(int fd, struct statfs* buf) {
    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    struct shim_mount* fs = hdl->fs;
    put_handle(hdl);
    return __do_statfs(fs, buf);
}

long shim_do_newfstatat(int dirfd, const char* pathname, struct stat* statbuf, int flags) {
    if (flags & ~(AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW))
        return -EINVAL;
    if (test_user_string(pathname))
        return -EFAULT;
    if (test_user_memory(statbuf, sizeof(*statbuf), true))
        return -EFAULT;

    int lookup_flags = LOOKUP_ACCESS | LOOKUP_FOLLOW;
    if (flags & AT_SYMLINK_NOFOLLOW)
        lookup_flags &= ~LOOKUP_FOLLOW;
    if (flags & AT_NO_AUTOMOUNT) {
        /* Do nothing as automount isn't supported */
        debug("ignoring AT_NO_AUTOMOUNT.");
    }

    int ret = 0;

    if (!*pathname) {
        if (!(flags & AT_EMPTY_PATH))
            return -ENOENT;

        if (dirfd == AT_FDCWD) {
            lock(&g_process.fs_lock);
            struct shim_dentry* cwd  = g_process.cwd;
            get_dentry(cwd);
            unlock(&g_process.fs_lock);

            struct shim_d_ops* d_ops = cwd->fs->d_ops;
            if (d_ops && d_ops->stat) {
                ret = d_ops->stat(cwd, statbuf);
                put_dentry(cwd);
                return ret;
            }
            put_dentry(cwd);
            return -EACCES;
        }
        return shim_do_fstat(dirfd, statbuf);
    }

    struct shim_dentry* dir = NULL;
    if (*pathname != '/') {
        ret = get_dirfd_dentry(dirfd, &dir);
        if (ret < 0)
            return ret;
    }

    struct shim_dentry* dent = NULL;
    ret = path_lookupat(dir, pathname, lookup_flags, &dent, NULL);
    if (ret >= 0) {
        struct shim_d_ops* d_ops = dent->fs->d_ops;
        if (d_ops && d_ops->stat)
            ret = d_ops->stat(dent, statbuf);
        else
            ret = -EACCES;
        put_dentry(dent);
    }
    if (dir)
        put_dentry(dir);
    return ret;
}
