/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system calls: "read", "write", "open", "creat", "openat", "close", "lseek",
 * "pread64", "pwrite64", "getdents", "getdents64", "fsync", "truncate" and "ftruncate".
 */

#include <dirent.h>
#include <errno.h>
#include <linux/fcntl.h>
#include <stdalign.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_table.h"
#include "shim_thread.h"
#include "shim_utils.h"
#include "stat.h"

int do_handle_read(struct shim_handle* hdl, void* buf, int count) {
    if (!(hdl->acc_mode & MAY_READ))
        return -EACCES;

    struct shim_mount* fs = hdl->fs;
    assert(fs && fs->fs_ops);

    if (!fs->fs_ops->read)
        return -EBADF;

    if (hdl->is_dir)
        return -EISDIR;

    return fs->fs_ops->read(hdl, buf, count);
}

long shim_do_read(int fd, void* buf, size_t count) {
    if (test_user_memory(buf, count, true))
        return -EFAULT;

    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    /* sockets may read from LibOS buffer due to MSG_PEEK, so need to call socket-specific recv */
    if (hdl->type == TYPE_SOCK) {
        put_handle(hdl);
        return shim_do_recvfrom(fd, buf, count, 0, NULL, NULL);
    }

    int ret = do_handle_read(hdl, buf, count);
    put_handle(hdl);
    return ret;
}

int do_handle_write(struct shim_handle* hdl, const void* buf, int count) {
    if (!(hdl->acc_mode & MAY_WRITE))
        return -EACCES;

    struct shim_mount* fs = hdl->fs;
    assert(fs && fs->fs_ops);

    if (!fs->fs_ops->write)
        return -EBADF;

    if (hdl->is_dir)
        return -EISDIR;

    return fs->fs_ops->write(hdl, buf, count);
}

long shim_do_write(int fd, const void* buf, size_t count) {
    if (test_user_memory((void*)buf, count, false))
        return -EFAULT;

    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret = do_handle_write(hdl, buf, count);
    put_handle(hdl);
    return ret;
}

long shim_do_open(const char* file, int flags, mode_t mode) {
    return shim_do_openat(AT_FDCWD, file, flags, mode);
}

long shim_do_creat(const char* path, mode_t mode) {
    return shim_do_open(path, O_CREAT | O_TRUNC | O_WRONLY, mode);
}

long shim_do_openat(int dfd, const char* filename, int flags, int mode) {
    if (!filename || test_user_string(filename))
        return -EFAULT;

    if (!(flags & O_CREAT)) {
        /* `mode` should be ignored if O_CREAT is not specified, according to man */
        mode = 0;
    } else {
        /* This isn't documented, but that's what Linux does. */
        mode &= 07777;
    }

    struct shim_dentry* dir = NULL;
    int ret = 0;

    if (*filename != '/' && (ret = get_dirfd_dentry(dfd, &dir)) < 0)
        return ret;

    struct shim_handle* hdl = get_new_handle();
    if (!hdl) {
        ret = -ENOMEM;
        goto out;
    }

    ret = open_namei(hdl, dir, filename, flags, mode, NULL);
    if (ret < 0)
        goto out_hdl;

    ret = set_new_fd_handle(hdl, flags & O_CLOEXEC ? FD_CLOEXEC : 0, NULL);

out_hdl:
    put_handle(hdl);
out:
    if (dir)
        put_dentry(dir);
    return ret;
}

long shim_do_close(int fd) {
    struct shim_handle* handle = detach_fd_handle(fd, NULL, NULL);
    if (!handle)
        return -EBADF;

    put_handle(handle);
    return 0;
}

/* lseek is simply doing arithmetic on the offset, no PAL call here */
long shim_do_lseek(int fd, off_t offset, int origin) {
    if (origin != SEEK_SET && origin != SEEK_CUR && origin != SEEK_END)
        return -EINVAL;

    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret = 0;
    struct shim_mount* fs = hdl->fs;
    assert(fs && fs->fs_ops);

    if (!fs->fs_ops->seek) {
        ret = -ESPIPE;
        goto out;
    }

    if (hdl->is_dir) {
        /* TODO: handle lseek'ing of directories */
        ret = -ENOSYS;
        goto out;
    }

    ret = fs->fs_ops->seek(hdl, offset, origin);
out:
    put_handle(hdl);
    return ret;
}

long shim_do_pread64(int fd, char* buf, size_t count, loff_t pos) {
    if (test_user_memory(buf, count, true))
        return -EFAULT;

    if (pos < 0)
        return -EINVAL;

    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    struct shim_mount* fs = hdl->fs;
    ssize_t ret = -EACCES;

    if (!fs || !fs->fs_ops)
        goto out;

    if (!fs->fs_ops->seek) {
        ret = -ESPIPE;
        goto out;
    }

    if (!fs->fs_ops->read)
        goto out;

    if (hdl->is_dir)
        goto out;

    int offset = fs->fs_ops->seek(hdl, 0, SEEK_CUR);
    if (offset < 0) {
        ret = offset;
        goto out;
    }

    ret = fs->fs_ops->seek(hdl, pos, SEEK_SET);
    if (ret < 0)
        goto out;

    int bytes = fs->fs_ops->read(hdl, buf, count);

    ret = fs->fs_ops->seek(hdl, offset, SEEK_SET);
    if (ret < 0)
        goto out;

    ret = bytes;
out:
    put_handle(hdl);
    return ret;
}

long shim_do_pwrite64(int fd, char* buf, size_t count, loff_t pos) {
    if (test_user_memory(buf, count, false))
        return -EFAULT;

    if (pos < 0)
        return -EINVAL;

    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    struct shim_mount* fs = hdl->fs;
    ssize_t ret = -EACCES;

    if (!fs || !fs->fs_ops)
        goto out;

    if (!fs->fs_ops->seek) {
        ret = -ESPIPE;
        goto out;
    }

    if (!fs->fs_ops->write)
        goto out;

    if (hdl->is_dir)
        goto out;

    int offset = fs->fs_ops->seek(hdl, 0, SEEK_CUR);
    if (offset < 0) {
        ret = offset;
        goto out;
    }

    ret = fs->fs_ops->seek(hdl, pos, SEEK_SET);
    if (ret < 0)
        goto out;

    int bytes = fs->fs_ops->write(hdl, buf, count);

    ret = fs->fs_ops->seek(hdl, offset, SEEK_SET);
    if (ret < 0)
        goto out;

    ret = bytes;
out:
    put_handle(hdl);
    return ret;
}

static inline int get_dirent_type(mode_t type) {
    switch (type) {
        case S_IFLNK:
            return LINUX_DT_LNK;
        case S_IFREG:
            return LINUX_DT_REG;
        case S_IFDIR:
            return LINUX_DT_DIR;
        case S_IFCHR:
            return LINUX_DT_CHR;
        case S_IFBLK:
            return LINUX_DT_BLK;
        case S_IFIFO:
            return LINUX_DT_FIFO;
        case S_IFSOCK:
            return LINUX_DT_SOCK;
        default:
            return LINUX_DT_UNKNOWN;
    }
}

long shim_do_getdents(int fd, struct linux_dirent* buf, size_t count) {
    if (test_user_memory(buf, count, true))
        return -EFAULT;

    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret = -EACCES;

    if (!hdl->is_dir) {
        ret = -ENOTDIR;
        goto out_no_unlock;
    }

    /* DEP 3/3/17: Properly handle an unlinked directory */
    if (hdl->dentry->state & DENTRY_NEGATIVE) {
        ret = -ENOENT;
        goto out_no_unlock;
    }

    /* we are grabbing the lock because the handle content is actually
       updated */
    lock(&hdl->lock);

    struct shim_dir_handle* dirhdl = &hdl->dir_info;
    struct shim_dentry* dent = hdl->dentry;
    struct linux_dirent* b = buf;
    int bytes = 0;

    /* If we haven't listed the directory, do this first */
    if (!(dent->state & DENTRY_LISTED)) {
        ret = list_directory_dentry(dent);
        if (ret < 0)
            goto out;
    }

/* Size calculation for dirent considering alignment restrictions for b->d_ino */
// TODO: This "+ 1" below is most likely not needed (NULL byte is already included in
//       linux_dirent_tail).
#define DIRENT_SIZE(len) \
    ALIGN_UP(sizeof(struct linux_dirent) + sizeof(struct linux_dirent_tail) + (len) + 1, \
             alignof(struct linux_dirent))

#define ASSIGN_DIRENT(dent, name, type)                                                  \
    do {                                                                                 \
        int len = strlen(name);                                                          \
        if (bytes + DIRENT_SIZE(len) > count)                                            \
            goto done;                                                                   \
                                                                                         \
        struct linux_dirent_tail* bt = (void*)b + DIRENT_SIZE(len) - sizeof(*bt);        \
                                                                                         \
        b->d_ino    = (dent)->ino;                                                       \
        b->d_off    = ++dirhdl->offset;                                                  \
        b->d_reclen = DIRENT_SIZE(len);                                                  \
                                                                                         \
        memcpy(b->d_name, name, len + 1);                                                \
                                                                                         \
        bt->pad    = 0;                                                                  \
        bt->d_type = (type);                                                             \
                                                                                         \
        bytes += b->d_reclen;                                                            \
        b = (void*)b + b->d_reclen;                                                      \
    } while (0)

    if (dirhdl->dot) {
        ASSIGN_DIRENT(dirhdl->dot, ".", LINUX_DT_DIR);
        put_dentry(dirhdl->dot);
        dirhdl->dot = NULL;
    }

    if (dirhdl->dotdot) {
        ASSIGN_DIRENT(dirhdl->dotdot, "..", LINUX_DT_DIR);
        put_dentry(dirhdl->dotdot);
        dirhdl->dotdot = NULL;
    }

    if (dirhdl->ptr == (void*)-1) {
        ret = list_directory_handle(dent, hdl);
        if (ret < 0)
            goto out;
    }

    while (dirhdl->ptr && *dirhdl->ptr) {
        dent = *dirhdl->ptr;
        /* DEP 3/3/17: We need to filter negative dentries */
        if (!(dent->state & DENTRY_NEGATIVE))
            ASSIGN_DIRENT(dent, dentry_get_name(dent), get_dirent_type(dent->type));
        put_dentry(dent);
        *(dirhdl->ptr++) = NULL;
    }

#undef DIRENT_SIZE
#undef ASSIGN_DIRENT

done:
    ret = bytes;
    /* DEP 3/3/17: Properly detect EINVAL case, where buffer is too small to
     * hold anything */
    if (bytes == 0 && (dirhdl->dot || dirhdl->dotdot || (dirhdl->ptr && *dirhdl->ptr)))
        ret = -EINVAL;
out:
    unlock(&hdl->lock);
out_no_unlock:
    put_handle(hdl);
    return ret;
}

long shim_do_getdents64(int fd, struct linux_dirent64* buf, size_t count) {
    if (test_user_memory(buf, count, true))
        return -EFAULT;

    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret = -EACCES;

    if (!hdl->is_dir) {
        ret = -ENOTDIR;
        goto out_no_unlock;
    }

    /* DEP 3/3/17: Properly handle an unlinked directory */
    if (hdl->dentry->state & DENTRY_NEGATIVE) {
        ret = -ENOENT;
        goto out_no_unlock;
    }

    lock(&hdl->lock);

    struct shim_dir_handle* dirhdl = &hdl->dir_info;
    struct shim_dentry* dent = hdl->dentry;
    struct linux_dirent64* b = buf;
    int bytes = 0;

    /* If we haven't listed the directory, do this first */
    if (!(dent->state & DENTRY_LISTED)) {
        ret = list_directory_dentry(dent);
        if (ret)
            goto out;
    }

/* Size calculation for dirent considering alignment restrictions for b->d_ino */
#define DIRENT_SIZE(len) ALIGN_UP(sizeof(struct linux_dirent64) + (len) + 1, \
                                  alignof(struct linux_dirent64))

#define ASSIGN_DIRENT(dent, name, type)       \
    do {                                      \
        int len = strlen(name);               \
        if (bytes + DIRENT_SIZE(len) > count) \
            goto done;                        \
                                              \
        b->d_ino    = (dent)->ino;            \
        b->d_off    = ++dirhdl->offset;       \
        b->d_reclen = DIRENT_SIZE(len);       \
        b->d_type   = (type);                 \
                                              \
        memcpy(b->d_name, name, len + 1);     \
                                              \
        bytes += b->d_reclen;                 \
        b = (void*)b + b->d_reclen;           \
    } while (0)

    if (dirhdl->dot) {
        ASSIGN_DIRENT(dirhdl->dot, ".", LINUX_DT_DIR);
        put_dentry(dirhdl->dot);
        dirhdl->dot = NULL;
    }

    if (dirhdl->dotdot) {
        ASSIGN_DIRENT(dirhdl->dotdot, "..", LINUX_DT_DIR);
        put_dentry(dirhdl->dotdot);
        dirhdl->dotdot = NULL;
    }

    if (dirhdl->ptr == (void*)-1) {
        ret = list_directory_handle(dent, hdl);
        if (ret)
            goto out;
    }

    while (dirhdl->ptr && *dirhdl->ptr) {
        dent = *dirhdl->ptr;
        /* DEP 3/3/17: We need to filter negative dentries */
        if (!(dent->state & DENTRY_NEGATIVE))
            ASSIGN_DIRENT(dent, dentry_get_name(dent), get_dirent_type(dent->type));
        put_dentry(dent);
        *(dirhdl->ptr++) = NULL;
    }

#undef DIRENT_SIZE
#undef ASSIGN_DIRENT

done:
    ret = bytes;
    /* DEP 3/3/17: Properly detect EINVAL case, where buffer is too small to
     * hold anything */
    if (bytes == 0 && (dirhdl->dot || dirhdl->dotdot || (dirhdl->ptr && *dirhdl->ptr)))
        ret = -EINVAL;
out:
    unlock(&hdl->lock);
out_no_unlock:
    put_handle(hdl);
    return ret;
}

long shim_do_fsync(int fd) {
    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret = -EACCES;
    struct shim_mount* fs = hdl->fs;

    if (!fs || !fs->fs_ops)
        goto out;

    if (hdl->is_dir)
        goto out;

    if (!fs->fs_ops->flush) {
        ret = -EROFS;
        goto out;
    }

    ret = fs->fs_ops->flush(hdl);
out:
    put_handle(hdl);
    return ret;
}

// DEP 10/20/16: Assuming fsync >> fdatasync for now
//  and no app depends on only syncing data for correctness.
long shim_do_fdatasync(int fd) {
    return shim_do_fsync(fd);
}

long shim_do_truncate(const char* path, loff_t length) {
    if (length < 0)
        return -EINVAL;

    struct shim_dentry* dent = NULL;
    int ret = 0;

    if (!path || test_user_string(path))
        return -EFAULT;

    if ((ret = path_lookupat(/*start=*/NULL, path, LOOKUP_FOLLOW, &dent)) < 0)
        return ret;

    struct shim_mount* fs = dent->fs;

    if (!fs || !fs->d_ops || !fs->d_ops->open) {
        ret = -EBADF;
        goto out;
    }

    if (!fs->fs_ops->truncate) {
        ret = -EROFS;
        goto out;
    }

    struct shim_handle* hdl = get_new_handle();

    if (!hdl) {
        ret = -ENOMEM;
        goto out;
    }

    hdl->fs = fs;

    if ((ret = fs->d_ops->open(hdl, dent, O_WRONLY)) < 0)
        goto out_handle;

    ret = fs->fs_ops->truncate(hdl, length);
out_handle:
    put_handle(hdl);
out:
    return ret;
}

long shim_do_ftruncate(int fd, loff_t length) {
    if (length < 0)
        return -EINVAL;

    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    struct shim_mount* fs = hdl->fs;
    int ret = -EINVAL;

    if (!fs || !fs->fs_ops)
        goto out;

    if (hdl->is_dir || !fs->fs_ops->truncate)
        goto out;

    ret = fs->fs_ops->truncate(hdl, length);
out:
    put_handle(hdl);
    return ret;
}
