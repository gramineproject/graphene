/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Li Xun <xun.li@intel.com>
 */

/*
 * This file contains code for implementation of 'tmpfs' filesystem.
 * The tmpfs files are *not* cloned during fork/clone and cannot be synchronized between processes.
 */

#include <asm/mman.h>
#include <asm/unistd.h>
#include <errno.h>

#include "perm.h"
#include "shim_flags_conv.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_utils.h"
#include "stat.h"

/*
 * Implementation:
 *
 * The tmpfs file handles are TYPE_STR, and we delegate work to str_* functions. This works because
 * shim_tmpfs_data structure (which is stored with dentries) begins with shim_str_data.
 */

struct shim_tmpfs_data {
    struct shim_str_data str_data;
    struct shim_lock lock;
    enum shim_file_type type;
    mode_t mode;
    unsigned long atime;
    unsigned long mtime;
    unsigned long ctime;
    unsigned long nlink;
};

static int tmpfs_mount(const char* uri, void** mount_data) {
    __UNUSED(uri);
    __UNUSED(mount_data);
    return 0;
}

static int tmpfs_unmount(void* mount_data) {
    __UNUSED(mount_data);
    return 0;
}

static struct shim_tmpfs_data* __create_data(void) {
    struct shim_tmpfs_data* data = calloc(1, sizeof(*data));
    if (!data)
        return NULL;

    if (!create_lock(&data->lock)) {
        free(data);
        return NULL;
    }
    return data;
}

static void __destroy_data(struct shim_tmpfs_data* data) {
    destroy_lock(&data->lock);
    if (data->str_data.str)
        free(data->str_data.str);
    free(data);
}

static int create_data(struct shim_dentry* dent) {
    assert(locked(&dent->lock));

    if (dent->data)
        return 0;

    struct shim_tmpfs_data* data = __create_data();
    if (!data)
        return -ENOMEM;

    data->type = FILE_UNKNOWN;
    data->mode = NO_MODE;

    uint64_t time = 0;
    if (DkSystemTimeQuery(&time) < 0) {
        __destroy_data(data);
        return -EPERM;
    }

    data->atime = time / 1000000;
    data->mtime = data->atime;
    data->ctime = data->atime;
    data->nlink = 1;

    dent->data = data;
    return 0;
}

static inline int get_or_create_tmpfs_data(struct shim_dentry* dent,
                                           struct shim_tmpfs_data** dataptr) {
    lock(&dent->lock);
    if (!dent->data) {
        int ret = create_data(dent);
        if (ret < 0) {
            unlock(&dent->lock);
            return ret;
        }
    }
    assert(dent->data);
    *dataptr = (struct shim_tmpfs_data*)dent->data;
    unlock(&dent->lock);
    return 0;
}

static void tmpfs_update_ino(struct shim_dentry* dent) {
    if (dent->state & DENTRY_INO_UPDATED)
        return;

    unsigned long ino = 1;
    if (!qstrempty(&dent->rel_path))
        ino = hash_path(qstrgetstr(&dent->rel_path), dent->rel_path.len);

    dent->ino = ino;
    dent->state |= DENTRY_INO_UPDATED;
}

static int tmpfs_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags) {
    int ret = 0;
    struct shim_tmpfs_data* data;
    ret = get_or_create_tmpfs_data(dent, &data);
    if (ret < 0)
        return ret;

    lock(&data->lock);
    if (dent->state & DENTRY_MOUNTPOINT) {
        /* root of tmpfs */
        data->type = FILE_DIR;
        data->mode = PERM_rwxrwxrwx;
        dent->type = S_IFDIR;
        tmpfs_update_ino(dent);
    }

    if (data->type == FILE_UNKNOWN) {
        if (!(flags & O_CREAT)) {
            ret = -ENOENT;
            goto out;
        }
        data->type = FILE_REGULAR;
        data->mode = PERM_rwxrwxrwx;
        dent->type = S_IFREG;
        tmpfs_update_ino(dent);
        /* always keep data for tmpfs until unlink */
        REF_INC(data->str_data.ref_count);
    }

    switch (data->type) {
        case FILE_REGULAR:
            ret = str_open(hdl, dent, flags);
            if (ret < 0)
                goto out;
            break;
        case FILE_DIR:
            if (flags & (O_ACCMODE | O_CREAT | O_TRUNC | O_APPEND)) {
                ret = -EISDIR;
                goto out;
            }
            ret = str_open(hdl, dent, flags);
            if (ret < 0)
                goto out;
            hdl->is_dir = true;
            break;
        default:
            ret = -EACCES;
            goto out;
    }

    hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);
    ret = 0;

out:
    unlock(&data->lock);

    return ret;
}

static int tmpfs_dput(struct shim_dentry* dent) {
    lock(&dent->lock);
    struct shim_tmpfs_data* tmpfs_data = dent->data;

    if (!tmpfs_data || REF_DEC(tmpfs_data->str_data.ref_count) > 1) {
        unlock(&dent->lock);
        return 0;
    }
    __destroy_data(tmpfs_data);

    dent->data  = NULL;
    dent->state = DENTRY_NEGATIVE;
    dent->mode  = NO_MODE;
    unlock(&dent->lock);
    return 0;
}

static int tmpfs_flush(struct shim_handle* hdl) {
    return str_flush(hdl);
}

static int tmpfs_close(struct shim_handle* hdl) {
    if (hdl->flags & (O_WRONLY | O_RDWR)) {
        int ret = tmpfs_flush(hdl);
        if (ret < 0)
            return ret;
    }
    return tmpfs_dput(hdl->dentry);
}

static ssize_t tmpfs_read(struct shim_handle* hdl, void* buf, size_t count) {
    assert(hdl->dentry);
    if (!(hdl->acc_mode & MAY_READ)) {
        return -EBADF;
    }

    struct shim_tmpfs_data* tmpfs_data = hdl->dentry->data;
    assert(tmpfs_data);
    if (tmpfs_data->type != FILE_REGULAR) {
        return -EISDIR;
    }

    lock(&hdl->lock);
    ssize_t ret = str_read(hdl, buf, count);
    /* technically, we should update access time here, but we skip this because it could hurt
     * performance on Linux-SGX host */
    unlock(&hdl->lock);
    return ret;
}

static ssize_t tmpfs_write(struct shim_handle* hdl, const void* buf, size_t count) {
    struct shim_tmpfs_data* tmpfs_data = hdl->dentry->data;
    assert(tmpfs_data);
    if (tmpfs_data->type != FILE_REGULAR) {
        return -EISDIR;
    }

    uint64_t time = 0;
    if (DkSystemTimeQuery(&time) < 0) {
        return -EPERM;
    }

    lock(&hdl->lock);
    ssize_t ret = str_write(hdl, buf, count);
    if (ret < 0) {
        goto out;
    }

    tmpfs_data->ctime = time / 1000000;
    tmpfs_data->mtime = tmpfs_data->ctime;

out:
    unlock(&hdl->lock);
    return ret;
}

/* TODO: tmpfs_mmap() function is not implemented because shim_do_mmap() and shim_do_munmap()
   are currently not flexible enough for correct tmpfs implementation. In particular, shim_do_mmap()
   pre-allocates memory region at a specific address (making it impossible to have two mmaps on the
   same tmpfs file), and shim_do_munmap() doesn't have a callback into tmpfs at all. */
static int tmpfs_mmap(struct shim_handle* hdl, void** addr, size_t size, int prot, int flags,
                      uint64_t offset) {
    __UNUSED(hdl);
    __UNUSED(addr);
    __UNUSED(size);
    __UNUSED(prot);
    __UNUSED(flags);
    __UNUSED(offset);

    log_error("tmpfs_mmap(): mmap() function for tmpfs mount type is not implemented.\n");
    return -ENOSYS;
}

static off_t tmpfs_seek(struct shim_handle* hdl, off_t offset, int whence) {
    return str_seek(hdl, offset, whence);
}

static int query_dentry(struct shim_dentry* dent, mode_t* mode, struct stat* stat) {
    int ret = 0;

    struct shim_tmpfs_data* data;
    ret = get_or_create_tmpfs_data(dent, &data);
    if (ret < 0)
        return ret;

    lock(&data->lock);

    switch (data->type) {
        case FILE_REGULAR:
            dent->type = S_IFREG;
            break;
        case FILE_DIR:
            dent->type = S_IFDIR;
            break;
        default:
            unlock(&data->lock);
            return -ENOENT;
    }

    if (mode)
        *mode = data->mode;

    if (stat) {
        memset(stat, 0, sizeof(struct stat));

        stat->st_mode  = (mode_t)data->mode;
        stat->st_dev   = 0;
        stat->st_ino   = dent->ino;
        stat->st_size  = data->str_data.len;
        stat->st_atime = (time_t)data->atime;
        stat->st_mtime = (time_t)data->mtime;
        stat->st_ctime = (time_t)data->ctime;
        stat->st_nlink = data->nlink;

        switch (data->type) {
            case FILE_REGULAR:
                stat->st_mode |= S_IFREG;
                break;
            case FILE_DIR:
                stat->st_mode |= S_IFDIR;
                break;
            default:
                unlock(&data->lock);
                return -ENOENT;
        }
    }

    unlock(&data->lock);
    return 0;
}

static int tmpfs_mode(struct shim_dentry* dent, mode_t* mode) {
    if (qstrempty(&dent->rel_path)) {
        /* root of pseudo-FS */
        return pseudo_dir_mode(/*name=*/NULL, mode);
    }
    return query_dentry(dent, mode, NULL);
}

static int tmpfs_stat(struct shim_dentry* dent, struct stat* statbuf) {
    if (qstrempty(&dent->rel_path)) {
        /* root of pseudo-FS */
        return pseudo_dir_stat(/*name=*/NULL, statbuf);
    }
    return query_dentry(dent, NULL, statbuf);
}

static int tmpfs_lookup(struct shim_dentry* dent) {
    if (qstrempty(&dent->rel_path)) {
        /* root of pseudo-FS */
        dent->ino = 1;
        dent->state |= DENTRY_ISDIRECTORY;
        return 0;
    }
    return query_dentry(dent, NULL, NULL);
}

static int tmpfs_creat(struct shim_handle* hdl, struct shim_dentry* dir, struct shim_dentry* dent,
                       int flags, mode_t mode) {
    int ret = 0;
    assert(hdl);

    struct shim_tmpfs_data* data;
    ret = get_or_create_tmpfs_data(dent, &data);
    if (ret < 0)
        return ret;

    if (data->type == FILE_DIR) {
        return -EISDIR;
    }
    ret = tmpfs_open(hdl, dent, flags | O_CREAT | O_EXCL);
    if (ret < 0) {
        __destroy_data(data);
        return ret;
    }

    data->mode = mode;

    /* Increment the parent's link count */
    struct shim_tmpfs_data* parent_data = (struct shim_tmpfs_data*)dir->data;
    if (parent_data) {
        lock(&parent_data->lock);
        parent_data->nlink++;
        unlock(&parent_data->lock);
    }
    return 0;
}

static int tmpfs_mkdir(struct shim_dentry* dir, struct shim_dentry* dent, mode_t mode) {
    int ret = 0;
    struct shim_tmpfs_data* data;
    ret = get_or_create_tmpfs_data(dent, &data);
    if (ret < 0)
        return ret;

    if (data->type != FILE_UNKNOWN)
        return -EEXIST;
    data->type = FILE_DIR;
    data->mode = mode;

    dent->type = S_IFDIR;

    tmpfs_update_ino(dent);

    /* Increment the parent's link count */
    struct shim_tmpfs_data* parent_data = (struct shim_tmpfs_data*)dir->data;
    if (parent_data) {
        lock(&parent_data->lock);
        parent_data->nlink++;
        unlock(&parent_data->lock);
    }
    return 0;
}

static int tmpfs_hstat(struct shim_handle* hdl, struct stat* stat) {
    assert(hdl->dentry);
    if (qstrempty(&hdl->dentry->rel_path)) {
        /* root of pseudo-FS */
        return pseudo_dir_stat(/*name=*/NULL, stat);
    }
    return query_dentry(hdl->dentry, NULL, stat);
}

static int tmpfs_truncate(struct shim_handle* hdl, off_t len) {
    int ret = 0;
    lock(&hdl->lock);
    ret = str_truncate(hdl, len);
    unlock(&hdl->lock);
    return ret;
}

static int tmpfs_readdir(struct shim_dentry* dent, struct shim_dirent** dirent) {
    int ret = 0;
    size_t dirent_buf_size = 0;
    char* dirent_buf = NULL;

    struct shim_tmpfs_data* tmpfs_data = dent->data;
    assert(tmpfs_data);
    if (tmpfs_data->type != FILE_DIR) {
        return -ENOTDIR;
    }

    struct shim_dentry* tmp_dent = NULL;
    struct shim_tmpfs_data* tmp_data = NULL;
    LISTP_FOR_EACH_ENTRY(tmp_dent, &dent->children, siblings) {
        assert((tmp_dent->state & DENTRY_INVALID_FLAGS) == 0);

        if (tmp_dent->state & DENTRY_NEGATIVE)
            continue;
        tmp_data = tmp_dent->data;
        if (!tmp_data || (tmp_data->type != FILE_DIR && tmp_data->type != FILE_REGULAR))
            continue;
        dirent_buf_size += SHIM_DIRENT_ALIGNED_SIZE(tmp_dent->name.len + 1);
    }

    dirent_buf = malloc(dirent_buf_size);
    if (!dirent_buf) {
        ret = -ENOMEM;
        goto out;
    }

    size_t dirent_cur_off = 0;
    struct shim_dirent** last = NULL;
    LISTP_FOR_EACH_ENTRY(tmp_dent, &dent->children, siblings) {
        if (tmp_dent->state & DENTRY_NEGATIVE)
            continue;
        tmp_data = tmp_dent->data;
        if (!tmp_data || (tmp_data->type != FILE_DIR && tmp_data->type != FILE_REGULAR))
            continue;

        struct shim_dirent* dptr = (struct shim_dirent*)(dirent_buf + dirent_cur_off);
        dptr->ino  = tmp_dent->ino;
        dptr->type = tmp_data->type == FILE_DIR ? LINUX_DT_DIR : LINUX_DT_REG;
        memcpy(dptr->name, qstrgetstr(&tmp_dent->name), tmp_dent->name.len + 1);
        size_t len = SHIM_DIRENT_ALIGNED_SIZE(tmp_dent->name.len + 1);
        dptr->next = (struct shim_dirent*)(dirent_buf + dirent_cur_off + len);
        last = &dptr->next;
        dirent_cur_off += len;
    }
    if (last) {
        *last = NULL;
    }
    *dirent = (struct shim_dirent*)dirent_buf;

out:
    if (ret) {
        free(dirent_buf);
    }
    return ret;
}

static int tmpfs_unlink(struct shim_dentry* dir, struct shim_dentry* dent) {
    struct shim_tmpfs_data* tmpfs_data = dent->data;
    if (!tmpfs_data)
        return -ENOENT;

    if (tmpfs_data->type == FILE_REGULAR) {
        tmpfs_dput(dent);
    } else if (tmpfs_data->type == FILE_DIR && dent->nchildren != 0) {
        struct shim_dentry* tmp = NULL;
        size_t nchildren = 0;
        LISTP_FOR_EACH_ENTRY(tmp, &dent->children, siblings) {
            if (tmp->state & DENTRY_NEGATIVE)
                continue;
            nchildren++;
        }
        if (nchildren != 0)
            return -ENOTEMPTY;
        dent->data = NULL;
        dent->mode = NO_MODE;
    }

    struct shim_tmpfs_data* parent_data = dir->data;
    if (parent_data) {
        lock(&parent_data->lock);
        parent_data->nlink--;
        unlock(&parent_data->lock);
    }

    return 0;
}

static off_t tmpfs_poll(struct shim_handle* hdl, int poll_type) {
    assert(hdl->type == TYPE_STR);
    struct shim_str_data* data = hdl->info.str.data;
    off_t size = data ? data->len : 0;

    if (poll_type == FS_POLL_SZ)
        return size;

    return -EAGAIN;
}

static int tmpfs_rename(struct shim_dentry* old, struct shim_dentry* new) {
    struct shim_tmpfs_data* tmpfs_data = new->data;
    assert(tmpfs_data && tmpfs_data->str_data.str == NULL);

    uint64_t time = 0;
    if (DkSystemTimeQuery(&time) < 0) {
        return -EPERM;
    }

    __destroy_data(tmpfs_data);

    /* old file must be existing, otherwise some bug */
    assert(REF_GET(old->ref_count) > 0);

    new->data = old->data;
    new->mode = old->mode;
    new->type = old->type;

    tmpfs_data        = new->data;
    tmpfs_data->ctime = time / 1000000;

    /* mark old file as non-existing now, after renaming */
    old->state |= DENTRY_NEGATIVE;
    return 0;
}

static int tmpfs_chmod(struct shim_dentry* dent, mode_t mode) {
    struct shim_tmpfs_data* tmpfs_data = dent->data;
    if (!tmpfs_data)
        return -ENOENT;

    uint64_t time = 0;
    if (DkSystemTimeQuery(&time) < 0) {
        return -EPERM;
    }

    dent->mode        = mode;
    tmpfs_data->mode  = mode;
    tmpfs_data->ctime = time / 1000000;
    return 0;
}

struct shim_fs_ops tmp_fs_ops = {
    .mount    = &tmpfs_mount,
    .unmount  = &tmpfs_unmount,
    .flush    = &tmpfs_flush,
    .close    = &tmpfs_close,
    .read     = &tmpfs_read,
    .write    = &tmpfs_write,
    .mmap     = &tmpfs_mmap,
    .seek     = &tmpfs_seek,
    .hstat    = &tmpfs_hstat,
    .truncate = &tmpfs_truncate,
    .poll     = &tmpfs_poll,
};

struct shim_d_ops tmp_d_ops = {
    .open    = &tmpfs_open,
    .mode    = &tmpfs_mode,
    .lookup  = &tmpfs_lookup,
    .creat   = &tmpfs_creat,
    .mkdir   = &tmpfs_mkdir,
    .stat    = &tmpfs_stat,
    .dput    = &tmpfs_dput,
    .readdir = &tmpfs_readdir,
    .unlink  = &tmpfs_unlink,
    .rename  = &tmpfs_rename,
    .chmod   = &tmpfs_chmod,
};
