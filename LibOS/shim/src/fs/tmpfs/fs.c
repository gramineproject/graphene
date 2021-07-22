/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Li Xun <xun.li@intel.com>
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * This file contains code for implementation of 'tmpfs' filesystem. The tmpfs files are *not*
 * cloned during fork/clone and cannot be synchronized between processes.
 *
 * The tmpfs files are directly represented by their dentries (i.e. a file exists whenever
 * corresponding dentry exists). The file data is stored in the dentries.
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

#define USEC_IN_SEC 1000000

struct shim_tmpfs_data {
    struct shim_mem_file mem;
    time_t ctime;
    time_t mtime;
    time_t atime;
};

/* Get data associated with dentry. This is created on demand, instead of during dentry validation,
 * because the dentry might have been restored from a checkpoint, and Graphene's checkpointing
 * system currently omits the dentry `data` field. */
static int tmpfs_get_data(struct shim_dentry* dent, struct shim_tmpfs_data** out_data) {
    assert(locked(&dent->lock));
    if (dent->data) {
        *out_data = dent->data;
        return 0;
    }

    struct shim_tmpfs_data* data = malloc(sizeof(*data));
    if (!data)
        return -ENOMEM;

    mem_file_init(&data->mem, /*data=*/NULL, /*size=*/0);

    uint64_t time_us;
    if (DkSystemTimeQuery(&time_us) < 0) {
        free(data);
        return -EPERM;
    }

    data->ctime = time_us / USEC_IN_SEC;
    data->mtime = data->ctime;
    data->atime = data->ctime;

    dent->data = data;
    *out_data = data;
    return 0;
}

static int tmpfs_mount(const char* uri, void** mount_data) {
    __UNUSED(uri);
    __UNUSED(mount_data);
    return 0;
}

static int tmpfs_unmount(void* mount_data) {
    __UNUSED(mount_data);
    return 0;
}

static int tmpfs_lookup(struct shim_dentry* dent) {
    if (!dent->parent) {
        /* This is the root dentry, initialize it. */
        dent->type = S_IFDIR;
        dent->perm = PERM_rwx______;
        return 0;
    }
    /* Looking up for other detries should fail: if a dentry has not been already created by `creat`
     * or `mkdir`, the corresponding file does not exist. */
    return -ENOENT;
}

static int tmpfs_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags) {
    __UNUSED(dent);
    hdl->type = TYPE_TMPFS;
    hdl->info.tmpfs.pos = 0;
    hdl->flags = flags & ~O_ACCMODE;
    hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);
    return 0;
}

static int tmpfs_creat(struct shim_handle* hdl, struct shim_dentry* dir, struct shim_dentry* dent,
                       int flags, mode_t mode) {
    __UNUSED(dir);

    int ret;

    /* Trigger creating dentry data to ensure right timestamp. */
    lock(&dent->lock);
    struct shim_tmpfs_data* data;
    ret = tmpfs_get_data(dent, &data);
    if (ret < 0)
        goto out;

    dent->type = S_IFREG;
    dent->perm = mode & ~S_IFMT;
    ret = 0;

out:
    unlock(&dent->lock);
    if (ret == 0)
        return tmpfs_open(hdl, dent, flags);
    return ret;
}

static int tmpfs_mkdir(struct shim_dentry* dir, struct shim_dentry* dent, mode_t mode) {
    __UNUSED(dir);

    int ret;

    /* Trigger creating dentry data to ensure right timestamp. */
    lock(&dent->lock);
    struct shim_tmpfs_data* data;
    ret = tmpfs_get_data(dent, &data);
    if (ret < 0)
        goto out;

    dent->type = S_IFDIR;
    dent->perm = mode & ~S_IFMT;
    ret = 0;

out:
    unlock(&dent->lock);
    return ret;
}

static int tmpfs_stat(struct shim_dentry* dent, struct stat* buf) {
    int ret;

    lock(&dent->lock);
    struct shim_tmpfs_data* data;
    ret = tmpfs_get_data(dent, &data);
    if (ret < 0)
        goto out;

    memset(buf, 0, sizeof(*buf));
    buf->st_mode  = dent->perm | dent->type;
    buf->st_size  = data->mem.size;
    buf->st_nlink = dent->type == S_IFDIR ? 2 : 1;
    buf->st_ctime = data->ctime;
    buf->st_mtime = data->mtime;
    buf->st_atime = data->atime;
    ret = 0;

out:
    unlock(&dent->lock);
    return ret;
}

static int tmpfs_readdir(struct shim_dentry* dent, readdir_callback_t callback, void* arg) {
    assert(locked(&g_dcache_lock));

    struct shim_dentry* child;
    LISTP_FOR_EACH_ENTRY(child, &dent->children, siblings) {
        if ((child->state & DENTRY_VALID) && !(child->state & DENTRY_NEGATIVE)) {
            int ret = callback(child->name, arg);
            if (ret < 0)
                return ret;
        }
    }
    return 0;
}

static int tmpfs_unlink(struct shim_dentry* dir, struct shim_dentry* dent) {
    __UNUSED(dir);

    if (dent->type == S_IFDIR) {
        /* TODO: the whole unlink operation should be wrapped in a lock; otherwise there's a race:
         * new files can be created before we delete the directory */
        lock(&g_dcache_lock);
        struct shim_dentry* child;
        bool found = false;
        LISTP_FOR_EACH_ENTRY(child, &dent->children, siblings) {
            if ((child->state & DENTRY_VALID) && !(child->state & DENTRY_NEGATIVE)) {
                found = true;
                break;
            }
        }
        unlock(&g_dcache_lock);
        if (found)
            return -ENOTEMPTY;
    }

    /* TODO: our `unlink` wipes the file data, even though there might be still file handles
     * associated with the dentry. A proper solution would keep the unlinked file until all handles
     * are closed, but also allow creating a new file with the same name. */
    lock(&dent->lock);
    struct shim_tmpfs_data* data = dent->data;
    if (data) {
        dent->data = NULL;
        mem_file_destroy(&data->mem);
        free(data);
    }
    unlock(&dent->lock);
    return 0;
}

/* Lock two dentries for the purposes of rename operation.
 * TODO: This should be probably done by the syscall handler, not here. */
static void lock_two_dentries(struct shim_dentry* dent1, struct shim_dentry* dent2) {
    assert(dent1 != dent2);
    if ((uintptr_t)dent1 < (uintptr_t)dent2) {
        lock(&dent1->lock);
        lock(&dent2->lock);
    } else {
        lock(&dent2->lock);
        lock(&dent1->lock);
    }
}

static void unlock_two_dentries(struct shim_dentry* dent1, struct shim_dentry* dent2) {
    assert(dent1 != dent2);
    if ((uintptr_t)dent1 < (uintptr_t)dent2) {
        unlock(&dent2->lock);
        unlock(&dent1->lock);
    } else {
        unlock(&dent1->lock);
        unlock(&dent2->lock);
    }
}

static int tmpfs_rename(struct shim_dentry* old, struct shim_dentry* new) {
    uint64_t time_us;
    if (DkSystemTimeQuery(&time_us) < 0)
        return -EPERM;

    lock_two_dentries(old, new);

    /* TODO: this should be done in the syscall handler, not here */
    new->type = old->type;
    new->perm = old->perm;

    if (new->data) {
        struct shim_tmpfs_data* data = new->data;
        mem_file_destroy(&data->mem);
        free(data);
    }
    new->data = old->data;
    old->data = NULL;

    struct shim_tmpfs_data* data = new->data;
    data->mtime = time_us / USEC_IN_SEC;

    unlock_two_dentries(old, new);
    return 0;
}

static int tmpfs_chmod(struct shim_dentry* dent, mode_t mode) {
    dent->perm = mode & ~S_IFMT;
    return 0;
}

static ssize_t tmpfs_read(struct shim_handle* hdl, void* buf, size_t size) {
    ssize_t ret;

    assert(hdl->type == TYPE_TMPFS);

    lock(&hdl->lock);
    lock(&hdl->dentry->lock);
    struct shim_tmpfs_data* data;
    ret = tmpfs_get_data(hdl->dentry, &data);
    if (ret < 0)
        goto out;

    ret = mem_file_read(&data->mem, hdl->info.tmpfs.pos, buf, size);
    if (ret < 0)
        goto out;

    hdl->info.tmpfs.pos += ret;

    /* technically, we should update access time here, but we skip this because it could hurt
     * performance on Linux-SGX host */

    /* keep `ret` */

out:
    unlock(&hdl->dentry->lock);
    unlock(&hdl->lock);
    return ret;
}

static ssize_t tmpfs_write(struct shim_handle* hdl, const void* buf, size_t size) {
    ssize_t ret;

    assert(hdl->type == TYPE_TMPFS);

    uint64_t time_us;
    if (DkSystemTimeQuery(&time_us) < 0)
        return -EPERM;

    lock(&hdl->lock);
    lock(&hdl->dentry->lock);
    struct shim_tmpfs_data* data;
    ret = tmpfs_get_data(hdl->dentry, &data);
    if (ret < 0)
        goto out;

    ret = mem_file_write(&data->mem, hdl->info.tmpfs.pos, buf, size);
    if (ret < 0)
        goto out;

    hdl->info.tmpfs.pos += ret;
    data->mtime = time_us / USEC_IN_SEC;
    /* keep `ret` */

out:
    unlock(&hdl->dentry->lock);
    unlock(&hdl->lock);
    return ret;
}

static int tmpfs_truncate(struct shim_handle* hdl, file_off_t size) {
    int ret;

    uint64_t time_us;
    if (DkSystemTimeQuery(&time_us) < 0)
        return -EPERM;

    assert(hdl->type == TYPE_TMPFS);

    lock(&hdl->lock);
    lock(&hdl->dentry->lock);
    struct shim_tmpfs_data* data;
    ret = tmpfs_get_data(hdl->dentry, &data);
    if (ret < 0)
        goto out;

    ret = mem_file_truncate(&data->mem, size);
    if (ret < 0)
        goto out;

    data->mtime = time_us / USEC_IN_SEC;
    ret = 0;

out:
    unlock(&hdl->dentry->lock);
    unlock(&hdl->lock);
    return ret;
}

static file_off_t tmpfs_seek(struct shim_handle* hdl, file_off_t offset, int whence) {
    file_off_t ret;

    assert(hdl->type == TYPE_TMPFS);

    lock(&hdl->lock);
    lock(&hdl->dentry->lock);
    struct shim_tmpfs_data* data;
    ret = tmpfs_get_data(hdl->dentry, &data);
    if (ret < 0)
        goto out;

    file_off_t pos = hdl->info.tmpfs.pos;
    ret = generic_seek(pos, data->mem.size, offset, whence, &pos);
    if (ret < 0)
        goto out;
    hdl->info.tmpfs.pos = pos;
    ret = pos;

out:
    unlock(&hdl->dentry->lock);
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

    log_error("tmpfs_mmap(): mmap() function for tmpfs mount type is not implemented.");
    return -ENOSYS;
}

static int tmpfs_hstat(struct shim_handle* handle, struct stat* buf) {
    assert(handle->dentry);
    return tmpfs_stat(handle->dentry, buf);
}

static int tmpfs_poll(struct shim_handle* hdl, int poll_type) {
    int ret;

    assert(hdl->type == TYPE_TMPFS);

    lock(&hdl->lock);
    lock(&hdl->dentry->lock);
    struct shim_tmpfs_data* data;
    ret = tmpfs_get_data(hdl->dentry, &data);
    if (ret < 0)
        goto out;

    ret = mem_file_poll(&data->mem, hdl->info.tmpfs.pos, poll_type);

out:
    unlock(&hdl->dentry->lock);
    unlock(&hdl->lock);
    return ret;
}

struct shim_fs_ops tmp_fs_ops = {
    .mount    = &tmpfs_mount,
    .unmount  = &tmpfs_unmount,
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
    .lookup  = &tmpfs_lookup,
    .creat   = &tmpfs_creat,
    .mkdir   = &tmpfs_mkdir,
    .stat    = &tmpfs_stat,
    .readdir = &tmpfs_readdir,
    .unlink  = &tmpfs_unlink,
    .rename  = &tmpfs_rename,
    .chmod   = &tmpfs_chmod,
};

struct shim_fs tmp_builtin_fs = {
    .name   = "tmpfs",
    .fs_ops = &tmp_fs_ops,
    .d_ops  = &tmp_d_ops,
};
