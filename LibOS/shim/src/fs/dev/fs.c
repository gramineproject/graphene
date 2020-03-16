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
 * This file contains codes for implementation of 'dev' filesystem.
 */

#define __KERNEL__

#include <asm/fcntl.h>
#include <asm/mman.h>
#include <asm/prctl.h>
#include <asm/unistd.h>
#include <errno.h>
#include <linux/fcntl.h>
#include <linux/stat.h>

#include <pal.h>
#include <pal_error.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_profile.h>
#include <shim_utils.h>

#define EMPTY_DEV_OPS     \
    {                     \
        .open     = NULL, \
        .close    = NULL, \
        .read     = NULL, \
        .write    = NULL, \
        .flush    = NULL, \
        .seek     = NULL, \
        .truncate = NULL, \
        .mode     = NULL, \
        .stat     = NULL, \
        .hstat    = NULL, \
    }

#define DEV_INO_BASE 1025

static ssize_t dev_null_read(struct shim_handle* hdl, void* buf, size_t count) {
    // Arguments for compatibility
    __UNUSED(hdl);
    __UNUSED(buf);
    __UNUSED(count);

    return 0;
}

static ssize_t dev_zero_read(struct shim_handle* hdl, void* buf, size_t count) {
    // Argument for compatibility
    __UNUSED(hdl);

    memset(buf, 0, count);
    return count;
}

static ssize_t dev_null_write(struct shim_handle* hdl, const void* buf, size_t count) {
    // Arguments for compatibility
    __UNUSED(hdl);
    __UNUSED(buf);
    __UNUSED(count);

    return count;
}

static int dev_null_mode(const char* name, mode_t* mode) {
    __UNUSED(name);  // We know it is /dev/null

    *mode = 0666 | S_IFCHR;
    return 0;
}

static int dev_null_stat(const char* name, struct stat* stat) {
    __UNUSED(name);  // We know it is /dev/null

    stat->st_mode    = 0666 | S_IFCHR;
    stat->st_uid     = 0;
    stat->st_gid     = 0;
    stat->st_size    = 0;
    stat->st_blksize = 0;
    return 0;
}

static int dev_null_hstat(struct shim_handle* hdl, struct stat* stat) {
    __UNUSED(hdl);  // We know it is /dev/null

    stat->st_mode    = 0666 | S_IFCHR;
    stat->st_uid     = 0;
    stat->st_gid     = 0;
    stat->st_size    = 0;
    stat->st_blksize = 0;
    return 0;
}

static int dev_null_truncate(struct shim_handle* hdl, uint64_t size) {
    // Arguments for compatibility
    __UNUSED(hdl);
    __UNUSED(size);

    return 0;
}

static int dev_random_mode(const char* name, mode_t* mode) {
    __UNUSED(name);  // We know it is /dev/random

    *mode = 0666 | S_IFCHR;
    return 0;
}

static ssize_t dev_urandom_read(struct shim_handle* hdl, void* buf, size_t count) {
    __UNUSED(hdl);
    ssize_t ret = DkRandomBitsRead(buf, count);

    if (ret < 0)
        return -convert_pal_errno(-ret);
    return count;
}

static ssize_t dev_random_read(struct shim_handle* hdl, void* buf, size_t count) {
    return dev_urandom_read(hdl, buf, count);
}

static int dev_random_stat(const char* name, struct stat* stat) {
    __UNUSED(name);  // we know it is /dev/random

    stat->st_mode    = 0666 | S_IFCHR;
    stat->st_uid     = 0;
    stat->st_gid     = 0;
    stat->st_size    = 0;
    stat->st_blksize = 0;
    return 0;
}

static int dev_random_hstat(struct shim_handle* hdl, struct stat* stat) {
    __UNUSED(hdl);  // pseudo-device

    stat->st_mode    = 0444 | S_IFCHR;
    stat->st_uid     = 0;
    stat->st_gid     = 0;
    stat->st_size    = 0;
    stat->st_blksize = 0;
    return 0;
}

static int search_dev_driver(const char* name, struct shim_dev_ops* ops) {
    if (!strcmp_static(name, "null") || !strcmp_static(name, "tty")) {
        if (ops)
            ops->read = &dev_null_read;
    null_dev:
        if (ops) {
            ops->write    = &dev_null_write;
            ops->truncate = &dev_null_truncate;
            ops->mode     = &dev_null_mode;
            ops->stat     = &dev_null_stat;
            ops->hstat    = &dev_null_hstat;
        }
        return 0;
    }

    if (!strcmp_static(name, "zero")) {
        if (ops)
            ops->read = &dev_zero_read;
        goto null_dev;
    }

    if (!strcmp_static(name, "random")) {
        if (ops)
            ops->read = &dev_random_read;
    random_dev:
        if (ops) {
            ops->mode  = &dev_random_mode;
            ops->stat  = &dev_random_stat;
            ops->hstat = &dev_random_hstat;
        }
        return 0;
    }

    if (!strcmp_static(name, "urandom")) {
        if (ops)
            ops->read = &dev_urandom_read;
        goto random_dev;
    }

    if (!strcmp_static(name, "stdin") || !strcmp_static(name, "stdout") ||
        !strcmp_static(name, "stderr"))
        return -EISLINK;

    return -ENOENT;
}

static int dev_mount(const char* uri, void** mount_data) {
    // Arguments for compatibility
    __UNUSED(uri);
    __UNUSED(mount_data);

    /* do nothing */
    return 0;
}

static int dev_unmount(void* mount_data) {
    // Arguments for compatibility
    __UNUSED(mount_data);

    /* do nothing */
    return 0;
}

static int dev_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags) {
    struct shim_dev_ops ops_buf = EMPTY_DEV_OPS;
    int ret                     = search_dev_driver(qstrgetstr(&dent->rel_path), &ops_buf);

    if (ret < 0)
        return ret;

    hdl->type     = TYPE_DEV;
    hdl->flags    = flags & ~O_ACCMODE;
    hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);

    memcpy(&hdl->info.dev.dev_ops, &ops_buf, sizeof(struct shim_dev_ops));

    if (!ops_buf.read && (hdl->acc_mode & MAY_READ))
        return -EACCES;

    if (!ops_buf.write && (hdl->acc_mode & MAY_WRITE))
        return -EACCES;

    if (ops_buf.open)
        return ops_buf.open(hdl, qstrgetstr(&dent->rel_path), flags);

    return 0;
}

static int dev_lookup(struct shim_dentry* dent) {
    if (qstrempty(&dent->rel_path)) {
        dent->state |= DENTRY_ISDIRECTORY;
        dent->ino = DEV_INO_BASE;
        return 0;
    }

    /* we don't care about forced or not */
    return search_dev_driver(qstrgetstr(&dent->rel_path), NULL);
}

static int dev_mode(struct shim_dentry* dent, mode_t* mode) {
    if (qstrempty(&dent->rel_path)) {
        dent->ino = DEV_INO_BASE;
        *mode     = 0555 | S_IFDIR;
        return 0;
    }

    /* we don't care about forced or not */
    struct shim_dev_ops ops_buf = EMPTY_DEV_OPS;
    int ret                     = search_dev_driver(qstrgetstr(&dent->rel_path), &ops_buf);

    if (ret < 0)
        return ret;

    return ops_buf.mode(qstrgetstr(&dent->rel_path), mode);
}

static int dev_flush(struct shim_handle* hdl) {
    if (!hdl->info.dev.dev_ops.flush)
        return 0;

    return hdl->info.dev.dev_ops.flush(hdl);
}

static int dev_close(struct shim_handle* hdl) {
    if (!hdl->info.dev.dev_ops.close)
        return 0;

    return hdl->info.dev.dev_ops.close(hdl);
}

static ssize_t dev_read(struct shim_handle* hdl, void* buf, size_t count) {
    if (!hdl->info.dev.dev_ops.read)
        return -EACCES;

    return hdl->info.dev.dev_ops.read(hdl, buf, count);
}

static ssize_t dev_write(struct shim_handle* hdl, const void* buf, size_t count) {
    if (!hdl->info.dev.dev_ops.write)
        return -EACCES;

    return hdl->info.dev.dev_ops.write(hdl, buf, count);
}

static off_t dev_seek(struct shim_handle* hdl, off_t offset, int wence) {
    if (!hdl->info.dev.dev_ops.seek)
        return -EACCES;

    return hdl->info.dev.dev_ops.seek(hdl, offset, wence);
}

static int dev_truncate(struct shim_handle* hdl, off_t len) {
    if (!hdl->info.dev.dev_ops.truncate)
        return -EACCES;

    return hdl->info.dev.dev_ops.truncate(hdl, len);
}

static int dev_readdir(struct shim_dentry* dent, struct shim_dirent** dirent) {
    if (!qstrempty(&dent->rel_path)) {
        struct shim_dev_ops ops_buf = EMPTY_DEV_OPS;
        int ret                     = search_dev_driver(qstrgetstr(&dent->rel_path), &ops_buf);

        if (ret < 0 && ret != -EISLINK)
            return ret;

        return -ENOTDIR;
    }

    struct shim_dirent *buf, *ptr;
    int buf_size = MAX_PATH;

retry:
    buf     = malloc(buf_size);
    *dirent = ptr = buf;
    struct shim_dirent** last = dirent;

#define COPY_ENTRY(devname, devtype)                                 \
    do {                                                             \
        int name_len = strlen(devname);                              \
                                                                     \
        if ((void*)(ptr + 1) + name_len + 1 > (void*)buf + buf_size) \
            goto nomem;                                              \
                                                                     \
        ptr->next = (void*)(ptr + 1) + name_len + 1;                 \
        ptr->ino  = 1;                                               \
        ptr->type = (devtype);                                       \
        memcpy(ptr->name, (devname), name_len + 1);                  \
        last = &ptr->next;                                           \
        ptr  = ptr->next;                                            \
    } while (0)

    COPY_ENTRY("null", LINUX_DT_CHR);
    COPY_ENTRY("zero", LINUX_DT_CHR);
    COPY_ENTRY("stdin", LINUX_DT_LNK);
    COPY_ENTRY("stdout", LINUX_DT_LNK);
    COPY_ENTRY("stderr", LINUX_DT_LNK);
#undef COPY_ENTRY

    *last = NULL;
    return 0;

nomem:
    buf_size *= 2;
    free(buf);
    goto retry;
}

static int dev_stat(struct shim_dentry* dent, struct stat* buf) {
    if (qstrempty(&dent->rel_path)) {
        buf->st_dev     = DEV_INO_BASE;
        buf->st_ino     = DEV_INO_BASE;
        buf->st_mode    = 0777 | S_IFDIR;
        buf->st_size    = 4096;
        buf->st_blksize = 4096;
        return 0;
    }

    struct shim_dev_ops ops_buf = EMPTY_DEV_OPS;
    int ret                     = search_dev_driver(qstrgetstr(&dent->rel_path), &ops_buf);

    if (ret < 0 && ret != -EISLINK)
        return ret;

    if (ret == -EISLINK) {
        buf->st_dev     = DEV_INO_BASE;
        buf->st_ino     = DEV_INO_BASE;
        buf->st_mode    = 0777 | S_IFLNK;
        buf->st_size    = 0;
        buf->st_blksize = 0;
        return 0;
    }

    buf->st_dev = DEV_INO_BASE;
    buf->st_ino = DEV_INO_BASE;

    return ops_buf.stat ? ops_buf.stat(qstrgetstr(&dent->rel_path), buf) : -EACCES;
}

static int dev_hstat(struct shim_handle* hdl, struct stat* buf) {
    if (!hdl->info.dev.dev_ops.hstat)
        return -EACCES;

    return hdl->info.dev.dev_ops.hstat(hdl, buf);
}

static off_t dev_poll(struct shim_handle* hdl, int poll_type) {
    if (poll_type == FS_POLL_SZ)
        return 0;

    off_t ret = 0;
    if ((poll_type & FS_POLL_RD) && hdl->info.dev.dev_ops.read)
        ret |= FS_POLL_RD;
    if ((poll_type & FS_POLL_WR) && hdl->info.dev.dev_ops.write)
        ret |= FS_POLL_WR;

    return ret;
}

static int dev_follow_link(struct shim_dentry* dent, struct shim_qstr* link) {
    const char* name = qstrgetstr(&dent->rel_path);

    if (!strcmp_static(name, "stdin")) {
        qstrsetstr(link, "/proc/self/0", static_strlen("/proc/self/0"));
        return 0;
    } else if (!strcmp_static(name, "stdout")) {
        qstrsetstr(link, "/proc/self/1", static_strlen("/proc/self/1"));
        return 0;
    } else if (!strcmp_static(name, "stderr")) {
        qstrsetstr(link, "/proc/self/2", static_strlen("/proc/self/2"));
        return 0;
    }

    if (!strcmp_static(name, "null") || !strcmp_static(name, "zero"))
        return -ENOTLINK;

    return -ENOENT;
}

int dev_update_dev_ops(struct shim_handle* hdl) {
    int ret;
    char buf[STR_SIZE];
    size_t bufsize = sizeof(buf);
    struct shim_dev_ops ops_buf = EMPTY_DEV_OPS;

    assert(hdl && hdl->type == TYPE_DEV);

    ret = get_base_name(qstrgetstr(&hdl->path), buf, &bufsize);
    if (ret < 0)
        return -ENOENT;

    ret = search_dev_driver(buf, &ops_buf);
    if (ret < 0)
        return ret;

    memcpy(&hdl->info.dev.dev_ops, &ops_buf, sizeof(ops_buf));
    return 0;
}

struct shim_fs_ops dev_fs_ops = {
    .mount    = &dev_mount,
    .unmount  = &dev_unmount,
    .flush    = &dev_flush,
    .close    = &dev_close,
    .read     = &dev_read,
    .write    = &dev_write,
    .seek     = &dev_seek,
    .hstat    = &dev_hstat,
    .poll     = &dev_poll,
    .truncate = &dev_truncate,
};

struct shim_d_ops dev_d_ops = {
    .open        = &dev_open,
    .lookup      = &dev_lookup,
    .mode        = &dev_mode,
    .readdir     = &dev_readdir,
    .stat        = &dev_stat,
    .follow_link = &dev_follow_link,
};
