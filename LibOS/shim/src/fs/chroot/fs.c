/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * This file contains code for implementation of 'chroot' filesystem.
 */

#define _POSIX_C_SOURCE 200809L /* for SSIZE_MAX */
#include <asm/fcntl.h>
#include <asm/mman.h>
#include <asm/unistd.h>
#include <errno.h>
#include <limits.h>
#include <linux/fcntl.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_flags_conv.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_thread.h"
#include "shim_utils.h"
#include "shim_vma.h"
#include "stat.h"

struct chroot_mount_data {
    /* Device number to use for `st_dev` */
    unsigned long dev;

    /* Default file type (S_IFREG for regular files, S_IFCHR for devices). See `chroot_lookup`. */
    mode_t default_type;

    /* Root of the filesystem on host (URI without the scheme) */
    size_t root_len;
    char root[];
};

static int chroot_mount(const char* uri, void** mount_data) {
    const char* root;

    mode_t default_type;
    if (strstartswith(uri, URI_PREFIX_FILE)) {
        default_type = S_IFREG;
        root = uri + strlen(URI_PREFIX_FILE);
    } else if (strstartswith(uri, URI_PREFIX_DEV)) {
        default_type = S_IFCHR;
        root = uri + strlen(URI_PREFIX_DEV);
    } else {
        return -EINVAL;
    }

    /* Treat empty path as "." */
    if (*root == '\0')
        root = ".";

    size_t root_len = strlen(root);
    struct chroot_mount_data* mdata = malloc(sizeof(struct chroot_mount_data) + root_len + 1);
    if (!mdata)
        return -ENOMEM;

    mdata->dev = hash_str(uri);
    mdata->default_type = default_type;
    mdata->root_len = root_len;
    memcpy(&mdata->root, root, root_len + 1);
    *mount_data = mdata;
    return 0;
}

static int chroot_unmount(void* mount_data) {
    free(mount_data);
    return 0;
}

/*
 * Calculate the URI for a dentry. The URI scheme is determined by file type (`type` field). It
 * needs to be passed separately (instead of using `dent->type`) because the dentry might not have
 * this information yet: we might be creating a new file, or looking up a file we don't know yet.
 */
static int chroot_dentry_uri(struct shim_dentry* dent, mode_t type, char** out_uri) {
    int ret;

    const char* prefix;
    switch (type) {
        case S_IFREG:
            prefix = URI_PREFIX_FILE;
            break;
        case S_IFDIR:
            prefix = URI_PREFIX_DIR;
            break;
        case S_IFCHR:
            prefix = URI_PREFIX_DEV;
            break;
        default:
            BUG();
    }
    size_t prefix_len = strlen(prefix);

    char* rel_path;
    size_t rel_path_size;
    ret = dentry_rel_path(dent, &rel_path, &rel_path_size);
    if (ret < 0)
        return ret;

    struct chroot_mount_data* mdata = dent->mount->data;

    char* uri;
    if (rel_path_size == 1) {
        /* this is the mount root, the URI is "<prefix:><root>" */
        uri = malloc(prefix_len + mdata->root_len + 1);
        if (!uri) {
            ret = -ENOMEM;
            goto out;
        }
        memcpy(uri, prefix, prefix_len);
        memcpy(uri + prefix_len, mdata->root, mdata->root_len + 1);
    } else {
        /* this is not the mount root, the URI is "<prefix:><root>/<rel_path>" */
        uri = malloc(prefix_len + mdata->root_len + 1 + rel_path_size);
        if (!uri) {
            ret = -ENOMEM;
            goto out;
        }
        memcpy(uri, prefix, prefix_len);
        memcpy(uri + prefix_len, mdata->root, mdata->root_len);
        uri[prefix_len + mdata->root_len] = '/';
        memcpy(uri + prefix_len + mdata->root_len + 1, rel_path, rel_path_size);
    }
    *out_uri = uri;
    ret = 0;

out:
    free(rel_path);
    return ret;
}

static int chroot_init_dentry(struct shim_dentry* dent, mode_t type, mode_t perm, file_off_t size) {
    assert(locked(&dent->lock));
    assert(!dent->inode);

    dent->type = type;
    dent->perm = perm;

    struct shim_inode* inode = get_new_inode(dent->mount, type, perm);
    if (!inode)
        return -ENOMEM;
    inode->size = size;
    dent->inode = inode;
    return 0;
}

static int chroot_lookup(struct shim_dentry* dent) {
    int ret;

    lock(&dent->lock);

    struct chroot_mount_data* mdata = dent->mount->data;

    /*
     * We don't know the file type yet, so we can't construct a PAL URI with the right prefix. Use
     * the file type from mount URI.
     *
     * Explanation: In almost all cases, a "file:" URI would be good enough. If the underlying file
     * is a directory or a device, `DkStreamAttributesQuery` will still recognize it. However, PAL
     * also recognizes a special "dev:tty" device, which doesn't work that way (i.e. "file:tty" will
     * not open it).
     */
    char* uri = NULL;
    ret = chroot_dentry_uri(dent, mdata->default_type, &uri);
    if (ret < 0)
        goto out;

    PAL_STREAM_ATTR pal_attr;
    ret = DkStreamAttributesQuery(uri, &pal_attr);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    mode_t type;
    switch (pal_attr.handle_type) {
        case pal_type_file:
            type = S_IFREG;
            break;
        case pal_type_dir:
            type = S_IFDIR;
            break;
        case pal_type_dev:
            type = S_IFCHR;
            break;
        case pal_type_pipe:
            log_warning("trying to access '%s' which is a host-level FIFO (named pipe); "
                        "Graphene supports only named pipes created by Graphene processes",
                        uri);
            ret = -EACCES;
            goto out;
        default:
            log_error("unexpected handle type returned by PAL: %d", pal_attr.handle_type);
            BUG();
    }

    mode_t perm = (pal_attr.readable ? S_IRUSR : 0) |
                  (pal_attr.writable ? S_IWUSR : 0) |
                  (pal_attr.runnable ? S_IXUSR : 0);

    file_off_t size = (type == S_IFREG ? pal_attr.pending_size : 0);

    ret = chroot_init_dentry(dent, type, perm, size);
out:
    unlock(&dent->lock);
    return ret;
}

/* Open a temporary read-only PAL handle for a file (used by `unlink` etc.) */
static int chroot_temp_open(struct shim_dentry* dent, mode_t type, PAL_HANDLE* palhdl) {
    char* uri;
    int ret = chroot_dentry_uri(dent, type, &uri);
    if (ret < 0)
        return ret;

    ret = DkStreamOpen(uri, PAL_ACCESS_RDONLY, /*share_flags=*/0, /*create=*/0, /*options=*/0,
                       palhdl);
    if (ret < 0)
        return pal_to_unix_errno(ret);

    return 0;
}

/* Open a PAL handle, and associate it with a LibOS handle (if provided). */
static int chroot_do_open(struct shim_handle* hdl, struct shim_dentry* dent, mode_t type,
                          int flags, mode_t mode) {
    assert(locked(&dent->lock));

    int ret;

    char* uri;
    ret = chroot_dentry_uri(dent, type, &uri);
    if (ret < 0)
        return ret;

    PAL_HANDLE palhdl;
    int access = LINUX_OPEN_FLAGS_TO_PAL_ACCESS(flags);
    int create = LINUX_OPEN_FLAGS_TO_PAL_CREATE(flags);
    int options = LINUX_OPEN_FLAGS_TO_PAL_OPTIONS(flags);
    ret = DkStreamOpen(uri, access, mode, create, options, &palhdl);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    if (hdl) {
        if (!qstrsetstr(&hdl->uri, uri, strlen(uri))) {
            DkObjectClose(palhdl);
            ret = -ENOMEM;
            goto out;
        }

        hdl->type = TYPE_CHROOT;
        hdl->info.chroot.pos = 0;
        hdl->flags = flags;
        hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);
        hdl->pal_handle = palhdl;
    } else {
        DkObjectClose(palhdl);
    }

    ret = 0;

out:
    free(uri);
    return ret;
}

static int chroot_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags) {
    int ret;

    lock(&dent->lock);
    if (!dent->inode) {
        ret = -ENOENT;
        goto out;
    }

    ret = chroot_do_open(hdl, dent, dent->type, flags, /*mode=*/0);
    if (ret < 0)
        goto out;

    hdl->inode = dent->inode;
    get_inode(dent->inode);

out:
    unlock(&dent->lock);
    return ret;
}

static int chroot_creat(struct shim_handle* hdl, struct shim_dentry* dir, struct shim_dentry* dent,
                        int flags, mode_t mode) {
    __UNUSED(dir);

    int ret;

    mode_t type = S_IFREG;
    mode_t perm = mode & ~S_IFMT;

    lock(&dent->lock);
    ret = chroot_do_open(hdl, dent, type, flags | O_CREAT | O_EXCL, perm);
    if (ret < 0)
        goto out;

    ret = chroot_init_dentry(dent, type, perm, /*size=*/0);
    if (ret < 0)
        goto out;

    hdl->inode = dent->inode;
    get_inode(dent->inode);

out:
    unlock(&dent->lock);
    return ret;
}

static int chroot_mkdir(struct shim_dentry* dir, struct shim_dentry* dent, mode_t mode) {
    __UNUSED(dir);

    int ret;

    mode_t type = S_IFDIR;
    mode_t perm = mode & ~S_IFMT;

    lock(&dent->lock);
    ret = chroot_do_open(/*hdl=*/NULL, dent, type, O_CREAT | O_EXCL, perm);
    if (ret < 0)
        goto out;

    ret = chroot_init_dentry(dent, type, perm, /*size=*/0);
out:
    unlock(&dent->lock);
    return ret;
}

static int chroot_istat(struct shim_inode* inode, struct stat* buf) {
    memset(buf, 0, sizeof(*buf));

    lock(&inode->lock);
    buf->st_mode = inode->type | inode->perm;
    buf->st_size = inode->size;
    /*
     * Pretend `nlink` is 2 for directories (to account for "." and ".."), 1 for other files.
     *
     * Applications are unlikely to depend on exact value of `nlink`, and for us, it's inconvenient
     * to keep track of the exact value (we would have to list the directory, and also take into
     * account synthetic files created by Graphene, such as named pipes and sockets).
     *
     * TODO: Make this a default for filesystems that don't provide `nlink`?
     */
    buf->st_nlink = (inode->type == FILE_DIR ? 2 : 1);
    unlock(&inode->lock);
    return 0;
}

static int chroot_stat(struct shim_dentry* dent, struct stat* buf) {
    int ret;

    lock(&dent->lock);
    if (!dent->inode) {
        ret = -ENOENT;
        goto out;
    }

    ret = chroot_istat(dent->inode, buf);
    if (ret < 0)
        goto out;

    struct chroot_mount_data* mdata = dent->mount->data;
    buf->st_dev = mdata->dev;
    ret = 0;
out:
    unlock(&dent->lock);
    return ret;
}

static int chroot_hstat(struct shim_handle* hdl, struct stat* buf) {
    assert(hdl->type == TYPE_CHROOT);

    return chroot_istat(hdl->inode, buf);
}

static int chroot_flush(struct shim_handle* hdl) {
    assert(hdl->type == TYPE_CHROOT);

    int ret = DkStreamFlush(hdl->pal_handle);
    return pal_to_unix_errno(ret);
}

static ssize_t chroot_read(struct shim_handle* hdl, void* buf, size_t count) {
    assert(hdl->type == TYPE_CHROOT);

    ssize_t ret;

    if (count == 0)
        return 0;

    if (count > SSIZE_MAX)
        return -EFBIG;

    struct shim_inode* inode = hdl->inode;
    lock(&hdl->lock);

    file_off_t pos = hdl->info.chroot.pos;

    /* Make sure won't overflow `pos` */
    file_off_t max_end_pos;
    if (inode->type == S_IFREG && __builtin_add_overflow(pos, count, &max_end_pos)) {
        ret = -EFBIG;
        goto out;
    }

    size_t actual_count = count;
    ret = DkStreamRead(hdl->pal_handle, pos, &actual_count, buf, /*source=*/NULL, /*size=*/0);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }
    assert(actual_count <= count);
    if (inode->type == S_IFREG) {
        pos += actual_count;
        hdl->info.chroot.pos = pos;
    }
    ret = actual_count;

out:
    unlock(&hdl->lock);
    return ret;
}

static ssize_t chroot_write(struct shim_handle* hdl, const void* buf, size_t count) {
    assert(hdl->type == TYPE_CHROOT);

    ssize_t ret;

    if (count == 0)
        return 0;

    if (count > SSIZE_MAX)
        return -EFBIG;

    struct shim_inode* inode = hdl->inode;
    lock(&hdl->lock);

    file_off_t pos = hdl->info.chroot.pos;

    /* Make sure won't overflow `pos` */
    file_off_t max_end_pos;
    if (inode->type == S_IFREG && __builtin_add_overflow(pos, count, &max_end_pos)) {
        ret = -EFBIG;
        goto out;
    }

    size_t actual_count = count;
    ret = DkStreamWrite(hdl->pal_handle, pos, &actual_count, (void*)buf, /*dest=*/NULL);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }
    if (actual_count > count)
        BUG();
    if (inode->type == S_IFREG) {
        pos += actual_count;
        hdl->info.chroot.pos = pos;

        /* Update file size, if necessary */
        lock(&inode->lock);
        if (inode->size < pos)
            inode->size = pos;
        unlock(&inode->lock);
    }
    ret = actual_count;

out:
    unlock(&hdl->lock);
    return ret;
}

static int chroot_mmap(struct shim_handle* hdl, void** addr, size_t size, int prot, int flags,
                       uint64_t offset) {
    assert(hdl->type == TYPE_CHROOT);

    int pal_prot = LINUX_PROT_TO_PAL(prot, flags);

#if MAP_FILE == 0
    if (flags & MAP_ANONYMOUS)
#else
    if (!(flags & MAP_FILE))
#endif
        return -EINVAL;

    int ret = DkStreamMap(hdl->pal_handle, addr, pal_prot, offset, size);
    return pal_to_unix_errno(ret);
}

static file_off_t chroot_seek(struct shim_handle* hdl, file_off_t offset, int whence) {
    assert(hdl->type == TYPE_CHROOT);

    file_off_t ret;

    lock(&hdl->lock);
    file_off_t pos = hdl->info.chroot.pos;

    lock(&hdl->inode->lock);
    file_off_t size = hdl->inode->size;
    unlock(&hdl->inode->lock);

    ret = generic_seek(pos, size, offset, whence, &pos);
    if (ret == 0) {
        hdl->info.chroot.pos = pos;
        ret = pos;
    }
    unlock(&hdl->lock);
    return ret;
}

static int chroot_truncate(struct shim_handle* hdl, file_off_t size) {
    assert(hdl->type == TYPE_CHROOT);

    int ret;

    lock(&hdl->lock);
    lock(&hdl->inode->lock);
    ret = DkStreamSetLength(hdl->pal_handle, size);
    if (ret == 0) {
        hdl->inode->size = size;
    } else {
        ret = pal_to_unix_errno(ret);
    }
    unlock(&hdl->inode->lock);
    unlock(&hdl->lock);
    return ret;
}

static int chroot_readdir(struct shim_dentry* dent, readdir_callback_t callback, void* arg) {
    int ret;
    PAL_HANDLE palhdl;
    char* buf = NULL;
    size_t buf_size = READDIR_BUF_SIZE;

    ret = chroot_temp_open(dent, S_IFDIR, &palhdl);
    if (ret < 0)
        return ret;

    buf = malloc(buf_size);
    if (!buf) {
        ret = -ENOMEM;
        goto out;
    }

    while (true) {
        size_t read_size = buf_size;
        ret = DkStreamRead(palhdl, 0, &read_size, buf, /*source=*/NULL, /*size=*/0);
        if (ret < 0) {
            ret = pal_to_unix_errno(ret);
            goto out;
        }
        if (read_size == 0) {
            /* End of directory listing */
            break;
        }

        /* Last entry must be null-terminated */
        assert(buf[read_size - 1] == '\0');

        /* Read all entries (separated by null bytes) and invoke `callback` on each */
        size_t start = 0;
        while (start < read_size - 1) {
            size_t end = start;
            while (buf[end] != '\0')
                end++;

            if (end == start) {
                log_error("chroot_readdir: empty name returned from PAL");
                die_or_inf_loop();
            }

            /* By the PAL convention, if a name ends with '/', it is a directory. However, we ignore
             * that distinction here and pass the name without '/' to the callback. */
            if (buf[end - 1] == '/')
                buf[end - 1] = '\0';

            if ((ret = callback(&buf[start], arg)) < 0)
                goto out;

            start = end + 1;
        }
    }
    ret = 0;

out:
    free(buf);
    DkObjectClose(palhdl);
    return ret;
}

static ssize_t chroot_checkpoint(void** checkpoint, void* data) {
    struct chroot_mount_data* mdata = data;

    *checkpoint = mdata;
    return sizeof(struct chroot_mount_data) + mdata->root_len + 1;
}

static int chroot_migrate(void* checkpoint, void** data) {
    struct chroot_mount_data* mdata = checkpoint;

    size_t alloc_size = sizeof(struct chroot_mount_data) + mdata->root_len + 1;

    void* new_data = malloc(alloc_size);
    if (!new_data)
        return -ENOMEM;

    memcpy(new_data, mdata, alloc_size);
    *data = new_data;

    return 0;
}

static int chroot_unlink(struct shim_dentry* dir, struct shim_dentry* dent) {
    __UNUSED(dir);

    int ret;

    lock(&dent->lock);

    PAL_HANDLE palhdl;
    ret = chroot_temp_open(dent, dent->type, &palhdl);
    if (ret < 0)
        goto out;

    ret = DkStreamDelete(palhdl, /*access=*/0);
    DkObjectClose(palhdl);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    struct shim_inode* inode = dent->inode;
    dent->inode = NULL;
    put_inode(inode);

out:
    unlock(&dent->lock);
    return ret;
}

static int chroot_poll(struct shim_handle* hdl, int poll_type) {
    assert(hdl->type == TYPE_CHROOT);

    int ret;

    lock(&hdl->lock);
    lock(&hdl->inode->lock);

    if (hdl->inode->type == S_IFREG) {
        ret = 0;
        if (poll_type & FS_POLL_WR)
            ret |= FS_POLL_WR;
        if ((poll_type & FS_POLL_RD) && hdl->info.chroot.pos < hdl->inode->size)
            ret |= FS_POLL_RD;
    } else {
        ret = -EAGAIN;
    }

    unlock(&hdl->inode->lock);
    unlock(&hdl->lock);
    return ret;
}

static int chroot_rename(struct shim_dentry* old, struct shim_dentry* new) {
    int ret;
    char* new_uri = NULL;

    lock_two_dentries(old, new);

    ret = chroot_dentry_uri(new, old->type, &new_uri);
    if (ret < 0)
        goto out;

    PAL_HANDLE palhdl;
    ret = chroot_temp_open(old, old->type, &palhdl);
    if (ret < 0)
        goto out;

    ret = DkStreamChangeName(palhdl, new_uri);
    DkObjectClose(palhdl);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    struct shim_inode* inode = new->inode;
    if (inode) {
        new->inode = NULL;
        put_inode(inode);
    }

    new->inode = old->inode;
    new->type = old->type;
    new->perm = old->perm;

    old->inode = NULL;
    ret = 0;

out:
    unlock_two_dentries(old, new);
    free(new_uri);
    return ret;
}

static int chroot_chmod(struct shim_dentry* dent, mode_t mode) {
    int ret;

    lock(&dent->lock);
    lock(&dent->inode->lock);

    PAL_HANDLE palhdl;
    ret = chroot_temp_open(dent, dent->type, &palhdl);
    if (ret < 0)
        goto out;

    PAL_STREAM_ATTR attr = {.share_flags = mode};
    ret = DkStreamAttributesSetByHandle(palhdl, &attr);
    DkObjectClose(palhdl);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    dent->perm = mode & ~S_IFMT;
    dent->inode->perm = mode & ~S_IFMT;
    ret = 0;

out:
    unlock(&dent->inode->lock);
    unlock(&dent->lock);
    return ret;
}

struct shim_fs_ops chroot_fs_ops = {
    .mount      = &chroot_mount,
    .unmount    = &chroot_unmount,
    .flush      = &chroot_flush,
    .read       = &chroot_read,
    .write      = &chroot_write,
    .mmap       = &chroot_mmap,
    .seek       = &chroot_seek,
    .hstat      = &chroot_hstat,
    .truncate   = &chroot_truncate,
    .checkpoint = &chroot_checkpoint,
    .migrate    = &chroot_migrate,
    .poll       = &chroot_poll,
};

struct shim_d_ops chroot_d_ops = {
    .open    = &chroot_open,
    .lookup  = &chroot_lookup,
    .creat   = &chroot_creat,
    .mkdir   = &chroot_mkdir,
    .stat    = &chroot_stat,
    .readdir = &chroot_readdir,
    .unlink  = &chroot_unlink,
    .rename  = &chroot_rename,
    .chmod   = &chroot_chmod,
};

struct shim_fs chroot_builtin_fs = {
    .name   = "chroot",
    .fs_ops = &chroot_fs_ops,
    .d_ops  = &chroot_d_ops,
};
