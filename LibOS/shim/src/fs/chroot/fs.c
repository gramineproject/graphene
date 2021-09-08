/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * This file contains code for implementation of 'chroot' filesystem.
 *
 * TODO: reintroduce the file position sync (using shim_fs_sync.h) after the migration to inodes is
 * finished.
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

#define KEEP_URI_PREFIX 0

static int chroot_mount(const char* uri, void** mount_data) {
    __UNUSED(mount_data);
    if (!(strstartswith(uri, URI_PREFIX_FILE) || strstartswith(uri, URI_PREFIX_DEV)))
        return -EINVAL;
    return 0;
}

static const char* strip_prefix(const char* uri) {
    const char* s = strchr(uri, ':');
    assert(s);
    return s + 1;
}

/*
 * Calculate the URI for a dentry. The URI scheme is determined by file type (`type` field). It
 * needs to be passed separately (instead of using `dent->type`) because the dentry might not have
 * this information yet: we might be creating a new file, or looking up a file we don't know yet.
 *
 * If `type` is KEEP_URI_PREFIX, we keep the URI prefix from mount URI.
 */
static int chroot_dentry_uri(struct shim_dentry* dent, mode_t type, char** out_uri) {
    assert(dent->mount);
    assert(dent->mount->uri);

    int ret;

    const char* root = strip_prefix(dent->mount->uri);

    const char* prefix;
    size_t prefix_len;
    switch (type) {
        case S_IFREG:
            prefix = URI_PREFIX_FILE;
            prefix_len = static_strlen(URI_PREFIX_FILE);
            break;
        case S_IFDIR:
            prefix = URI_PREFIX_DIR;
            prefix_len = static_strlen(URI_PREFIX_DIR);
            break;
        case S_IFCHR:
            prefix = URI_PREFIX_DEV;
            prefix_len = static_strlen(URI_PREFIX_DEV);
            break;
        case KEEP_URI_PREFIX:
            prefix = dent->mount->uri;
            prefix_len = root - prefix;
            break;
        default:
            BUG();
    }

    char* rel_path;
    size_t rel_path_size;
    ret = dentry_rel_path(dent, &rel_path, &rel_path_size);
    if (ret < 0)
        return ret;

    /* Treat empty path as "." */
    if (*root == '\0')
        root = ".";

    size_t root_len = strlen(root);

    /* Allocate buffer for "<prefix:><root>/<rel_path>" (if `rel_path` is empty, we don't need the
     * space for `/`, but overallocating 1 byte doesn't hurt us, and keeps the code simple) */
    char* uri = malloc(prefix_len + root_len + 1 + rel_path_size);
    if (!uri) {
        ret = -ENOMEM;
        goto out;
    }
    memcpy(uri, prefix, prefix_len);
    memcpy(uri + prefix_len, root, root_len);
    if (rel_path_size == 1) {
        /* this is the mount root, the URI is "<prefix:><root>"*/
        uri[prefix_len + root_len] = '\0';
    } else {
        /* this is not the mount root, the URI is "<prefix:><root>/<rel_path>" */
        uri[prefix_len + root_len] = '/';
        memcpy(uri + prefix_len + root_len + 1, rel_path, rel_path_size);
    }
    *out_uri = uri;
    ret = 0;

out:
    free(rel_path);
    return ret;
}

static int chroot_setup_dentry(struct shim_dentry* dent, mode_t type, mode_t perm,
                               file_off_t size) {
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
    assert(locked(&g_dcache_lock));

    int ret;

    lock(&dent->lock);

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
    ret = chroot_dentry_uri(dent, KEEP_URI_PREFIX, &uri);
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
        case PAL_TYPE_FILE:
            type = S_IFREG;
            break;
        case PAL_TYPE_DIR:
            type = S_IFDIR;
            break;
        case PAL_TYPE_DEV:
            type = S_IFCHR;
            break;
        case PAL_TYPE_PIPE:
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

    ret = chroot_setup_dentry(dent, type, perm, size);
out:
    unlock(&dent->lock);
    free(uri);
    return ret;
}

/* Open a temporary read-only PAL handle for a file (used by `unlink` etc.) */
static int chroot_temp_open(struct shim_dentry* dent, mode_t type, PAL_HANDLE* out_palhdl) {
    char* uri;
    int ret = chroot_dentry_uri(dent, type, &uri);
    if (ret < 0)
        return ret;

    ret = DkStreamOpen(uri, PAL_ACCESS_RDONLY, /*share_flags=*/0, /*create=*/0, /*options=*/0,
                       out_palhdl);
    free(uri);
    return pal_to_unix_errno(ret);
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
    ret = 0;

out:
    unlock(&dent->lock);
    return ret;
}

static int chroot_creat(struct shim_handle* hdl, struct shim_dentry* dir, struct shim_dentry* dent,
                        int flags, mode_t mode) {
    __UNUSED(dir);

    assert(locked(&g_dcache_lock));

    int ret;

    mode_t type = S_IFREG;
    mode_t perm = mode & ~S_IFMT;

    lock(&dent->lock);
    ret = chroot_do_open(hdl, dent, type, flags | O_CREAT | O_EXCL, perm);
    if (ret < 0)
        goto out;

    ret = chroot_setup_dentry(dent, type, perm, /*size=*/0);
    if (ret < 0)
        goto out;

    hdl->inode = dent->inode;
    get_inode(dent->inode);
    ret = 0;

out:
    unlock(&dent->lock);
    return ret;
}

static int chroot_mkdir(struct shim_dentry* dir, struct shim_dentry* dent, mode_t mode) {
    __UNUSED(dir);

    assert(locked(&g_dcache_lock));

    int ret;

    mode_t type = S_IFDIR;
    mode_t perm = mode & ~S_IFMT;

    lock(&dent->lock);
    ret = chroot_do_open(/*hdl=*/NULL, dent, type, O_CREAT | O_EXCL, perm);
    if (ret < 0)
        goto out;

    ret = chroot_setup_dentry(dent, type, perm, /*size=*/0);
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

    buf->st_dev = hash_str(dent->mount->uri);
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
        hdl->info.chroot.pos += actual_count;
    }
    ret = actual_count;

out:
    unlock(&hdl->lock);
    return ret;
}

static ssize_t chroot_write(struct shim_handle* hdl, const void* buf, size_t count) {
    assert(hdl->type == TYPE_CHROOT);

    ssize_t ret;

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
    assert(count <= actual_count);
    if (inode->type == S_IFREG) {
        pos += actual_count;
        hdl->info.chroot.pos = pos;

        /* Update file size if we just wrote past the end of file */
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

    if (flags & MAP_ANONYMOUS)
        return -EINVAL;

    int ret = DkStreamMap(hdl->pal_handle, addr, pal_prot, offset, size);
    return pal_to_unix_errno(ret);
}

/* TODO: this function emulates lseek() completely inside the LibOS, but some device files may
 * report size == 0 during fstat() and may provide device-specific lseek() logic; this emulation
 * breaks for such device-specific cases */
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

    lock(&hdl->inode->lock);
    ret = DkStreamSetLength(hdl->pal_handle, size);
    if (ret == 0) {
        hdl->inode->size = size;
    } else {
        ret = pal_to_unix_errno(ret);
    }
    unlock(&hdl->inode->lock);
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
        ret = DkStreamRead(palhdl, /*offset=*/0, &read_size, buf, /*source=*/NULL, /*size=*/0);
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
            size_t end = start + strlen(&buf[start]);

            if (end == start) {
                log_error("chroot_readdir: empty name returned from PAL");
                BUG();
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

    /* No need to adjust refcount of `old->inode`: we add a reference from `new` and remove the one
     * from `old`. */
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

static int chroot_chmod(struct shim_dentry* dent, mode_t perm) {
    int ret;

    lock(&dent->lock);
    lock(&dent->inode->lock);

    PAL_HANDLE palhdl;
    ret = chroot_temp_open(dent, dent->type, &palhdl);
    if (ret < 0)
        goto out;

    PAL_STREAM_ATTR attr = {.share_flags = perm};
    ret = DkStreamAttributesSetByHandle(palhdl, &attr);
    DkObjectClose(palhdl);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    /* `dent->perm` already updated by caller */
    dent->inode->perm = perm;
    ret = 0;

out:
    unlock(&dent->inode->lock);
    unlock(&dent->lock);
    return ret;
}

static int chroot_reopen(struct shim_handle* hdl, PAL_HANDLE* out_palhdl) {
    const char* uri = qstrgetstr(&hdl->uri);
    PAL_HANDLE palhdl;

    mode_t mode = 0;
    int access = LINUX_OPEN_FLAGS_TO_PAL_ACCESS(hdl->flags);
    int create = 0;
    int options = LINUX_OPEN_FLAGS_TO_PAL_OPTIONS(hdl->flags);
    int ret = DkStreamOpen(uri, access, mode, create, options, &palhdl);
    if (ret < 0)
        return pal_to_unix_errno(ret);
    *out_palhdl = palhdl;
    return 0;
}

/*
 * Prepare the handle to be sent to child process. If the corresponding file still exists on the
 * host, we will not checkpoint its PAL handle, but let the child process open another one.
 *
 * TODO: this is only necessary because PAL handles for protected files cannot be sent to child
 * process (`DkSendHandle`). This workaround limits the damage: inheriting a handle by child process
 * will now fail to work only if it's a handle for a protected file *and* the file has been deleted
 * from host.
 */
static int chroot_checkout(struct shim_handle* hdl) {
    assert(hdl->type == TYPE_CHROOT);
    assert(hdl->pal_handle);

    /* We don't take `hdl->lock` because this is actually the handle *copied* for checkpointing (and
     * the lock isn't even properly initialized). */

    /* First, check if we have not deleted or renamed the file (the dentry contains the same
     * inode). */
    lock(&hdl->dentry->lock);
    bool is_in_dentry = (hdl->dentry->inode == hdl->inode);
    unlock(&hdl->dentry->lock);

    /* Then check if the file still exists on host. If so, we assume it can be opened by the child
     * process, so the PAL handle doesn't need sending. */
    if (is_in_dentry) {
        PAL_STREAM_ATTR attr;
        if (DkStreamAttributesQuery(qstrgetstr(&hdl->uri), &attr) == 0) {
            hdl->pal_handle = NULL;
        }
    }

    return 0;
}

static int chroot_checkin(struct shim_handle* hdl) {
    assert(hdl->type == TYPE_CHROOT);

    /* We don't take `hdl->lock` because this handle is being initialized (during checkpoint
     * restore). */

    if (!hdl->pal_handle) {
        PAL_HANDLE palhdl;
        int ret = chroot_reopen(hdl, &palhdl);
        if (ret < 0) {
            log_warning("%s: failed to open %s: %d", __func__, qstrgetstr(&hdl->uri), ret);
            return ret;
        }
        hdl->pal_handle = palhdl;
    }
    return 0;
}

struct shim_fs_ops chroot_fs_ops = {
    .mount      = &chroot_mount,
    .flush      = &chroot_flush,
    .read       = &chroot_read,
    .write      = &chroot_write,
    .mmap       = &chroot_mmap,
    .seek       = &chroot_seek,
    .hstat      = &chroot_hstat,
    .truncate   = &chroot_truncate,
    .poll       = &chroot_poll,
    .checkout   = &chroot_checkout,
    .checkin    = &chroot_checkin,
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
