/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * This file contains implementation of the "pseudo" filesystem.
 */

#include "perm.h"
#include "shim_fs_pseudo.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "stat.h"

LISTP_TYPE(pseudo_node) g_pseudo_roots = LISTP_INIT;

/* Find a root node with given name. */
static struct pseudo_node* pseudo_find_root(const char* name) {
    struct pseudo_node* node;
    LISTP_FOR_EACH_ENTRY(node, &g_pseudo_roots, siblings) {
        if (node->name && strcmp(name, node->name) == 0) {
            return node;
        }
    }

    log_debug("Cannot find pseudofs node: %s", name);
    return NULL;
}

/*
 * Find a `pseudo_node` for given dentry. The pointer to retrieved node is cached in the `data`
 * field of the dentry.
 *
 * Note that we call `pseudo_find`, instead of initializing `dent->data` once on dentry lookup,
 * because the dentry might be restored from a checkpoint. Checkpointing clears the `data` field,
 * which is actually what we want, because we are not able to send `pseudo_node` pointers across
 * processes.
 *
 * Instead, we retrieve the node on first access to given dentry, and store it in `dent->data`. At
 * the same time, we also retrieve and cache nodes all the way to the root (see the recursive call
 * below).
 *
 * Note that `pseudo_find` might fail for such a checkpointed dentry: for instance, we might have a
 * dentry for `/proc/<pid>` where the process does not exist anymore. Ideally, we would invalidate
 * such dentries; for now, all operations on them will return -ENOENT.
 */
static struct pseudo_node* pseudo_find(struct shim_dentry* dent) {
    struct pseudo_node* node;

    lock(&dent->lock);
    node = dent->data;
    unlock(&dent->lock);

    if (node)
        return node;

    if (!dent->parent) {
        /* This is the filesystem root */
        node = pseudo_find_root(dent->mount->uri);
        goto out;
    }

    /* Recursive call: find the node for parent */
    struct pseudo_node* parent_node = pseudo_find(dent->parent);
    if (!parent_node) {
        node = NULL;
        goto out;
    }

    /* Look for a child node with matching name */
    assert(parent_node->type == PSEUDO_DIR);
    LISTP_FOR_EACH_ENTRY(node, &parent_node->dir.children, siblings) {
        if (node->name && strcmp(dent->name, node->name) == 0) {
            goto out;
        }
        if (node->name_exists && node->name_exists(dent->parent, dent->name)) {
            goto out;
        }
    }
    node = NULL;
out:
    if (node) {
        lock(&dent->lock);
        dent->data = node;
        unlock(&dent->lock);
    }
    return node;
}

static int pseudo_mount(const char* uri, void** mount_data) {
    __UNUSED(uri);
    __UNUSED(mount_data);
    return 0;
}

static int pseudo_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags) {
    int ret;
    struct pseudo_node* node = pseudo_find(dent);
    if (!node)
        return -ENOENT;

    switch (node->type) {
        case PSEUDO_DIR:
            hdl->type = TYPE_PSEUDO;
            /* This is a directory handle, so it will be initialized by `dentry_open`. */
            break;

        case PSEUDO_LINK:
            return -EINVAL;

        case PSEUDO_STR: {
            char* str;
            size_t len;
            if (node->str.load) {
                ret = node->str.load(dent, &str, &len);
                if (ret < 0)
                    return ret;
                assert(str);
            } else {
                len = 0;
                str = NULL;
            }

            hdl->type = TYPE_STR;
            mem_file_init(&hdl->info.str.mem, str, len);
            hdl->info.str.dirty = false;
            hdl->info.str.pos = 0;
            break;
        }

        case PSEUDO_DEV: {
            hdl->type = TYPE_DEV;
            if (node->dev.dev_ops.open) {
                ret = node->dev.dev_ops.open(hdl, dent, flags);
                if (ret < 0)
                    return ret;
            }
            break;
        }
    }
    hdl->flags = flags & ~O_ACCMODE;
    hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);

    return 0;
}

static int pseudo_lookup(struct shim_dentry* dent) {
    struct pseudo_node* node = pseudo_find(dent);
    if (!node)
        return -ENOENT;

    switch (node->type) {
        case PSEUDO_DIR:
            dent->type = S_IFDIR;
            break;
        case PSEUDO_LINK:
            dent->type = S_IFLNK;
            break;
        case PSEUDO_STR:
            dent->type = S_IFREG;
            break;
        case PSEUDO_DEV:
            dent->type = S_IFCHR;
            break;
    }
    dent->perm = node->perm;
    return 0;
}

static int count_nlink(const char* name, void* arg) {
    __UNUSED(name);
    size_t* nlink = arg;
    (*nlink)++;
    return 0;
}

static int pseudo_readdir(struct shim_dentry* dent, readdir_callback_t callback, void* arg);

static dev_t makedev(unsigned int major, unsigned int minor) {
    dev_t dev;
    dev  = (((dev_t)(major & 0x00000fffu)) <<  8);
    dev |= (((dev_t)(major & 0xfffff000u)) << 32);
    dev |= (((dev_t)(minor & 0x000000ffu)) <<  0);
    dev |= (((dev_t)(minor & 0xffffff00u)) << 12);
    return dev;
}

static int pseudo_stat(struct shim_dentry* dent, struct stat* buf) {
    struct pseudo_node* node = pseudo_find(dent);
    if (!node)
        return -ENOENT;

    memset(buf, 0, sizeof(*buf));
    buf->st_dev = 1;
    buf->st_mode = dent->type | dent->perm;
    switch (node->type) {
        case PSEUDO_DIR: {
            /* This is not very efficient, but libraries like hwloc check `nlink` in some places. */
            size_t nlink = 2; // Initialize to 2 for `.` and parent
            int ret = pseudo_readdir(dent, &count_nlink, &nlink);
            if (ret < 0)
                return ret;
            buf->st_nlink = nlink;
            break;
        }
        case PSEUDO_DEV:
            buf->st_rdev = makedev(node->dev.major, node->dev.minor);
            buf->st_nlink = 1;
            break;
        default:
            buf->st_nlink = 1;
            break;
    }
    return 0;
}

static int pseudo_hstat(struct shim_handle* handle, struct stat* buf) {
    assert(handle->dentry);
    return pseudo_stat(handle->dentry, buf);
}

static int pseudo_follow_link(struct shim_dentry* dent, char** out_target) {
    struct pseudo_node* node = pseudo_find(dent);
    char* target;

    if (!node)
        return -ENOENT;

    if (node->type != PSEUDO_LINK)
        return -EINVAL;

    if (node->link.follow_link) {
        int ret = node->link.follow_link(dent, &target);
        if (ret < 0)
            return ret;
        *out_target = target;
        return 0;
    }

    assert(node->link.target);
    target = strdup(node->link.target);
    if (!target)
        return -ENOMEM;

    *out_target = target;
    return 0;
}

static int pseudo_readdir(struct shim_dentry* dent, readdir_callback_t callback, void* arg) {
    int ret;

    struct pseudo_node* parent_node = pseudo_find(dent);
    if (!parent_node)
        return -ENOENT;
    if (parent_node->type != PSEUDO_DIR)
        return -ENOTDIR;

    struct pseudo_node* node;
    LISTP_FOR_EACH_ENTRY(node, &parent_node->dir.children, siblings) {
        if (node->name) {
            ret = callback(node->name, arg);
            if (ret < 0)
                return ret;
        }
        if (node->list_names) {
            ret = node->list_names(dent, callback, arg);
            if (ret < 0)
                return ret;
        }
    }
    return 0;
}

static ssize_t pseudo_read(struct shim_handle* hdl, void* buf, size_t size) {
    assert(hdl->dentry);
    struct pseudo_node* node = pseudo_find(hdl->dentry);
    if (!node)
        return -ENOENT;
    switch (node->type) {
        case PSEUDO_STR: {
            assert(hdl->type == TYPE_STR);
            lock(&hdl->lock);
            ssize_t ret = mem_file_read(&hdl->info.str.mem, hdl->info.str.pos, buf, size);
            if (ret > 0)
                hdl->info.str.pos += ret;
            unlock(&hdl->lock);
            return ret;
        }

        case PSEUDO_DEV:
            if (!node->dev.dev_ops.read)
                return -EACCES;
            return node->dev.dev_ops.read(hdl, buf, size);

        default:
            return -ENOSYS;
    }
}

static ssize_t pseudo_write(struct shim_handle* hdl, const void* buf, size_t size) {
    assert(hdl->dentry);
    struct pseudo_node* node = pseudo_find(hdl->dentry);
    if (!node)
        return -ENOENT;
    switch (node->type) {
        case PSEUDO_STR: {
            assert(hdl->type == TYPE_STR);
            lock(&hdl->lock);
            ssize_t ret = mem_file_write(&hdl->info.str.mem, hdl->info.str.pos, buf, size);
            if (ret > 0) {
                hdl->info.str.pos += ret;
                hdl->info.str.dirty = true;
            }
            unlock(&hdl->lock);
            return ret;
        }

        case PSEUDO_DEV:
            if (!node->dev.dev_ops.write)
                return -EACCES;
            return node->dev.dev_ops.write(hdl, buf, size);

        default:
            return -ENOSYS;
    }
}

static file_off_t pseudo_seek(struct shim_handle* hdl, file_off_t offset, int whence) {
    file_off_t ret;

    assert(hdl->dentry);
    struct pseudo_node* node = pseudo_find(hdl->dentry);
    if (!node)
        return -ENOENT;
    switch (node->type) {
        case PSEUDO_STR: {
            lock(&hdl->lock);
            file_off_t pos = hdl->info.str.pos;
            ret = generic_seek(pos, hdl->info.str.mem.size, offset, whence, &pos);
            if (ret == 0) {
                hdl->info.str.pos = pos;
                ret = pos;
            }
            unlock(&hdl->lock);
            return ret;
        }

        case PSEUDO_DEV:
            if (!node->dev.dev_ops.seek)
                return -EACCES;
            return node->dev.dev_ops.seek(hdl, offset, whence);

        default:
            return -ENOSYS;
    }
}

static int pseudo_truncate(struct shim_handle* hdl, file_off_t size) {
    assert(hdl->dentry);
    struct pseudo_node* node = pseudo_find(hdl->dentry);
    if (!node)
        return -ENOENT;
    switch (node->type) {
        case PSEUDO_STR:
            assert(hdl->type == TYPE_STR);
            lock(&hdl->lock);
            int ret = mem_file_truncate(&hdl->info.str.mem, size);
            if (ret == 0)
                hdl->info.str.dirty = true;
            unlock(&hdl->lock);
            return ret;

        case PSEUDO_DEV:
            if (!node->dev.dev_ops.truncate)
                return -EACCES;
            return node->dev.dev_ops.truncate(hdl, size);

        default:
            return -ENOSYS;
    }
}

static int pseudo_str_flush(struct pseudo_node* node, struct shim_handle* hdl) {
    assert(locked(&hdl->lock));
    assert(hdl->type == TYPE_STR);

    if (hdl->info.str.dirty && node->str.save) {
        struct shim_mem_file* mem = &hdl->info.str.mem;
        int ret = node->str.save(hdl->dentry, mem->buf, mem->size);
        if (ret < 0)
            return ret;
    }
    hdl->info.str.dirty = false;
    return 0;
}

static int pseudo_flush(struct shim_handle* hdl) {
    assert(hdl->dentry);
    struct pseudo_node* node = pseudo_find(hdl->dentry);
    if (!node)
        return -ENOENT;
    switch (node->type) {
        case PSEUDO_STR:
            return pseudo_str_flush(node, hdl);

        case PSEUDO_DEV:
            if (!node->dev.dev_ops.flush)
                return -EINVAL;
            return node->dev.dev_ops.flush(hdl);

        default:
            return -ENOSYS;
    }
}

static int pseudo_close(struct shim_handle* hdl) {
    assert(hdl->dentry);
    struct pseudo_node* node = pseudo_find(hdl->dentry);
    if (!node)
        return -ENOENT;
    switch (node->type) {
        case PSEUDO_STR: {
            lock(&hdl->lock);
            int ret = pseudo_str_flush(node, hdl);
            if (ret < 0) {
                log_debug("pseudo_str_flush() failed, proceeding with close");
            }
            mem_file_destroy(&hdl->info.str.mem);
            unlock(&hdl->lock);
            return ret;
        }

        case PSEUDO_DEV:
            if (!node->dev.dev_ops.close)
                return 0;
            return node->dev.dev_ops.close(hdl);

        default:
            return 0;
    }
}

static int pseudo_poll(struct shim_handle* hdl, int poll_type) {
    assert(hdl->dentry);
    struct pseudo_node* node = pseudo_find(hdl->dentry);
    if (!node)
        return -ENOENT;
    switch (node->type) {
        case PSEUDO_STR: {
            assert(hdl->type == TYPE_STR);
            lock(&hdl->lock);
            int ret = mem_file_poll(&hdl->info.str.mem, hdl->info.str.pos, poll_type);
            unlock(&hdl->lock);
            return ret;
        }

        case PSEUDO_DEV: {
            int ret = 0;
            if ((poll_type & FS_POLL_RD) && node->dev.dev_ops.read)
                ret |= FS_POLL_RD;
            if ((poll_type & FS_POLL_WR) && node->dev.dev_ops.write)
                ret |= FS_POLL_WR;
            return ret;
        }

        default:
            return -ENOSYS;
    }
}

int pseudo_parse_ulong(const char* str, unsigned long max_value, unsigned long* out_value) {
    unsigned long value;
    const char* end;

    if (str_to_ulong(str, 10, &value, &end) < 0 || *end != '\0' || value > max_value)
        return -1;

    /* no leading zeroes */
    if (str[0] == '0' && str[1] != '\0')
        return -1;

    *out_value = value;
    return 0;
}


static struct pseudo_node* pseudo_add_ent(struct pseudo_node* parent_node, const char* name,
                                          enum pseudo_type type) {
    struct pseudo_node* node = calloc(1, sizeof(*node));
    if (!node) {
        log_error("Out of memory when allocating pseudofs node");
        abort();
    }
    node->name = name;
    node->type = type;

    if (parent_node) {
        assert(parent_node->type == PSEUDO_DIR);
        node->parent = parent_node;
        LISTP_ADD(node, &parent_node->dir.children, siblings);
    } else {
        LISTP_ADD(node, &g_pseudo_roots, siblings);
    }
    return node;
}

struct pseudo_node* pseudo_add_root_dir(const char* name) {
    return pseudo_add_dir(/*parent_node=*/NULL, name);
}

struct pseudo_node* pseudo_add_dir(struct pseudo_node* parent_node, const char* name) {
    struct pseudo_node* node = pseudo_add_ent(parent_node, name, PSEUDO_DIR);
    node->perm = PSEUDO_PERM_DIR;
    return node;
}

struct pseudo_node* pseudo_add_link(struct pseudo_node* parent_node, const char* name,
                                    int (*follow_link)(struct shim_dentry*, char**)) {
    struct pseudo_node* node = pseudo_add_ent(parent_node, name, PSEUDO_LINK);
    node->link.follow_link = follow_link;
    node->perm = PSEUDO_PERM_LINK;
    return node;
}

struct pseudo_node* pseudo_add_str(struct pseudo_node* parent_node, const char* name,
                                   int (*load)(struct shim_dentry*, char**, size_t*)) {
    struct pseudo_node* node = pseudo_add_ent(parent_node, name, PSEUDO_STR);
    node->str.load = load;
    node->perm = PSEUDO_PERM_FILE_R;
    return node;
}

struct pseudo_node* pseudo_add_dev(struct pseudo_node* parent_node, const char* name) {
    struct pseudo_node* node = pseudo_add_ent(parent_node, name, PSEUDO_DEV);
    node->perm = PSEUDO_PERM_FILE_R;
    return node;
}

struct shim_fs_ops pseudo_fs_ops = {
    .mount    = &pseudo_mount,
    .hstat    = &pseudo_hstat,
    .read     = &pseudo_read,
    .write    = &pseudo_write,
    .seek     = &pseudo_seek,
    .truncate = &pseudo_truncate,
    .close    = &pseudo_close,
    .flush    = &pseudo_flush,
    .poll     = &pseudo_poll,
};

struct shim_d_ops pseudo_d_ops = {
    .open        = &pseudo_open,
    .lookup      = &pseudo_lookup,
    .readdir     = &pseudo_readdir,
    .stat        = &pseudo_stat,
    .follow_link = &pseudo_follow_link,
};

struct shim_fs pseudo_builtin_fs = {
    .name   = "pseudo",
    .fs_ops = &pseudo_fs_ops,
    .d_ops  = &pseudo_d_ops,
};
