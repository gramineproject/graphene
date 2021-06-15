
#include "stat.h"
#include "perm.h"
#include "shim_fs_pseudo.h"
#include "shim_internal.h"

LISTP_TYPE(pseudo2_ent) g_pseudo_roots = LISTP_INIT;

static struct pseudo2_ent* pseudo_find_root(const char* name) {
    struct pseudo2_ent* ent;
    LISTP_FOR_EACH_ENTRY(ent, &g_pseudo_roots, siblings) {
        if (ent->name && strcmp(name, ent->name) == 0) {
            return ent;
        }
    }
    return NULL;
}

static struct pseudo2_ent* pseudo_find(struct shim_dentry* dent) {
    if (dent->data)
        return dent->data;

    if (!dent->parent) {
        if (!dent->mount->data) {
            dent->mount->data = pseudo_find_root(qstrgetstr(&dent->mount->uri));
            assert(dent->mount->data);
        }
        dent->data = dent->mount->data;
        return dent->data;
    }

    const char* name = qstrgetstr(&dent->name);

    struct pseudo2_ent* parent_ent = pseudo_find(dent->parent);
    if (!parent_ent)
        return NULL;

    assert(parent_ent->type == PSEUDO_DIR);
    struct pseudo2_ent* ent;
    LISTP_FOR_EACH_ENTRY(ent, &parent_ent->dir.children, siblings) {
        if (ent->name && strcmp(name, ent->name) == 0) {
            dent->data = ent;
            return ent;
        } else if (ent->match_name && ent->match_name(dent->parent, name) >= 0) {
            dent->data = ent;
            return ent;
        }
    }
    return NULL;
}

static int pseudo2_mount(const char* uri, void** mount_data) {
    struct pseudo2_ent* ent = pseudo_find_root(uri);
    if (!ent) {
        log_error("cannot find pseudo root: %s\n", uri);
        return -ENODEV;
    }
    *mount_data = ent;
    return 0;
}

static int pseudo2_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags) {
    __UNUSED(hdl);
    __UNUSED(flags);
    int ret;
    struct pseudo2_ent* ent = pseudo_find(dent);
    if (!ent)
        return -ENOENT;

    switch (ent->type) {
        case PSEUDO_DIR:
            break;

        case PSEUDO_LINK:
            return -EINVAL;

        case PSEUDO_STR: {
            assert(ent->str.get_content);
            char* str;
            size_t len;
            ret = ent->str.get_content(dent, &str, &len);
            if (ret < 0)
                return ret;
            assert(str);

            struct shim_str_data* data = malloc(sizeof(struct shim_str_data));
            if (!data) {
                free(str);
                return -ENOMEM;
            }

            memset(data, 0, sizeof(struct shim_str_data));
            data->str = str;
            data->len = len;
            hdl->type = TYPE_STR;
            hdl->info.str.data = data;
            break;
        }

        case PSEUDO_DEV: {
            hdl->type = TYPE_DEV;
            break;
        }
    }
    hdl->flags = flags & ~O_ACCMODE;
    hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);

    return 0;
}

static int pseudo2_lookup(struct shim_dentry* dent) {
    struct pseudo2_ent* ent = pseudo_find(dent);
    if (!ent)
        return -ENOENT;

    switch (ent->type) {
        case PSEUDO_DIR:
            dent->state |= DENTRY_ISDIRECTORY;
            dent->type = S_IFDIR;
            break;
        case PSEUDO_LINK:
            dent->state |= DENTRY_ISLINK;
            dent->type = S_IFLNK;
            break;
        case PSEUDO_STR:
            dent->type = S_IFREG;
            break;
        case PSEUDO_DEV:
            dent->type = S_IFCHR;
            break;
    }
    dent->perm = ent->perm;
    return 0;
};

static int pseudo2_mode(struct shim_dentry* dent, mode_t* mode) {
    *mode = dent->type | dent->perm;
    return 0;
};

static int count_nlink(const char* name, void* arg) {
    __UNUSED(name);
    size_t* nlink = arg;
    (*nlink)++;
    return 0;
}

static int pseudo2_readdir(struct shim_dentry* dent, readdir_callback_t callback, void* arg);

static int pseudo2_stat(struct shim_dentry* dent, struct stat* buf) {
    struct pseudo2_ent* ent = pseudo_find(dent);
    if (!ent)
        return -ENOENT;

    memset(buf, 0, sizeof(*buf));
    buf->st_dev = 1;
    buf->st_mode = dent->type | dent->perm;
    switch (ent->type) {
        case PSEUDO_DIR: {
            /* This is not very efficient, but libraries like hwloc check `nlink` in some places. */
            size_t nlink = 2; // Initialize to 2 for `.` and parent
            int ret = pseudo2_readdir(dent, &count_nlink, &nlink);
            if (ret < 0)
                return 0;
            buf->st_nlink = nlink;
            break;
        }
        case PSEUDO_DEV:
            buf->st_rdev = makedev(ent->dev.major, ent->dev.minor);
            buf->st_nlink = 1;
            break;
        default:
            buf->st_nlink = 1;
            break;
    }
    return 0;
}

static int pseudo2_hstat(struct shim_handle* handle, struct stat* buf) {
    assert(handle->dentry);
    return pseudo2_stat(handle->dentry, buf);
}

static int pseudo2_follow_link(struct shim_dentry* dent, struct shim_qstr* link) {
    struct pseudo2_ent* ent = pseudo_find(dent);
    if (!ent)
        return -ENOENT;

    if (ent->type != PSEUDO_LINK)
        return -EINVAL;

    if (ent->link.follow_link)
        return ent->link.follow_link(dent, link);

    assert(ent->link.target);
    if (!qstrsetstr(link, ent->link.target, strlen(ent->link.target)))
        return -ENOMEM;

    return 0;
}

static int pseudo2_readdir(struct shim_dentry* dent, readdir_callback_t callback, void* arg) {
    int ret;

    struct pseudo2_ent* parent_ent = pseudo_find(dent);
    if (!parent_ent)
        return -ENOENT;
    if (parent_ent->type != PSEUDO_DIR)
        return -ENOTDIR;

    struct pseudo2_ent* ent;
    LISTP_FOR_EACH_ENTRY(ent, &parent_ent->dir.children, siblings) {
        if (ent->name) {
            ret = callback(ent->name, arg);
            if (ret < 0)
                return ret;
        }
        if (ent->list_names) {
            ret = ent->list_names(dent, callback, arg);
            if (ret < 0)
                return ret;
        }
    }
    return 0;
}

static ssize_t pseudo2_read(struct shim_handle* hdl, void* buf, size_t count) {
    assert(hdl->dentry);
    struct pseudo2_ent* ent = pseudo_find(hdl->dentry);
    if (!ent)
        return -ENOENT;
    switch (ent->type) {
        case PSEUDO_STR:
            return str_read(hdl, buf, count);
            break;

        case PSEUDO_DEV:
            if (!ent->dev.dev_ops.read)
                return -EACCES;
            return ent->dev.dev_ops.read(hdl, buf, count);

        default:
            return -ENOSYS;
    }
}

static ssize_t pseudo2_write(struct shim_handle* hdl, const void* buf, size_t count) {
    assert(hdl->dentry);
    struct pseudo2_ent* ent = pseudo_find(hdl->dentry);
    if (!ent)
        return -ENOENT;
    switch (ent->type) {
        case PSEUDO_STR:
            return str_write(hdl, buf, count);

        case PSEUDO_DEV:
            if (!ent->dev.dev_ops.write)
                return -EACCES;
            return ent->dev.dev_ops.write(hdl, buf, count);
            break;

        default:
            return -ENOSYS;
    }
}

static off_t pseudo2_seek(struct shim_handle* hdl, off_t offset, int whence) {
    assert(hdl->dentry);
    struct pseudo2_ent* ent = pseudo_find(hdl->dentry);
    if (!ent)
        return -ENOENT;
    switch (ent->type) {
        case PSEUDO_STR:
            return str_seek(hdl, offset, whence);

        case PSEUDO_DEV:
            if (!ent->dev.dev_ops.seek)
                return -EACCES;
            return ent->dev.dev_ops.seek(hdl, offset, whence);

        default:
            return -ENOSYS;
    }
}

static int pseudo2_truncate(struct shim_handle* hdl, off_t len) {
    assert(hdl->dentry);
    struct pseudo2_ent* ent = pseudo_find(hdl->dentry);
    if (!ent)
        return -ENOENT;
    switch (ent->type) {
        case PSEUDO_STR:
            /* e.g. fopen("w") wants to truncate; since these are pre-populated files,
             * just ignore */
            return 0;

        case PSEUDO_DEV:
            if (!ent->dev.dev_ops.truncate)
                return -EACCES;
            return ent->dev.dev_ops.truncate(hdl, len);

        default:
            return -ENOSYS;
    }
}

static int pseudo2_flush(struct shim_handle* hdl) {
    assert(hdl->dentry);
    struct pseudo2_ent* ent = pseudo_find(hdl->dentry);
    if (!ent)
        return -ENOENT;
    switch (ent->type) {
        case PSEUDO_STR:
            return str_flush(hdl);
            break;

        case PSEUDO_DEV:
            if (!ent->dev.dev_ops.flush)
                return 0;
            return ent->dev.dev_ops.flush(hdl);

        default:
            return 0;
    }
}

static int pseudo2_close(struct shim_handle* hdl) {
    assert(hdl->dentry);
    struct pseudo2_ent* ent = pseudo_find(hdl->dentry);
    if (!ent)
        return -ENOENT;
    switch (ent->type) {
        case PSEUDO_STR:
            return str_close(hdl);

        case PSEUDO_DEV:
            if (!ent->dev.dev_ops.close)
                return 0;
            return ent->dev.dev_ops.close(hdl);

        default:
            return 0;
    }
}

static off_t pseudo2_poll(struct shim_handle* hdl, int poll_type) {
    if (poll_type == FS_POLL_SZ)
        return 0;

    assert(hdl->dentry);
    struct pseudo2_ent* ent = pseudo_find(hdl->dentry);
    if (!ent)
        return -ENOENT;
    switch (ent->type) {
        case PSEUDO_DEV: {
            off_t ret = 0;
            if ((poll_type & FS_POLL_RD) && ent->dev.dev_ops.read)
                ret |= FS_POLL_RD;
            if ((poll_type & FS_POLL_WR) && ent->dev.dev_ops.write)
                ret |= FS_POLL_WR;
            return ret;
        }
        default:
            return -ENOSYS;
    }
}

static struct pseudo2_ent* pseudo_add_ent(struct pseudo2_ent* parent_ent, const char* name,
                                          enum pseudo_type type) {
    struct pseudo2_ent* ent = malloc(sizeof(*ent));
    if (!ent) {
        log_error("Out of memory when allocating pseudo entity");
        abort();
    }
    memset(ent, 0, sizeof(*ent));
    ent->name = name;
    ent->type = type;

    if (parent_ent) {
        assert(parent_ent->type == PSEUDO_DIR);
        ent->parent = parent_ent;
        LISTP_ADD(ent, &parent_ent->dir.children, siblings);
    } else {
        LISTP_ADD(ent, &g_pseudo_roots, siblings);
    }
    return ent;
}

struct pseudo2_ent* pseudo_add_root_dir(const char* name) {
    return pseudo_add_dir(/*parent_ent=*/NULL, name);
}

struct pseudo2_ent* pseudo_add_dir(struct pseudo2_ent* parent_ent, const char* name) {
    struct pseudo2_ent* ent = pseudo_add_ent(parent_ent, name, PSEUDO_DIR);
    ent->perm = PSEUDO_MODE_DIR;
    return ent;
}

struct pseudo2_ent* pseudo_add_link(struct pseudo2_ent* parent_ent, const char* name,
                                    int (*follow_link)(struct shim_dentry*, struct shim_qstr*)) {
    struct pseudo2_ent* ent = pseudo_add_ent(parent_ent, name, PSEUDO_LINK);
    ent->link.follow_link = follow_link;
    ent->perm = PSEUDO_MODE_LINK;
    return ent;
}

struct pseudo2_ent* pseudo_add_str(struct pseudo2_ent* parent_ent, const char* name,
                                   int (*get_content)(struct shim_dentry*, char**, size_t*)) {
    struct pseudo2_ent* ent = pseudo_add_ent(parent_ent, name, PSEUDO_STR);
    ent->str.get_content = get_content;
    ent->perm = PSEUDO_MODE_FILE_R;
    return ent;
}

struct pseudo2_ent* pseudo_add_dev(struct pseudo2_ent* parent_ent, const char* name) {
    struct pseudo2_ent* ent = pseudo_add_ent(parent_ent, name, PSEUDO_DEV);
    ent->perm = PSEUDO_MODE_FILE_R;
    return ent;
}

struct shim_fs_ops pseudo_fs_ops = {
    .mount    = &pseudo2_mount,
    .hstat    = &pseudo2_hstat,
    .read     = &pseudo2_read,
    .write    = &pseudo2_write,
    .seek     = &pseudo2_seek,
    .truncate = &pseudo2_truncate,
    .close    = &pseudo2_close,
    .flush    = &pseudo2_flush,
    .poll     = &pseudo2_poll,
};

struct shim_d_ops pseudo_d_ops = {
    .open        = &pseudo2_open,
    .lookup      = &pseudo2_lookup,
    .mode        = &pseudo2_mode,
    .readdir     = &pseudo2_readdir,
    .stat        = &pseudo2_stat,
    .follow_link = &pseudo2_follow_link,
};

struct shim_fs pseudo_builtin_fs = {
    .name   = "pseudo",
    .fs_ops = &pseudo_fs_ops,
    .d_ops  = &pseudo_d_ops,
};
