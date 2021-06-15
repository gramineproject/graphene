
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
            data->str          = str;
            data->len          = len;
            hdl->type          = TYPE_STR;
            hdl->flags         = flags & ~O_RDONLY;
            hdl->acc_mode      = MAY_READ;
            hdl->info.str.data = data;
            break;
        }
    }
    return 0;
}

static int pseudo2_lookup(struct shim_dentry* dent) {
    struct pseudo2_ent* ent = pseudo_find(dent);
    if (!ent)
        return -ENOENT;

    dent->data = ent;
    switch (ent->type) {
        case PSEUDO_DIR:
            dent->state |= DENTRY_ISDIRECTORY;
            dent->type = S_IFDIR;
            dent->perm = PERM_r_x______;
            break;
        case PSEUDO_LINK:
            dent->state |= DENTRY_ISLINK;
            dent->type = S_IFLNK;
            dent->perm = PERM_rwxrwxrwx;
            break;
        case PSEUDO_STR:
            dent->type = S_IFREG;
            dent->perm = PERM_r________;
            break;
    }
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
    if (ent->type == PSEUDO_DIR) {
        /* This is not very efficient, but libraries like hwloc check `nlink` in some places. */
        size_t nlink = 2; // Initialize to 2 for `.` and parent
        int ret = pseudo2_readdir(dent, &count_nlink, &nlink);
        if (ret < 0)
            return 0;
        buf->st_nlink = nlink;
    } else {
        buf->st_nlink = 1;
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
    assert(ent->link.follow_link);

    return ent->link.follow_link(dent, link);
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
    int ret;
    assert(hdl->dentry);
    struct pseudo2_ent* ent = pseudo_find(hdl->dentry);
    if (!ent)
        return -ENOENT;
    switch (ent->type) {
        case PSEUDO_STR:
            ret = str_read(hdl, buf, count);
            break;

        default:
            return -ENOSYS;
    }
    return ret;
}

static off_t pseudo2_seek(struct shim_handle* hdl, off_t offset, int whence) {
    int ret;
    assert(hdl->dentry);
    struct pseudo2_ent* ent = pseudo_find(hdl->dentry);
    if (!ent)
        return -ENOENT;
    switch (ent->type) {
        case PSEUDO_STR:
            ret = str_seek(hdl, offset, whence);
            break;

        default:
            return -ENOSYS;
    }
    return ret;
}

static int pseudo2_close(struct shim_handle* hdl) {
    int ret;
    assert(hdl->dentry);
    struct pseudo2_ent* ent = pseudo_find(hdl->dentry);
    if (!ent)
        return -ENOENT;
    switch (ent->type) {
        case PSEUDO_STR:
            ret = str_close(hdl);
            break;

        default:
            /* do nothing */
            break;
    }
    return ret;
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
    return ent;
}

struct pseudo2_ent* pseudo_add_link(struct pseudo2_ent* parent_ent, const char* name,
                                    int (*follow_link)(struct shim_dentry*, struct shim_qstr*)) {
    struct pseudo2_ent* ent = pseudo_add_ent(parent_ent, name, PSEUDO_LINK);
    ent->link.follow_link = follow_link;
    return ent;
}

struct pseudo2_ent* pseudo_add_str(struct pseudo2_ent* parent_ent, const char* name,
                                   int (*get_content)(struct shim_dentry*, char**, size_t*)) {
    struct pseudo2_ent* ent = pseudo_add_ent(parent_ent, name, PSEUDO_STR);
    ent->str.get_content = get_content;
    return ent;
}

struct shim_fs_ops pseudo_fs_ops = {
    .mount    = &pseudo2_mount,
    .hstat    = &pseudo2_hstat,
    .read     = &pseudo2_read,
    .seek     = &pseudo2_seek,
    .close    = &pseudo2_close,
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
