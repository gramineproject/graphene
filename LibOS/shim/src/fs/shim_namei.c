/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2017, University of North Carolina at Chapel Hill and Fortanix, Inc. */

/*
 * This file contains code for parsing a FS path and looking up in the directory cache.
 */

#include <asm/fcntl.h>
#include <linux/fcntl.h>
#include <stdbool.h>

#include "pal.h"
#include "perm.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_utils.h"
#include "stat.h"

/* Advances a char pointer (string) past any repeated slashes and returns the result.
 * Must be a null-terminated string. */
static inline const char* eat_slashes(const char* string) {
    while (*string == '/')
        string++;
    return string;
}

int check_permissions(struct shim_dentry* dent, mode_t mask) {
    assert(locked(&g_dcache_lock));
    assert(dent->state & DENTRY_VALID);

    if (dent->state & DENTRY_NEGATIVE)
        return -ENOENT;

    /* If we only check if the file exists, at this point we know that */
    if (mask == F_OK)
        return 0;

    /* Check the "user" part of mode against mask */
    if (((dent->perm >> 6) & mask) == mask)
        return 0;

    return -EACCES;
}

/*!
 * \brief Search for a child of a dentry, querying the filesystem if necessary
 *
 * \param parent dentry to look in
 * \param name file name
 * \param name_len length of the name
 * \param[out] found pointer to retrieved dentry
 *
 * This function works like `lookup_dcache`, but if the dentry is not in cache, it queries the
 * underlying filesystem.
 *
 * The caller should hold `g_dcache_lock`.
 *
 * On success, returns 0 and sets `*found` to the found dentry (whose reference count is increased).
 * A negative filesystem lookup (ENOENT) is also considered a success, and `*found` is set to a
 * negative dentry. The dentry is always valid.
 *
 * On failure (including lookup failing with any other error than ENOENT) returns the negative error
 * code, and sets `*found` to NULL.
 */
static int lookup_dentry(struct shim_dentry* parent, const char* name, size_t name_len,
                         struct shim_dentry** found) {
    assert(locked(&g_dcache_lock));
    assert(parent);

    int ret = 0;

    struct shim_dentry* dent = lookup_dcache(parent, name, name_len);
    if (!dent) {
        dent = get_new_dentry(parent->mount, parent, name, name_len);
        if (!dent) {
            ret = -ENOMEM;
            goto err;
        }

        assert(!(dent->state & DENTRY_VALID));
    }

    if (!(dent->state & DENTRY_VALID)) {
        /* This is an invalid dentry: either we just created it, or it got left over from a previous
         * failed lookup. Perform the lookup. */
        assert(dent->fs);
        assert(dent->fs->d_ops);
        assert(dent->fs->d_ops->lookup);
        ret = dent->fs->d_ops->lookup(dent);

        if (ret == 0) {
            /*
             * Lookup succeeded. Now, ensure `dent->perm` and `dent->type` are valid.
             *
             * TODO: remove `mode()` as a separate operation, and make sure this is always done by
             * `lookup()`.
             */
            assert(dent->fs->d_ops->mode);
            mode_t mode;
            ret = dent->fs->d_ops->mode(dent, &mode);
            if (ret < 0) {
                goto err;
            }

            dent->perm = mode & ~S_IFMT;
            dent->type = mode & S_IFMT;

            dent->state |= DENTRY_VALID;
        } else if (ret == -ENOENT) {
            /* File not found, we will return a negative dentry */
            dent->state |= DENTRY_VALID | DENTRY_NEGATIVE;
        } else {
            /* Lookup failed, keep dentry as invalid (and don't return it to user) */
            goto err;
        }
    }

    *found = dent;
    return 0;

err:
    if (dent)
        put_dentry(dent);
    *found = NULL;
    return ret;
}

static int do_path_lookupat(struct shim_dentry* start, const char* path, int flags,
                            struct shim_dentry** found, unsigned int link_depth);


/* Helper function that follows a symbolic link, performing a nested call to `do_path_lookupat`  */
static int path_lookupat_follow(struct shim_dentry* parent, struct shim_dentry* link, int flags,
                                struct shim_dentry** found, unsigned int link_depth) {
    int ret;
    struct shim_qstr link_target = QSTR_INIT;

    assert(locked(&g_dcache_lock));

    assert(link->fs);
    assert(link->fs->d_ops);
    assert(link->fs->d_ops->follow_link);
    ret = link->fs->d_ops->follow_link(link, &link_target);
    if (ret < 0)
        goto out;

    ret = do_path_lookupat(parent, qstrgetstr(&link_target), flags, found, link_depth);

out:
    qstrfree(&link_target);
    return ret;
}

/*
 * This implementation is mostly iterative, but uses recursion to follow symlinks (which is why the
 * link depth is limited to MAX_LINK_DEPTH).
 */
static int do_path_lookupat(struct shim_dentry* start, const char* path, int flags,
                            struct shim_dentry** found, unsigned int link_depth) {
    assert(locked(&g_dcache_lock));

    struct shim_dentry* dent = NULL;
    struct shim_dentry* next_dent = NULL;
    int ret = 0;

    /* Empty path is invalid in POSIX */
    if (*path == '\0') {
        ret = -ENOENT;
        goto err;
    }

    if (*path == '/') {
        /* Absolute path, use process root even if `start` was provided (can happen for *at() system
         * calls) */
        lock(&g_process.fs_lock);
        dent = g_process.root;
        if (!dent) {
            /* Can happen during LibOS initialization */
            dent = g_dentry_root;
        }
        get_dentry(dent);
        unlock(&g_process.fs_lock);
    } else if (!start) {
        /* Relative part with no start dentry provided, use process current working directory */
        lock(&g_process.fs_lock);
        dent = g_process.cwd;
        if (!dent) {
            /* Can happen during LibOS initialization */
            start = g_dentry_root;
        }
        get_dentry(dent);
        unlock(&g_process.fs_lock);
    } else {
        /* Relative path with start dentry provided, use it */
        dent = start;
        get_dentry(dent);
    }

    const char* name = path;
    while (*name == '/')
        name++;

    while (*name != '\0') {
        assert(*name != '/');

        const char* name_end = name;
        while (*name_end != '\0' && *name_end != '/')
            name_end++;
        size_t name_len = name_end - name;

        const char* next_name = name_end;
        while (*next_name == '/')
            next_name++;

        /* Check if this is the final component, but treat paths ending with slash specially. */
        bool is_final = (*next_name == '\0');
        bool has_slash = (*name_end == '/');

        if (name_len > NAME_MAX) {
            ret = -ENAMETOOLONG;
            goto err;
        }

        if (name_len == 1 && name[0] == '.') {
            next_dent = dent;
            get_dentry(next_dent);
        } else if (name_len == 2 && name[0] == '.' && name[1] == '.') {
            next_dent = dent->parent ? dent->parent : dent;
            get_dentry(next_dent);
        } else {
            ret = lookup_dentry(dent, name, name_len, &next_dent);
            if (ret)
                goto err;

            if (!(next_dent->state & DENTRY_NEGATIVE) && (next_dent->state & DENTRY_ISLINK)) {
                /* Traverse the symbolic link. This applies to all intermediate segments, final
                 * segments ending with slash, and to all final segments if LOOKUP_FOLLOW is set. */
                if (!is_final || has_slash || (flags & LOOKUP_FOLLOW)) {
                    if (link_depth >= MAX_LINK_DEPTH) {
                        ret = -ELOOP;
                        goto err;
                    }

                    /* If this is not the final segment (without slash), the nested lookup has
                     * different options: it always follows symlinks, needs to always find the
                     * target, and the target has to be a directory. */
                    int sub_flags = flags;
                    if (!is_final || has_slash) {
                        sub_flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
                        sub_flags &= ~LOOKUP_CREATE;
                    }

                    struct shim_dentry* target_dent;
                    ret = path_lookupat_follow(dent, next_dent, sub_flags, &target_dent,
                                               link_depth + 1);
                    if (ret < 0)
                        goto err;

                    put_dentry(next_dent);
                    next_dent = target_dent;
                }
            }

            if (next_dent->state & DENTRY_NEGATIVE) {
                if ((!is_final || has_slash) && (flags & LOOKUP_MAKE_SYNTHETIC)) {
                    /* Create a synthetic directory */
                    next_dent->state &= ~DENTRY_NEGATIVE;
                    next_dent->state |= DENTRY_VALID | DENTRY_SYNTHETIC | DENTRY_ISDIRECTORY;
                    next_dent->type = S_IFDIR;
                    next_dent->perm = PERM_rwxr_xr_x;
                } else if (!(is_final && (flags & LOOKUP_CREATE))) {
                    ret = -ENOENT;
                    goto err;
                }
            } else if (!(next_dent->state & DENTRY_ISDIRECTORY)) {
                if (!is_final || has_slash || (flags & LOOKUP_DIRECTORY)) {
                    ret = -ENOTDIR;
                    goto err;
                }
            }
        }

        put_dentry(dent);
        dent = next_dent;
        next_dent = NULL;
        name = next_name;
    }

    assert(dent->state & DENTRY_VALID);
    assert(!next_dent);
    *found = dent;
    return 0;

err:
    if (dent)
        put_dentry(dent);
    if (next_dent)
        put_dentry(next_dent);
    *found = NULL;
    return ret;
}

int _path_lookupat(struct shim_dentry* start, const char* path, int flags,
                   struct shim_dentry** found) {
    return do_path_lookupat(start, path, flags, found, /*link_depth=*/0);
}

int path_lookupat(struct shim_dentry* start, const char* path, int flags,
                   struct shim_dentry** found) {
    lock(&g_dcache_lock);
    int ret = do_path_lookupat(start, path, flags, found, /*link_depth=*/0);
    unlock(&g_dcache_lock);
    return ret;
}

static inline int open_flags_to_lookup_flags(int flags) {
    int retval = LOOKUP_FOLLOW;

    if (flags & O_NOFOLLOW)
        retval &= ~LOOKUP_FOLLOW;

    if (flags & O_CREAT)
        retval |= LOOKUP_CREATE;

    /*
     * See `man 2 open`:
     *
     * "When these two flags [O_CREAT and O_EXCL] are specified, symbolic links are not followed: if
     * pathname is a symbolic link, then open() fails regardless of where the symbolic link points."
     */
    if ((flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL))
        retval &= ~LOOKUP_FOLLOW;

    if (flags & O_DIRECTORY)
        retval |= LOOKUP_DIRECTORY;

    return retval;
}

static void assoc_handle_with_dentry(struct shim_handle* hdl, struct shim_dentry* dent, int flags) {
    hdl->fs = dent->fs;
    get_dentry(dent);
    hdl->dentry = dent;
    hdl->flags = flags;
}

int dentry_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags) {
    assert(dent->state & DENTRY_VALID);
    assert(!(dent->state & DENTRY_NEGATIVE));
    assert(!hdl->dentry);

    int ret = 0;
    struct shim_fs* fs = dent->fs;

    if (!(fs->d_ops && fs->d_ops->open)) {
        ret = -EINVAL;
        goto err;
    }

    ret = fs->d_ops->open(hdl, dent, flags);
    if (ret < 0)
        goto err;

    assoc_handle_with_dentry(hdl, dent, flags);

    if (dent->state & DENTRY_ISDIRECTORY) {
        /* Initialize directory handle */
        hdl->is_dir = true;

        hdl->dir_info.dents = NULL;
    }

    /* truncate regular writable file if O_TRUNC is given */
    if ((flags & O_TRUNC) && ((flags & O_RDWR) | (flags & O_WRONLY))
            && !(dent->state & DENTRY_ISDIRECTORY)
            && !(dent->state & DENTRY_MOUNTPOINT)
            && !(dent->state & DENTRY_ISLINK)) {

        if (!(fs->fs_ops && fs->fs_ops->truncate)) {
            ret = -EINVAL;
            goto err;
        }
        ret = fs->fs_ops->truncate(hdl, 0);
        if (ret < 0)
            goto err;
    }

    return 0;

err:
    /* If we failed after calling `open`, undo it */
    if (hdl->dentry) {
        if (fs->fs_ops && fs->fs_ops->hput)
            fs->fs_ops->hput(hdl);

        hdl->dentry = NULL;
        put_dentry(dent);
    }
    return ret;
}

int open_namei(struct shim_handle* hdl, struct shim_dentry* start, const char* path, int flags,
               int mode, struct shim_dentry** found) {
    int lookup_flags = open_flags_to_lookup_flags(flags);
    mode_t acc_mode = ACC_MODE(flags & O_ACCMODE);
    int ret = 0;
    struct shim_dentry* dent = NULL;

    /* O_CREAT on a normal file triggers creat(), which needs a handle */
    if ((flags & O_CREAT) && !(flags & O_DIRECTORY))
        assert(hdl);

    if (hdl)
        assert(!hdl->dentry);

    lock(&g_dcache_lock);

    ret = _path_lookupat(start, path, lookup_flags, &dent);
    if (ret < 0)
        goto err;

    assert(dent->state & DENTRY_VALID);

    if (dent->state & DENTRY_ISDIRECTORY) {
        if (flags & O_WRONLY || flags & O_RDWR) {
            ret = -EISDIR;
            goto err;
        }
    }

    if (dent->state & DENTRY_ISLINK) {
        /*
         * Can happen if user specified O_NOFOLLOW, or O_TRUNC | O_EXCL. Posix requires us to fail
         * with -ELOOP when trying to open a symlink.
         *
         * (Linux allows opening a symlink with O_PATH, but Graphene does not support it yet).
         */
        ret = -ELOOP;
        goto err;
    }

    bool need_open = true;
    if (dent->state & DENTRY_NEGATIVE) {
        if (!(flags & O_CREAT)) {
            ret = -ENOENT;
            goto err;
        }

        /* The root always exists, so if we got here, the dentry should have a parent */
        struct shim_dentry* dir = dent->parent;
        assert(dir);
        assert(dir->fs);
        assert(dir->fs->d_ops);

        /* Check the parent permission first */
        ret = check_permissions(dir, MAY_WRITE | MAY_EXEC);
        if (ret < 0)
            goto err;

        /* Create directory or file, depending on O_DIRECTORY. Return -EINVAL if the operation is
         * not supported for this filesystem. */
        if (flags & O_DIRECTORY) {
            if (!dir->fs->d_ops->mkdir) {
                ret = -EINVAL;
                goto err;
            }
            ret = dir->fs->d_ops->mkdir(dir, dent, mode);
            if (ret < 0)
                goto err;
            dent->state &= ~DENTRY_NEGATIVE;
            dent->state |= DENTRY_ISDIRECTORY;
            dent->type = S_IFDIR;
        } else {
            if (!dir->fs->d_ops->creat) {
                ret = -EINVAL;
                goto err;
            }
            ret = dir->fs->d_ops->creat(hdl, dir, dent, flags, mode);
            if (ret < 0)
                goto err;
            dent->state &= ~DENTRY_NEGATIVE;
            assoc_handle_with_dentry(hdl, dent, flags);
            need_open = false;
        }
    } else {
        /* The file exists. This is not permitted if both O_CREAT and O_EXCL are set. */
        if ((flags & O_CREAT) && (flags & O_EXCL)) {
            ret = -EEXIST;
            goto err;
        }

        /* Check permissions. Note that we do it only if the file already exists: a newly created
         * file is allowed to have a mode that's incompatible with `acc_mode`. */
        ret = check_permissions(dent, acc_mode);
        if (ret < 0)
            goto err;
    }

    if (hdl && need_open) {
        ret = dentry_open(hdl, dent, flags);
        if (ret < 0)
            goto err;
    }

    if (found) {
        *found = dent;
    } else {
        put_dentry(dent);
    }
    unlock(&g_dcache_lock);
    return 0;

err:
    if (dent)
        put_dentry(dent);

    if (found)
        *found = NULL;

    unlock(&g_dcache_lock);
    return ret;
}

/* A list for `populate_directory` to hold file names from `readdir`. */
DEFINE_LIST(temp_dirent);
DEFINE_LISTP(temp_dirent);
struct temp_dirent {
    LIST_TYPE(temp_dirent) list;

    size_t name_len;
    char name[];
};

static int add_name(const char* name, void* arg) {
    LISTP_TYPE(temp_dirent)* ents = arg;

    size_t name_len = strlen(name);
    struct temp_dirent* ent = malloc(sizeof(*ent) + name_len + 1);
    if (!ent)
        return -ENOMEM;

    memcpy(&ent->name, name, name_len + 1);
    ent->name_len = name_len;
    LISTP_ADD(ent, ents, list);
    return 0;
}

/*
 * Ensure that a directory has a complete list of dentries, by calling `readdir` and then
 * `lookup_dentry` on every name.
 *
 * While `readdir` is callback-based, we don't look up the names inside of callback, but first
 * finish `readdir`. Otherwise, the two filesystem operations (`readdir` and `lookup`) might
 * deadlock.
 */
static int populate_directory(struct shim_dentry* dent) {
    assert(locked(&g_dcache_lock));

    if (dent->state & DENTRY_NEGATIVE)
        return -ENOENT;

    if (!dent->fs || !dent->fs->d_ops || !dent->fs->d_ops->readdir)
        return -EINVAL;

    LISTP_TYPE(temp_dirent) ents = LISTP_INIT;
    int ret = dent->fs->d_ops->readdir(dent, &add_name, &ents);
    if (ret < 0)
        log_error("readdir error: %d\n", ret);

    struct temp_dirent* ent;
    struct temp_dirent* tmp;

    LISTP_FOR_EACH_ENTRY(ent, &ents, list) {
        struct shim_dentry* child;
        ret = lookup_dentry(dent, ent->name, ent->name_len, &child);
        if (ret == 0) {
            put_dentry(child);
        } else if (ret != -EACCES) {
            /* Fail on underlying lookup errors, except -EACCES (for which we will just ignore the
             * file). The lookup might fail with -EACCES for host symlinks pointing to inaccessible
             * target, since the "chroot" filesystem transparently follows symlinks instead of
             * reporting them to Graphene. */
            goto out;
        }
    }

    ret = 0;
out:
    LISTP_FOR_EACH_ENTRY_SAFE(ent, tmp, &ents, list) {
        LISTP_DEL(ent, &ents, list);
        free(ent);
    }
    return ret;
}

int populate_directory_handle(struct shim_handle* hdl) {
    struct shim_dir_handle* dirhdl = &hdl->dir_info;

    assert(locked(&hdl->lock));
    assert(locked(&g_dcache_lock));
    assert(hdl->dentry);

    int ret;

    if (dirhdl->dents)
        return 0;

    if ((ret = populate_directory(hdl->dentry)) < 0)
        goto err;

    size_t capacity = hdl->dentry->nchildren + 2; // +2 for ".", ".."

    dirhdl->dents = malloc(sizeof(struct shim_dentry) * capacity);
    if (!dirhdl->dents) {
        ret = -ENOMEM;
        goto err;
    }
    dirhdl->count = 0;

    struct shim_dentry* dot = hdl->dentry;
    get_dentry(dot);
    dirhdl->dents[dirhdl->count++] = dot;

    struct shim_dentry* dotdot = hdl->dentry->parent ?: hdl->dentry;
    get_dentry(dotdot);
    dirhdl->dents[dirhdl->count++] = dotdot;

    struct shim_dentry* tmp;
    struct shim_dentry* dent;
    LISTP_FOR_EACH_ENTRY_SAFE(dent, tmp, &hdl->dentry->children, siblings) {
        if ((dent->state & DENTRY_VALID) && !(dent->state & DENTRY_NEGATIVE)) {
            get_dentry(dent);
            assert(dirhdl->count < capacity);
            dirhdl->dents[dirhdl->count++] = dent;
        }
        dentry_gc(dent);
    }

    return 0;

err:
    clear_directory_handle(hdl);
    return ret;
}

void clear_directory_handle(struct shim_handle* hdl) {
    struct shim_dir_handle* dirhdl = &hdl->dir_info;
    if (!dirhdl->dents)
        return;

    for (size_t i = 0; i < dirhdl->count; i++)
        put_dentry(dirhdl->dents[i]);
    free(dirhdl->dents);
    dirhdl->dents = NULL;
    dirhdl->count = 0;
}

int get_dirfd_dentry(int dirfd, struct shim_dentry** dir) {
    if (dirfd == AT_FDCWD) {
        lock(&g_process.fs_lock);
        *dir = g_process.cwd;
        get_dentry(*dir);
        unlock(&g_process.fs_lock);
        return 0;
    }

    if (dirfd < 0) {
        return -EBADF;
    }

    struct shim_handle* hdl = get_fd_handle(dirfd, NULL, NULL);
    if (!hdl) {
        return -EBADF;
    }

    if (!hdl->is_dir) {
        put_handle(hdl);
        return -ENOTDIR;
    }

    get_dentry(hdl->dentry);
    *dir = hdl->dentry;
    put_handle(hdl);
    return 0;
}
