/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2017, University of North Carolina at Chapel Hill and Fortanix, Inc. */

/*
 * This file contains code for parsing a FS path and looking up in the directory cache.
 */

#include <asm/fcntl.h>
#include <linux/fcntl.h>
#include <stdbool.h>

#include "pal.h"
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

    /*
     * Synthetic directories don't really have permissions.
     *
     * TODO: current mount operation marks the mount root as synthetic. Once that's fixed, we'll be
     * able to disallow W_OK here.
     */
    if (dent->state & DENTRY_SYNTHETIC)
        return 0;

    /* A dentry may not have the mode stored yet. Query the underlying filesystem. */
    if (dent->mode == NO_MODE) {
        assert(dent->fs);
        if (!dent->fs->d_ops || !dent->fs->d_ops->mode) {
            /* dentry is emulated in LibOS (AF_UNIX socket or FIFO pipe): no permission check */
            return 0;
        }

        /* Fall back to the low-level file system */
        mode_t mode = 0;
        int err = dent->fs->d_ops->mode(dent, &mode);

        /*
         * DEP 6/16/17: I think the low-level file system should be
         * setting modes, rather than defaulting to open here.
         * I'm ok with a file system that doesn't care setting the
         * permission to all.
         */
        if (err < 0)
            return err;

        dent->mode = mode;
    }

    /* Check the "user" part of mode against mask */
    if (((dent->mode >> 6) & mask) == mask)
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
 * On success, returns 0 and sets `*new` to the found dentry (whose reference count is increased). A
 * negative filesystem lookup (ENOENT) is also considered a success, and `*new` is set to a negative
 * dentry. The dentry is always valid.
 *
 * On failure (including lookup failing with any other error than ENOENT) returns the negative error
 * code, and sets `*new` to NULL.
 */
static int lookup_dentry(struct shim_dentry* parent, const char* name, size_t name_len,
                         struct shim_dentry** found) {
    assert(locked(&g_dcache_lock));
    assert(parent);

    int ret = 0;

    struct shim_dentry* dent = lookup_dcache(parent, name, name_len);
    if (!dent) {
        /* Make sure newly created dentry's relative path will fit into qstr. */
        if (parent->rel_path.len + 1 + name_len >= STR_SIZE) { /* +1 for '/' */
            log_error("Relative path exceeds the limit %d\n", STR_SIZE);
            ret = -ENAMETOOLONG;
            goto err;
        }

        dent = get_new_dentry(parent->fs, parent, name, name_len);
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
            /* Lookup succeeded */
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
        start = g_process.root;
        if (!start) {
            /* Can happen during LibOS initialization */
            start = g_dentry_root;
        }
        unlock(&g_process.fs_lock);
    } else if (!start) {
        /* Relative part with no start dentry provided, use process current working directory */
        lock(&g_process.fs_lock);
        start = g_process.cwd;
        if (!start) {
            /* Can happen during LibOS initialization */
            start = g_dentry_root;
        }
        unlock(&g_process.fs_lock);
    }

    assert(start);
    dent = start;
    get_dentry(dent);

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

        if (name_len > MAX_FILENAME) {
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

int dentry_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags) {
    assert(dent->state & DENTRY_VALID);
    assert(!(dent->state & DENTRY_NEGATIVE));
    assert(!hdl->dentry);

    int ret = 0;
    struct shim_mount* fs = dent->fs;

    if (!(fs->d_ops && fs->d_ops->open)) {
        ret = -EINVAL;
        goto err;
    }

    ret = fs->d_ops->open(hdl, dent, flags);
    if (ret < 0)
        goto err;

    set_handle_fs(hdl, fs);
    get_dentry(dent);
    hdl->dentry = dent;
    hdl->flags = flags;

    if (dent->state & DENTRY_ISDIRECTORY) {
        /* Initialize directory handle */
        hdl->is_dir = true;
        memcpy(hdl->fs_type, fs->type, sizeof(fs->type));

        /* Set `dot` and `dotdot` so that we later know to list them */
        get_dentry(dent);
        hdl->dir_info.dot = dent;

        if (dent->parent) {
            get_dentry(dent->parent);
            hdl->dir_info.dotdot = dent->parent;
        } else {
            hdl->dir_info.dotdot = NULL;
        }

        // Let's defer setting the DENTRY_LISTED flag until we need it
        // Use -1 to indicate that the buf/ptr isn't initialized
        hdl->dir_info.buf = (void*)-1;
        hdl->dir_info.ptr = (void*)-1;
    }

    if (!dentry_get_path_into_qstr(dent, &hdl->path)) {
        ret = -ENOMEM;
        goto err;
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
        /* Can happen if user specified O_NOFOLLOW, or O_TRUNC | O_EXCL. Posix requires us to fail
         * with -ELOOP when trying to open a symlink. */
        ret = -ELOOP;
        goto err;
    }

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

    if (hdl) {
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

static inline void set_dirent_type(mode_t* type, int d_type) {
    switch (d_type) {
        case LINUX_DT_DIR:
            *type = S_IFDIR;
            return;
        case LINUX_DT_FIFO:
            *type = S_IFIFO;
            return;
        case LINUX_DT_CHR:
            *type = S_IFCHR;
            return;
        case LINUX_DT_BLK:
            *type = S_IFBLK;
            return;
        case LINUX_DT_REG:
            *type = S_IFREG;
            return;
        case LINUX_DT_LNK:
            *type = S_IFLNK;
            return;
        case LINUX_DT_SOCK:
            *type = S_IFSOCK;
            return;
        default:
            *type = 0;
            return;
    }
}

/* This function enumerates a directory and caches the results in the cache.
 *
 * Input: A dentry for a directory in the DENTRY_ISDIRECTORY and not in the
 * DENTRY_LISTED state.  The dentry DENTRY_LISTED flag is set upon success.
 *
 * Return value: 0 on success, <0 on error
 *
 * DEP 7/9/17: This work was once done as part of open, but, since getdents*
 * have no consistency semantics, we can apply the principle of laziness and
 * not do the work until we are sure we really need to.
 */
int list_directory_dentry(struct shim_dentry* dent) {
    int ret = 0;
    struct shim_mount* fs = dent->fs;
    lock(&g_dcache_lock);

    /* DEP 8/4/17: Another process could list this directory
     * while we are waiting on the dcache lock.  This is ok,
     * no need to blow an assert.
     */
    if (dent->state & DENTRY_LISTED) {
        unlock(&g_dcache_lock);
        return 0;
    }

    // DEP 7/9/17: In yet another strange turn of events in POSIX-land,
    // you can do a readdir on a rmdir-ed directory handle.  What you
    // expect to learn is beyond me, but be careful with blowing assert
    // and tell the program something to keep it moving.
    if (dent->state & DENTRY_NEGATIVE) {
        unlock(&g_dcache_lock);
        return 0;
    }

    assert(dent->state & DENTRY_ISDIRECTORY);

    struct shim_dirent* dirent = NULL;

    if ((ret = fs->d_ops->readdir(dent, &dirent)) < 0 || !dirent) {
        dirent = NULL;
        goto done_read;
    }

    struct shim_dirent* d = dirent;
    for (; d; d = d->next) {
        struct shim_dentry* child;
        if ((ret = lookup_dentry(dent, d->name, strlen(d->name), &child)) < 0) {
            /* -ENOENT from underlying lookup should be handled as DENTRY_NEGATIVE */
            assert(ret != -ENOENT);

            /* Ignore inaccessible files */
            if (ret == -EACCES)
                continue;

            /* Other errors fail the lookup */
            goto done_read;
        }

        if (child->state & DENTRY_NEGATIVE) {
            put_dentry(child);
            continue;
        }

        if (!(child->state & DENTRY_VALID)) {
            child->state |= DENTRY_VALID | DENTRY_RECENTLY;
        }

        set_dirent_type(&child->type, d->type);
        child->ino = d->ino;
        put_dentry(child);
    }

    /* Once DENTRY_LISTED is set, the ino of the newly created file will not be updated, so its
     * ino needs to be set in create() or open(O_CREAT). */
    dent->state |= DENTRY_LISTED;
    ret = 0;

done_read:
    unlock(&g_dcache_lock);
    free(dirent);
    return ret;
}

/* This function caches the contents of a directory (dent), already
 * in the listed state, in a buffer associated with a handle (hdl).
 *
 * This function should only be called once on a handle.
 *
 * Returns 0 on success, <0 on failure.
 */
int list_directory_handle(struct shim_dentry* dent, struct shim_handle* hdl) {
    struct shim_dentry** children = NULL;

    int nchildren = dent->nchildren, count = 0;
    struct shim_dentry* child;
    struct shim_dentry* tmp;

    assert(hdl->dir_info.buf == (void*)-1);
    assert(hdl->dir_info.ptr == (void*)-1);

    // Handle the case where the handle is on a rmdir-ed directory
    // Handle is already locked by caller, so these values shouldn't change
    // after dcache lock is acquired
    if (dent->state & DENTRY_NEGATIVE) {
        hdl->dir_info.buf = NULL;
        hdl->dir_info.ptr = NULL;
        return 0;
    }

    children = malloc(sizeof(struct shim_dentry*) * (nchildren + 1));
    if (!children)
        return -ENOMEM;

    lock(&g_dcache_lock);
    LISTP_FOR_EACH_ENTRY_SAFE(child, tmp, &dent->children, siblings) {
        if (count >= nchildren)
            break;

        struct shim_dentry* c = child;

        while (c->state & DENTRY_MOUNTPOINT)
            c = c->mounted->root;

        if (c->state & DENTRY_VALID) {
            get_dentry(c);
            children[count++] = c;
        }

        dentry_gc(child);
    }
    children[count] = NULL;

    hdl->dir_info.buf = children;
    hdl->dir_info.ptr = children;

    unlock(&g_dcache_lock);

    return 0;
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
