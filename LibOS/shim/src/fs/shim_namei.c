/* Copyright (C) 2017, University of North Carolina at Chapel Hill
   and Fortanix, Inc.
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
 * shim_namei.c
 *
 * This file contains codes for parsing a FS path and looking up in the
 * directory cache.
 */

#include <asm/fcntl.h>
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <stdbool.h>

#include <pal.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_profile.h>
#include <shim_thread.h>
#include <shim_utils.h>

/* Advances a char pointer (string) past any repeated slashes and returns the result.
 * Must be a null-terminated string. */
static inline const char * eat_slashes (const char * string)
{
    while (*string == '/')
        string++;
    return string;
}

static inline int __lookup_flags (int flags)
{
    int retval = LOOKUP_FOLLOW;

    if (flags & O_NOFOLLOW)
        retval &= ~LOOKUP_FOLLOW;

    if ((flags & (O_CREAT|O_EXCL)) == (O_CREAT|O_EXCL))
        retval &= ~LOOKUP_FOLLOW;

    if (flags & O_DIRECTORY)
        retval |= LOOKUP_DIRECTORY;

    return retval;
}

/* check permission (specified by mask) of a dentry. If force is not set,
 * permission is considered granted on invalid dentries
 *
 * mask is the same as mode in the manual for access(2): F_OK, R_OK, W_OK,
 * X_OK
 *
 * Returns 0 on success, negative on failure.
 */
/* Assume caller has acquired dcache_lock */
int __permission(struct shim_dentry* dent, mode_t mask) {
    assert(locked(&dcache_lock));

    mode_t mode = 0;

    /* Pseudo dentries don't really have permssions.  I wonder if
     * we could tighten up the range of allowed calls.
     */
    if (dent->state & DENTRY_ANCESTOR)
        return 0;

    if (dent->state & DENTRY_NEGATIVE)
        return -ENOENT;

    /* At this point, we can just return zero if we are only
     * checking F_OK (the dentry isn't negative). */
    if (mask == F_OK)
        return 0;

    /* A dentry may not have the mode stored.  The original code
     * used both NO_MODE and !DENTRY_VALID; let's try to consolidate to
     * just NO_MODE.
     */
    if (dent->mode == NO_MODE) {

        /* DEP 6/16/17: I don't think we should be defaulting to 0 if
         * there isn't a mode function. */
        assert(dent->fs);
        assert(dent->fs->d_ops);
        assert(dent->fs->d_ops->mode);

        /* Fall back to the low-level file system */
        int err = dent->fs->d_ops->mode(dent, &mode);

        /*
         * DEP 6/16/17: I think the low-level file system should be
         * setting modes, rather than defaulting to open here.
         * I'm ok with a file system that doesn't care setting the
         * permission to all.
         *
         * Set an assertion here to catch these cases in debugging.
         */
        assert(err != -ESKIPPED);

        if (err < 0)
            return err;

        dent->mode = mode;
    }

    mode = dent->mode;


    if (((mode >> 6) & mask) == mask)
        return 0;

    return -EACCES;
}

/*
 * This function looks up a single dentry based on its parent dentry pointer
 * and the name.  Namelen is the length of char * name.
 * The dentry is returned in pointer *new.  The refcount of new is incremented
 * by one.
 *
 * Parent can be null when mounting the root file system.  In this case, the
 * function creates a new, negative dentry, which will then be initialized by
 * the mount code and made non-negative.
 *
 * The fs argument specifies the file system type to use on a miss; typically,
 * this will be parent->fs.
 *
 * This function checks the dcache first, and then, on a miss, falls back
 * to the low-level file system.
 *
 * XXX: The original code returned whether the process can exec the task?
 *       Not clear this is needed; try not doing this.
 *
 * Returns zero if the file is found; -ENOENT if it doesn't exist,
 * possibly other errors.
 *
 * The caller should hold the dcache_lock.
 */
int lookup_dentry (struct shim_dentry * parent, const char * name, int namelen, struct shim_dentry ** new, struct shim_mount * fs)
{
    assert(locked(&dcache_lock));

    struct shim_dentry * dent = NULL;
    int do_fs_lookup = 0;
    int err = 0;

    /* Look up the name in the dcache first, one atom at a time. */
    dent = __lookup_dcache(parent, name, namelen, NULL);

    if (!dent) {
        if (parent) {
            /* Newly created dentry's relative path will be a concatenation of parent
             * + name strings (see get_new_dentry), make sure it fits into qstr */
            if (parent->rel_path.len + 1 + namelen >= STR_SIZE) {  /* +1 for '/' */
                debug("Relative path exceeds the limit %d\n", STR_SIZE);
                err = -ENAMETOOLONG;
                goto out;
            }
        }

        dent = get_new_dentry(fs, parent, name, namelen, NULL);
        if (!dent) {
            err = -ENOMEM;
            goto out;
        }
        do_fs_lookup = 1;
    } else {
        if (!(dent->state & DENTRY_VALID))
            do_fs_lookup = 1;
    }

    if (do_fs_lookup) {
        // This doesn't make any sense if there isn't a low-level
        // lookup function.
        assert(dent->fs);
        assert(dent->fs->d_ops);
        assert(dent->fs->d_ops->lookup);
        err = dent->fs->d_ops->lookup(dent);

        /* XXX: On an error, it seems like we should probably destroy
         * the dentry, rather than keep some malformed dentry lying around.
         * Not done in original code, so leaving for now.
         */
        if (err) {
            if (err == -ENOENT || err == -EACCES) {
                /* Non-existing files and inaccessible files are marked as
                 * negative dentries, so they can still be cached */
                dent->state |= DENTRY_NEGATIVE;
            } else {

                /* Trying to weed out ESKIPPED */
                assert(err != -ESKIPPED);
                goto out;
            }
        }
        dent->state |= DENTRY_VALID;
    }

    /* I think we can assume we have a valid dent at this point */
    assert(dent);
    assert(dent->state & DENTRY_VALID);

    // Set the err is ENOENT if negative
    if (dent->state & DENTRY_NEGATIVE)
        err = -ENOENT;

    if (new) {
        get_dentry(dent);
        *new = dent;
    }

out:
    if (dent) {
        put_dentry(dent);
    }

    return err;
}

/*
 * Looks up path under start dentry.  Saves in dent (if specified; dent may be
 * NULL).  Start is a hint, and may be null; in this case, we use the first
 * char of the path to infer whether the path is relative or absolute.
 *
 * Primarily to support bootstrapping, this function takes a fs parameter,
 * that specifies a mount point. Typically, this would be start->fs, but there
 * are cases where start may be absent (e.g., in bootstrapping).  Fs can be
 * null only if the current thread is defined.
 *
 * Assumes dcache_lock is held; main difference from path_lookupat is that
 * dcache_lock is acquired/released.
 *
 * We assume the caller has incremented the reference count on start and its
 * associated file system mount by one
 *
 * The refcount is raised by one on the returned dentry and associated mount.
 *
 * The make_ancestor flag creates pseudo-dentries for any parent paths that
 * are not in cache and do not exist on the underlying file system.  This is
 * intended for use only in setting up the file system view specified in the
 * manifest.
 *
 * If the file isn't found, returns -ENOENT.
 *
 * If the LOOKUP_DIRECTORY flag is set, and the found file isn't a directory,
 *  returns -ENOTDIR.
 */
int __path_lookupat (struct shim_dentry * start, const char * path, int flags,
                     struct shim_dentry ** dent, int link_depth,
                     struct shim_mount * fs, bool make_ancestor)
{
    assert(locked(&dcache_lock));
    // Basic idea: recursively iterate over path, peeling off one atom at a
    // time.
    /* Chia-Che 12/5/2014:
     * XXX I am not a big fan of recursion. I am giving a pass to this code
     * for now, but eventually someone (probably me) should rewrite it. */
    const char * my_path;
    int my_pathlen = 0;
    int err = 0;
    struct shim_dentry *my_dent = NULL;
    struct shim_qstr this = QSTR_INIT;
    bool leaf_case = false; // Leaf call in case of recursion
    bool no_start = false; // start not passed
    bool no_fs = false; // fs not passed
    struct shim_thread * cur_thread = get_cur_thread();

    if (cur_thread && *path == '/') {
        /*
         * Allow (start != NULL, absolute path) for *at() system calls.
         * which are common case as normal namei path resolution.
         */
        start = cur_thread->root;
        no_start = true;
        get_dentry(start);
        fs = NULL;
    }
    if (!start) {
        if (cur_thread) {
            start = cur_thread->cwd;
        } else {
            /* Start at the global root if we have no fs and no start dentry.
             * This should only happen as part of initialization.
             */
            start = dentry_root;
            assert(start);
        }
        no_start = true;
        // refcount should only be incremented if the caller didn't do it
        get_dentry(start);
        assert(fs == NULL);
    }

    assert(start);
    if (!fs) {
        no_fs = true;
        fs = start->fs;
        // refcount should only be incremented if the caller didn't do it
        get_mount(fs);
    }

    assert(fs);
    assert(start->state & DENTRY_ISDIRECTORY);

    // Peel off any preceeding slashes
    path = eat_slashes(path);

    // Check that we didn't hit the leaf case
    if (*path == '\0') {
        // We'll return start since this is the last path element
        my_dent = start;
        // Increment refcount of the found entry
        get_dentry(my_dent);
        leaf_case = true;
    } else {
        my_path = path;
        // Find the length of the path
        while (*my_path != '/' && *my_path != '\0') {
            my_path++;
            my_pathlen++;
        }

        if (my_pathlen > MAX_FILENAME) {
            err = -ENAMETOOLONG;
            goto out;
        }

        /* Handle . */
        if (my_pathlen == 1 && *path == '.') {
            /* For the recursion to work, we need to do the following:
             * Bump the ref count, set my_dent to start
             */
            my_dent = start;
            get_dentry(my_dent);
        } else if (my_pathlen == 2 && path[0] == '.' && path[1] == '.') {
            if (start->parent) {
                my_dent = start->parent;
            } else {
                // Root
                my_dent = start;
            }
            get_dentry(my_dent);

        } else {
            // Once we have an atom, look it up and update start
            err = lookup_dentry(start, path, my_pathlen, &my_dent, fs);
            // my_dent's refcount is incremented after this, consistent with cases above

            // Allow a negative dentry to move forward
            if (err < 0 && err != -ENOENT)
                goto out;

            // Drop any trailing slashes from the path
            my_path = eat_slashes(my_path);

            // If the LOOKUP_FOLLOW flag is set, check if we hit a symlink
            if ((flags & LOOKUP_FOLLOW) && (my_dent->state & DENTRY_ISLINK)) {
                // Keep from following too many links
                if (link_depth > 80) {
                    err = -ELOOP;
                    goto out;
                }
                link_depth++;

                assert(my_dent->fs->d_ops && my_dent->fs->d_ops->follow_link);

                if ((err = my_dent->fs->d_ops->follow_link(my_dent, &this)) < 0)
                    goto out;

                path = qstrgetstr(&this);

                if (path) {
                    /* symlink name starts with a slash, restart lookup at root */
                    if (*path == '/') {
                        struct shim_dentry * root;
                        // not sure how to deal with this case if cur_thread isn't defined
                        assert(cur_thread);
                        root = cur_thread->root;
                        /*XXX: Check out path_reacquire here? */
                        // my_dent's refcount was incremented by lookup_dentry above,
                        // we need to not leak it here
                        put_dentry(my_dent);
                        my_dent = root;
                        get_dentry(my_dent);
                    } else {
                        // Relative path, stay in this dir
                        put_dentry(my_dent);
                        my_dent = start;
                        get_dentry(my_dent);
                    }
                }
            }
        }

        // Drop any trailing slashes from the path
        my_path = eat_slashes(my_path);

        // If we found something, and there is more, recur
        if (*my_path != '\0') {

            /* If we have more to look up, but got a negative DENTRY,
             * we need to fail or (unlikely) create an ancestor dentry.*/
            if (my_dent->state & DENTRY_NEGATIVE) {
                if (make_ancestor) {
                    my_dent->state |= DENTRY_ANCESTOR;
                    my_dent->state |= DENTRY_ISDIRECTORY;
                    my_dent->state &= ~DENTRY_NEGATIVE;
                } else {
                    err = -ENOENT;
                    goto out;
                }
            }

            /* Although this is slight over-kill, let's just always increment the
             * mount ref count on a recursion, for easier bookkeeping */
            get_mount(my_dent->fs);
            err = __path_lookupat (my_dent, my_path, flags, dent, link_depth,
                                   my_dent->fs, make_ancestor);
            if (err < 0)
                goto out;
            /* If we aren't returning a live reference to the target dentry, go
             * ahead and release the ref count when we unwind the recursion.
             */
            put_mount(my_dent->fs);
            put_dentry(my_dent);
        } else {
            /* If make_ancestor is set, we also need to handle the case here */
            if (make_ancestor && (my_dent->state & DENTRY_NEGATIVE)) {
                my_dent->state |= DENTRY_ANCESTOR;
                my_dent->state |= DENTRY_ISDIRECTORY;
                my_dent->state &= ~DENTRY_NEGATIVE;
                if (err == -ENOENT)
                    err = 0;
            }
            leaf_case = true;
        }
    }

    /* Base case.  Set dent and return. */
    if (leaf_case) {
        if (dent)
            *dent = my_dent;

        // Enforce LOOKUP_CREATE flag at a higher level
        if (my_dent->state & DENTRY_NEGATIVE) {
            err = -ENOENT;
            goto out;
        }

        // Enforce the LOOKUP_DIRECTORY flag
        if ((flags & LOOKUP_DIRECTORY) && !(my_dent->state & DENTRY_ISDIRECTORY))
            err = -ENOTDIR;
    }

out:
    /* If we didn't have a start dentry, decrement the ref count here */
    if (no_start)
        put_dentry(start);

    if (no_fs)
        put_mount(fs);

    qstrfree(&this);
    return err;
}

/* Just wraps __path_lookupat, but also acquires and releases the dcache_lock.
 */
int path_lookupat (struct shim_dentry * start, const char * name, int flags,
                   struct shim_dentry ** dent, struct shim_mount * fs)
{
    int ret = 0;
    lock(&dcache_lock);
    ret = __path_lookupat (start, name, flags, dent, 0, fs, 0);
    unlock(&dcache_lock);
    return ret;
}


/* Open path with given flags, in mode, similar to Unix open.
 *
 * The start dentry specifies where to begin the search, and can be null. If
 * specified, we assume the caller has incremented the ref count on the start,
 * but not the associated mount (probably using get_dirfd_dentry)
 *
 * hdl is an optional argument; if passed in, it is initialized to
 *   refer to the opened path.
 *
 * We assume the caller has not increased
 *
 * The result is stored in dent.
 */

int open_namei (struct shim_handle * hdl, struct shim_dentry * start,
                const char * path, int flags, int mode,
                struct shim_dentry ** dent)
{
    int lookup_flags = __lookup_flags(flags);
    mode_t acc_mode = ACC_MODE(flags & O_ACCMODE);
    int err = 0, newly_created = 0;
    struct shim_dentry *mydent = NULL;

    if (*path == '\0') {
        /* corner case: trying to open with empty filename */
        return -ENOENT;
    }

    lock(&dcache_lock);

    // lookup the path from start, passing flags
    err = __path_lookupat(start, path, lookup_flags, &mydent, 0, NULL, 0);

    if (mydent && (mydent->state & DENTRY_ISDIRECTORY)) {
        if (flags & O_WRONLY || flags & O_RDWR) {
            err = -EISDIR;
            goto out;
        }
    }

    // Deal with O_CREAT, O_EXCL, but only if we actually got a valid prefix
    // of directories.
    if (mydent && err == -ENOENT && (flags & O_CREAT)) {
        // Create the file
        struct shim_dentry * dir = mydent->parent;

        if (!dir) {
            err = -ENOENT;
            goto out;
        }

        // Check the parent permission first
        err = __permission(dir, MAY_WRITE | MAY_EXEC);
        if (err)  goto out;

        // Try EINVAL when creat isn't an option
        if (!dir->fs->d_ops || !dir->fs->d_ops->creat) {
            err = -EINVAL;
            goto out;
        }

        // Differentiate directory and file creation;
        // Seems like overloading functionality that could probably be more
        // cleanly pushed into shim_do_mkdir
        if (flags & O_DIRECTORY) {
            err = dir->fs->d_ops->mkdir(dir, mydent, mode);
        } else {
            err = dir->fs->d_ops->creat(hdl, dir, mydent, flags, mode);
        }
        if (err)
            goto out;

        newly_created = 1;

        // If we didn't get an error and made a directory, set the dcache dir flag
        if (flags & O_DIRECTORY) {
            mydent->state |= DENTRY_ISDIRECTORY;
            mydent->type = S_IFDIR;
        }

        // Once the dentry is creat-ed, drop the negative flag
        mydent->state &= ~DENTRY_NEGATIVE;

        // Set err back to zero and fall through
        err = 0;
    } else if (err == 0 && ((flags & (O_CREAT|O_EXCL)) == (O_CREAT|O_EXCL))) {
        err = -EEXIST;
    }

    if (err < 0) {
        goto out;
    }

    // Check permission, but only if we didn't create the file.
    // creat/O_CREAT have idiosyncratic semantics about opening a
    // newly-created, read-only file for writing, but only the first time.
    if (!newly_created) {
        if ((err = __permission(mydent, acc_mode)) < 0)
            goto out;
    }

    // Set up the file handle, if provided
    if (hdl)
        err = dentry_open(hdl, mydent, flags);

out:
    if (dent && !err)
        *dent = mydent;

    unlock(&dcache_lock);

    return err;
}

/* This function calls the low-level file system to do the work
 * of opening file indicated by dent, and initializing it in hdl.
 * Flags are standard open flags.
 *
 * If O_TRUNC is specified, this function is responsible for calling
 * the underlying truncate function.
 */

int dentry_open (struct shim_handle * hdl, struct shim_dentry * dent,
                 int flags)
{
    int ret = 0;
    size_t size;
    char *path;
    struct shim_mount * fs = dent->fs;

    /* I think missing functionality should be treated as EINVAL, or maybe
     * ENOSYS?*/
    if (!fs->d_ops || !fs->d_ops->open) {
        ret = -EINVAL;
        goto out;
    }

    if ((ret = fs->d_ops->open(hdl, dent, flags)) < 0)
        goto out;

    set_handle_fs(hdl, fs);
    get_dentry(dent);
    hdl->dentry = dent;
    hdl->flags = flags;
    // Set the type of the handle if we have a directory.  The original code
    // had a special case for this.
    // XXX: Having a type on the handle seems a little redundant if we have a
    // dentry too.
    if (dent->state & DENTRY_ISDIRECTORY) {
        hdl->type = TYPE_DIR;
        memcpy(hdl->fs_type, fs->type, sizeof(fs->type));

        // Set dot and dot dot for some reason
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
        hdl->dir_info.buf = (void *)-1;
        hdl->dir_info.ptr = (void *)-1;
    }
    path = dentry_get_path(dent, true, &size);
    if (!path) {
        ret = -ENOMEM;
        goto out;
    }
    qstrsetstr(&hdl->path, path, size);

    /* truncate regular writable file if O_TRUNC is given */
    if ((flags & O_TRUNC) &&
            ((flags & O_RDWR) | (flags & O_WRONLY)) &&
            !(dent->state & DENTRY_ISDIRECTORY) &&
            !(dent->state & DENTRY_MOUNTPOINT) &&
            !(dent->state & DENTRY_ISLINK)) {
        if (!fs->fs_ops->truncate) {
            ret = -EINVAL;
            goto out;
        }
        ret = fs->fs_ops->truncate(hdl, 0);
    }

out:
    return ret;
}

static inline void set_dirent_type (mode_t * type, int d_type)
{
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
int list_directory_dentry (struct shim_dentry *dent) {

    int ret = 0;
    struct shim_mount * fs = dent->fs;
    lock(&dcache_lock);

    /* DEP 8/4/17: Another process could list this directory
     * while we are waiting on the dcache lock.  This is ok,
     * no need to blow an assert.
     */
    if (dent->state & DENTRY_LISTED){
        unlock(&dcache_lock);
        return 0;
    }

    // DEP 7/9/17: In yet another strange turn of events in POSIX-land,
    // you can do a readdir on a rmdir-ed directory handle.  What you
    // expect to learn is beyond me, but be careful with blowing assert
    // and tell the program something to keep it moving.
    if (dent->state & DENTRY_NEGATIVE) {
        unlock(&dcache_lock);
        return 0;
    }

    assert(dent->state & DENTRY_ISDIRECTORY);

    struct shim_dirent * dirent = NULL;

    if ((ret = fs->d_ops->readdir(dent, &dirent)) < 0 || !dirent) {
        dirent = NULL;
        goto done_read;
    }

    struct shim_dirent * d = dirent;
    for ( ; d ; d = d->next) {
        struct shim_dentry * child;
        if ((ret = lookup_dentry(dent, d->name, strlen(d->name),
                                 &child, fs)) < 0) {
            if (ret != -ENOENT) {
                /* if the file is recently deleted or inaccessible, ignore it */
                goto done_read;
            }
        }

        if (child->state & DENTRY_NEGATIVE)
            continue;

        if (!(child->state & DENTRY_VALID)) {
            set_dirent_type(&child->type, d->type);
            child->state |= DENTRY_VALID|DENTRY_RECENTLY;
        }

        child->ino = d->ino;
    }

    /* Once DENTRY_LISTED is set, the ino of the newly created file will not be updated, so its
     * ino needs to be set in create() or open(O_CREAT). */
    dent->state |= DENTRY_LISTED;
    ret = 0;

done_read:
    unlock(&dcache_lock);
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
int list_directory_handle (struct shim_dentry * dent, struct shim_handle * hdl)
{
    struct shim_dentry ** children = NULL;

    int nchildren = dent->nchildren, count = 0;
    struct shim_dentry * child;

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

    children = malloc(sizeof(struct shim_dentry *) * (nchildren + 1));
    if (!children)
        return -ENOMEM;

    lock(&dcache_lock);
    LISTP_FOR_EACH_ENTRY(child, &dent->children, siblings) {
        if (count >= nchildren)
            break;

        struct shim_dentry * c = child;

        while (c->state & DENTRY_MOUNTPOINT)
            c = c->mounted->root;

        if (c->state & DENTRY_VALID) {
            get_dentry(c);
            children[count++] = c;
        }
    }
    children[count] = NULL;

    hdl->dir_info.buf = children;
    hdl->dir_info.ptr = children;

    unlock(&dcache_lock);

    return 0;
}

int get_dirfd_dentry(int dirfd, struct shim_dentry** dir) {
    if (dirfd == AT_FDCWD) {
        struct shim_thread* cur = get_cur_thread();
        get_dentry(cur->cwd);
        *dir = cur->cwd;
        return 0;
    }

    if (dirfd < 0) {
        return -EBADF;
    }

    struct shim_handle* hdl = get_fd_handle(dirfd, NULL, NULL);
    if (!hdl) {
        return -EBADF;
    }

    if (hdl->type != TYPE_DIR) {
        put_handle(hdl);
        return -ENOTDIR;
    }

    get_dentry(hdl->dentry);
    *dir = hdl->dentry;
    put_handle(hdl);
    return 0;
}
