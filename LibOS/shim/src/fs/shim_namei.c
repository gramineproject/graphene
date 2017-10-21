/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_namei.c
 *
 * This file contains codes for parsing a FS path and looking up in the
 * directory cache.
 * The source codes are imported from Linux kernel, but simplified according
 * to the characteristic of library OS.
 */

#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_fs.h>
#include <shim_profile.h>

#include <pal.h>

#include <linux/stat.h>
#include <linux/fcntl.h>

#include <asm/fcntl.h>

/* check permission of a dentry. If force is not set, permission
   is consider granted on invalid dentries */
/* have dcache_lock acquired */
int permission (struct shim_dentry * dent, int mask, bool force)
{
    mode_t mode = 0;

    if (dent->state & DENTRY_ANCESTER)
        return 0;

    if (dent->state & DENTRY_NEGATIVE)
        return -ENOENT;

    if (!(dent->state & DENTRY_VALID) || dent->mode == NO_MODE) {
        if (!dent->fs || !dent->fs->d_ops || !dent->fs->d_ops->mode)
            return 0;

        /* the filesystem will decide the results when permission
           check isn't forced. If -ESKIPPED is returned, we assume
           the file/directory is accessible for now. */
        int err = dent->fs->d_ops->mode(dent, &mode, force);

        if (err == -ESKIPPED)
            return 0;

        if (err < 0)
            return err;

        if (dent->parent)
            dent->parent->nchildren++;

        dent->state |= DENTRY_VALID|DENTRY_RECENTLY;
        dent->mode = mode;
    } else {
        mode = dent->mode;
    }

    if (((mode >> 6) & mask & (MAY_READ|MAY_WRITE|MAY_EXEC)) == mask)
        return 0;

    return -EACCES;
}

static inline int __do_lookup_dentry (struct shim_dentry * dent, bool force)
{
    int err = 0;

    if (!(dent->state & DENTRY_VALID) &&
        dent->fs && dent->fs->d_ops && dent->fs->d_ops->lookup) {
        if ((err = dent->fs->d_ops->lookup(dent, force)) < 0) {
            if (err == -ENOENT) {
                dent->state |= DENTRY_NEGATIVE;
            } else {
                if (err == -ESKIPPED)
                    err = 0;
                return err;
            }
        }

        if (dent->parent)
            dent->parent->nchildren++;

        dent->state |= DENTRY_VALID|DENTRY_RECENTLY;
    }

    return 0;
}

/* looking up single dentry based on its parent and name */
/* have dcache_lock acquired */
int lookup_dentry (struct shim_dentry * parent, const char * name, int namelen,
                   bool force, struct shim_dentry ** new)
{
    struct shim_dentry * dent = NULL;
    int err = 0;
    HASHTYPE hash;
    dent = __lookup_dcache(parent, name, namelen, NULL, 0, &hash);

    if ((err = permission(parent, MAY_EXEC, false)) < 0) {
        if (dent)
            dent->state |= DENTRY_UNREACHABLE;
        goto out;
    }

    if (!dent) {
        dent = get_new_dentry(parent, name, namelen);

        if (!dent) {
            err = -ENOMEM;
            goto out;
        }

        if (parent->fs) {
            get_mount(parent->fs);
            dent->fs = parent->fs;
        }

        __set_parent_dentry(dent, parent);
        __add_dcache(dent, &hash);
    }

    err = __do_lookup_dentry(dent, force);
    dent->state |= DENTRY_REACHABLE;
    *new = dent;
out:
    return err;
}

static void path_reacquire (struct lookup * look, struct shim_dentry * dent);

/* looking up single dentry, but use struct lookup */
/* have dcache_lock acquired */
static int do_lookup (struct lookup * look, const char * name, int namelen,
                      bool force)
{
    int err = 0;
    struct shim_dentry * dent = NULL;

    if ((err = lookup_dentry(look->dentry, name, namelen,force, &dent)) < 0)
        goto fail;

    path_reacquire(look, dent);

    look->last      = dentry_get_name(dent);
    look->last_type = LAST_NORM;

fail:
    return err;
}

static int link_path_walk (const char * name, struct lookup * look);

/* have dcache_lock acquired */
void path_acquire (struct lookup * look)
{
    if (look->dentry)
        get_dentry(look->dentry);

    if (look->mount)
        get_mount(look->mount);
}

/* have dcache_lock acquired */
void path_release (struct lookup * look)
{
    if (look->dentry)
        put_dentry(look->dentry);

    if (look->mount)
        put_mount(look->mount);
}

/* have dcache_lock acquired */
static void path_reacquire (struct lookup * look, struct shim_dentry * dent)
{
    struct shim_dentry * old_dent = look->dentry;
    struct shim_mount * old_mount = look->mount;

    if (dent && dent != old_dent) {
        get_dentry(dent);
        if (old_dent)
            put_dentry(old_dent);
        look->dentry = dent;
    }

    if (dent && dent->fs && dent->fs != old_mount) {
        get_mount(dent->fs);
        if (old_mount)
            put_mount(old_mount);
        look->mount = dent->fs;
    }
}

/* try follow a link where the dentry points to */
/* have dcache_lock acquired */
static inline int __do_follow_link (struct lookup * look)
{
    int err = 0;

    struct shim_dentry * dent = look->dentry;

    assert(dent->state & DENTRY_ISLINK);
    assert(dent->fs->d_ops && dent->fs->d_ops->follow_link);

    struct shim_qstr this = QSTR_INIT;

    if ((err = dent->fs->d_ops->follow_link(dent, &this)) < 0)
        goto out;

    const char * link = qstrgetstr(&this);

    if (link) {
        /* symlink name starts with a slash, restart lookup at root */
        if (*link == '/') {
            struct shim_dentry * root = get_cur_thread()->root;
            path_reacquire(look, root);
        }

        look->flags |= LOOKUP_CONTINUE;

        /* now walk the whole link again */
        err = link_path_walk(link, look);
    }

out:
    qstrfree(&this);
    return err;
}

/* follow links on a dentry until the last target */
/* have dcache_lock acquired */
static int follow_link (struct lookup * look)
{
    int err = 0;
    int old_depth = look->depth;

    while (err >= 0 && look->dentry->state & DENTRY_ISLINK) {
        /* checks to contain link explosion */
        if (look->depth > 80) {
            err = -ELOOP;
            break;
        }

        look->depth++;
        err = __do_follow_link(look);
    }

    if (err < 0)
        look->depth = old_depth;

    return err;
}

/* follow a single dot-dot to the parent */
/* have dcache_lock acquired */
static int follow_dotdot (struct lookup * look)
{
    struct shim_dentry * dent = look->dentry;
    struct shim_mount * mount = look->mount;
    struct shim_thread * cur_thread = get_cur_thread();

    while (1) {
        /* if it reaches the root of current filesystem,
           return immediately. */
        if (dent == cur_thread->root)
            break;

        if (dent != mount->root) {
            struct shim_dentry * parent = dent->parent;
            path_reacquire(look, parent);
            break;
        }

        struct shim_dentry * parent = mount->mount_point;
        path_reacquire(look, parent);
        dent = parent;
        mount = parent->fs;
    }

    return 0;
}

/* walk through a absolute path based on current lookup structure,
   across mount point, dot dot and symlinks */
/* have dcache_lock acquired */
static int link_path_walk (const char * name, struct lookup * look)
{
    struct shim_dentry * dent = NULL;
    int err = 0;
    int lookup_flags = look->flags;

    /* remove all the slashes at the beginning */
    while (*name == '/')
        name++;

    if (!*name) {
        if (!(lookup_flags & LOOKUP_CONTINUE) &&
            (lookup_flags & LOOKUP_PARENT))
            path_reacquire(look, look->dentry->parent);

        goto out;
    }

    dent = look->dentry;
    lookup_flags |= LOOKUP_CONTINUE;

    while (*name) {
        const char * this_name = look->last = name;
        int namelen = -1;
        char c;

        do {
            namelen++;
            c = name[namelen];
        } while (c && (c != '/'));

        name += namelen;

        if (!c) {
            lookup_flags &= ~LOOKUP_CONTINUE;
        } else {
            while (*(++name) == '/');

            if (!*name) {
                lookup_flags |= LOOKUP_DIRECTORY;
                lookup_flags &= ~LOOKUP_CONTINUE;
            }
        }

        look->last_type = LAST_NORM;

        if (this_name[0] == '.')
            switch (namelen) {
                case 1:
                    look->last_type = LAST_DOT;
                    break;
                case 2:
                    if (this_name[1] == '.')
                        look->last_type = LAST_DOTDOT;
                    /* fallthrough */
                default:
                    break;
            }


        if (!(lookup_flags & LOOKUP_CONTINUE) &&
            (lookup_flags & LOOKUP_PARENT))
            goto out;

        switch (look->last_type) {
            case LAST_DOT:
                continue;
            case LAST_DOTDOT:
                err = follow_dotdot(look);
                if (err < 0)
                    goto out;
                /* fallthrough */
            default:
                break;
        }

        if (look->last_type == LAST_NORM) {
            /* actual lookup */
            err = do_lookup(look, this_name, namelen, false);
            if (err < 0)
                goto out;
        }

        if ((look->dentry->state & DENTRY_ISLINK) &&
            (look->last_type != LAST_NORM || look->flags & LOOKUP_FOLLOW)) {
            err = follow_link(look);
            if (err < 0)
                goto out;
        }

        assert(!(look->dentry->state & DENTRY_MOUNTPOINT));
        dent = look->dentry;

        if (!(dent->state & DENTRY_VALID) &&
            (look->flags & LOOKUP_SYNC && !(lookup_flags & LOOKUP_CONTINUE)) &&
            look->mount && look->mount->d_ops &&
            look->mount->d_ops->lookup) {
            err = look->mount->d_ops->lookup(dent, 1);
            if (err < 0) {
                if (err == -ENOENT) {
                    if (dent->state & DENTRY_VALID && dent->parent)
                        dent->parent->nchildren--;

                    dent->state |= DENTRY_NEGATIVE;
                    err = 0;
                } else {
                    goto out;
                }
            }

            if (!(dent->state & DENTRY_NEGATIVE) && dent->parent)
                dent->parent->nchildren++;

            dent->state |= DENTRY_VALID|DENTRY_RECENTLY;
        }

        if (dent->state & DENTRY_NEGATIVE) {
            if (lookup_flags & LOOKUP_CONTINUE) {
                if (!(dent->state & DENTRY_ANCESTER)) {
                    err = -ENOENT;
                    goto out;
                }
            } else {
                goto out;
            }
        }

        if (!(lookup_flags & LOOKUP_CONTINUE) &&
            (look->flags & LOOKUP_DIRECTORY) &&
            (dent->state & DENTRY_VALID) &&
            !(dent->state & DENTRY_ISDIRECTORY)) {
            err = -ENOTDIR;
            goto out;
        }
    }

out:
    return err;
}

DEFINE_PROFILE_OCCURENCE(dcache_hit, dcache);
DEFINE_PROFILE_OCCURENCE(dcache_miss, dcache);

static int path_lookup_dcache (struct shim_dentry * start, const char * path,
                               int flags,
                               struct shim_dentry ** dent,
                               struct shim_thread * cur_thread)
{
    if (!start && cur_thread)
        start = *path == '/' ? cur_thread->root : cur_thread->cwd;

    const char * startpath = NULL;
    int startpathlen = 0;
    char * fullpath = __alloca(STR_SIZE);

    if (start) {
        startpath = dentry_get_path(start, true, &startpathlen);
        memcpy(fullpath, startpath, startpathlen);
    }

    char * name = fullpath + startpathlen;
    int namelen;

    if ((namelen = get_norm_path(path, name, 0, STR_SIZE - startpathlen)) < 0)
        return namelen;

    struct shim_dentry * found =
                    __lookup_dcache(start, name, namelen,
                                    fullpath, startpathlen + namelen, NULL);

    if (found) {
        INC_PROFILE_OCCURENCE(dcache_hit);
        if (flags & LOOKUP_SYNC) {
            int ret = __do_lookup_dentry(found, true);
            if (ret < 0) {
                put_dentry(found);
                return ret;
            }
        }

        if (!(found->state & DENTRY_NEGATIVE) &&
            !(found->state & DENTRY_ISDIRECTORY) &&
            flags & LOOKUP_DIRECTORY) {
            put_dentry(found);
            return -ENOTDIR;
        }

        if (!(found->state & (DENTRY_REACHABLE|DENTRY_UNREACHABLE))) {
            put_dentry(found);
            found = NULL;
        }
    } else {
        INC_PROFILE_OCCURENCE(dcache_miss);
    }

    *dent = found;
    return 0;
}

/* have dcache_lock acquired */
static int path_lookup_walk (struct shim_dentry * start,
                             const char * name, int flags,
                             struct lookup * look,
                             struct shim_thread * cur_thread)
{
    struct shim_dentry * dent = start;

    if (!dent) {
        if (cur_thread)
            lock(cur_thread->lock);

        dent = (*name == '/' ?
               (cur_thread ? cur_thread->root : NULL) :
               (cur_thread ? cur_thread->cwd  : NULL)) ? : dentry_root;

        if (cur_thread)
            unlock(cur_thread->lock);
    }

    while (dent->state & DENTRY_MOUNTPOINT)
        dent = dent->mounted->root;

    look->dentry    = dent;
    look->mount     = dent->fs;
    look->last      = dentry_get_name(dent);
    look->last_type = LAST_ROOT;
    look->flags     = flags;
    look->depth     = 0;

    path_acquire(look);

    return link_path_walk(name, look);
}

DEFINE_PROFILE_CATAGORY(path_lookup, dcache);
DEFINE_PROFILE_INTERVAL(lookup_dcache_for_path_lookup, path_lookup);
DEFINE_PROFILE_INTERVAL(lookup_walk_for_path_lookup,   path_lookup);

int __path_lookupat (struct shim_dentry * start, const char * path, int flags,
                     struct shim_dentry ** dent)
{
    struct shim_thread * cur_thread = get_cur_thread();
    struct shim_dentry * found = NULL;
    int ret = 0;
    struct lookup look;
    BEGIN_PROFILE_INTERVAL();

    ret = path_lookup_dcache(start, path, flags, &found, cur_thread);
    if (ret < 0)
        return ret;

    SAVE_PROFILE_INTERVAL(lookup_dcache_for_path_lookup);

    if (!found) {
        if ((ret = path_lookup_walk(start, path, flags, &look, cur_thread)) < 0)
            return ret;

        get_dentry(look.dentry);
        found = look.dentry;
        SAVE_PROFILE_INTERVAL(lookup_walk_for_path_lookup);

        if (flags & LOOKUP_SYNC) {
            if ((ret = __do_lookup_dentry(found, true)) < 0)
                goto out_if;
        }

        if (!(found->state & DENTRY_ISDIRECTORY) &&
            flags & LOOKUP_DIRECTORY) {
            ret = -ENOTDIR;
            goto out_if;
        }

out_if:
        path_release(&look);
    }

    if (found) {
        if (!ret && dent)
            *dent = found;
        else
            put_dentry(found);
    }

    return 0;
}

/* if path_lookup succeed, the returned dentry is pop'ed */
int path_lookupat (struct shim_dentry * start, const char * path, int flags,
                   struct shim_dentry ** dent)
{
    struct shim_thread * cur_thread = get_cur_thread();
    struct shim_dentry * found = NULL;
    int ret = 0;
    struct lookup look;

    lock(dcache_lock);
    BEGIN_PROFILE_INTERVAL();

    ret = path_lookup_dcache(start, path, flags, &found, cur_thread);

    if (ret < 0) {
        unlock(dcache_lock);
        return ret;
    }

    SAVE_PROFILE_INTERVAL(lookup_dcache_for_path_lookup);

    if (!found) {
        if ((ret = path_lookup_walk(start, path, flags, &look,
                                    cur_thread)) < 0)
            goto out;

        get_dentry(look.dentry);
        found = look.dentry;
        SAVE_PROFILE_INTERVAL(lookup_walk_for_path_lookup);

        if (flags & LOOKUP_SYNC) {
            if ((ret = __do_lookup_dentry(found, true)) < 0)
                goto out_release;
        }

        if (found->state & DENTRY_NEGATIVE &&
            !(flags & LOOKUP_CREATE)) {
            ret = -ENOENT;
            goto out_release;
        }

        if (!(found->state & DENTRY_NEGATIVE) &&
            !(found->state & DENTRY_ISDIRECTORY) &&
            flags & LOOKUP_DIRECTORY) {
            ret = -ENOTDIR;
            goto out_release;
        }

out_release:
        path_release(&look);
    }

    if (found) {
        if (!ret && dent)
            *dent = found;
        else
            put_dentry(found);
    }

out:
    unlock(dcache_lock);
    return ret;
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

int create_dentry (struct shim_handle * hdl, struct shim_dentry * dir,
                   struct shim_dentry * dent, int flags, int mode)
{
    int err = permission(dir, MAY_WRITE | MAY_EXEC, true);
    if (err)
        return err;

    if (!dir->fs->d_ops || !dir->fs->d_ops->creat)
        return -EACCES;

    err = dir->fs->d_ops->creat(hdl, dir, dent, flags, mode);
    if (err)
        return err;

    if (!hdl)
        return 0;

    set_handle_fs(hdl, dent->fs);
    get_dentry(dent);
    hdl->dentry = dent;
    hdl->flags = flags;
    int size;
    char *path = dentry_get_path(dent, true, &size);
    qstrsetstr(&hdl->path, path, size);
    return 0;
}

int create_directory (struct shim_dentry * dir, struct shim_dentry * dent,
                      int mode)
{
    int err = permission(dir, MAY_WRITE | MAY_EXEC, true);
    if (err)
        return err;

    if (!dir->fs->d_ops || !dir->fs->d_ops->mkdir)
        return -EACCES;

    return dir->fs->d_ops->mkdir(dir, dent, mode);
}

DEFINE_PROFILE_CATAGORY(open_namei, dcache);
DEFINE_PROFILE_INTERVAL(path_lookup_dcache_for_open_namei, open_namei);
DEFINE_PROFILE_INTERVAL(path_lookup_walk_for_open_namei, open_namei);
DEFINE_PROFILE_INTERVAL(path_lookup_walk_2_for_open_namei, open_namei);
DEFINE_PROFILE_INTERVAL(end_open_namei, open_namei);
DEFINE_PROFILE_INTERVAL(open_namei_permission, open_namei);
DEFINE_PROFILE_INTERVAL(open_namei_dir_open, open_namei);
DEFINE_PROFILE_INTERVAL(open_namei_dentry_open, open_namei);
DEFINE_PROFILE_INTERVAL(open_namei_lookup_2, open_namei);
DEFINE_PROFILE_INTERVAL(open_namei_path_reacquire, open_namei);
DEFINE_PROFILE_INTERVAL(open_namei_create_dir, open_namei);
DEFINE_PROFILE_INTERVAL(open_namei_create_dentry, open_namei);

int open_namei (struct shim_handle * hdl, struct shim_dentry * start,
                const char * path, int flags, int mode,
                struct shim_dentry ** dent)
{
    struct shim_thread * cur_thread = get_cur_thread();
    struct lookup look = { .dentry = NULL, .mount = NULL };
    struct shim_dentry * dir = NULL;
    int err = 0;
    int acc_mode = ACC_MODE(flags & O_ACCMODE);
    int lookup_flags = __lookup_flags(flags);

#ifdef MAY_APPEND
    if (flags & O_APPEND)
        acc_mode |= MAY_APPEND;
#endif

    BEGIN_PROFILE_INTERVAL();
    lock(dcache_lock);

#if 0
    err = path_lookup_dcache(start, path, lookup_flags|LOOKUP_OPEN,
                             &look.dentry, cur_thread);

    if (err >= 0 && look.dentry) {
        look.mount = look.dentry->fs;
        if (look.mount)
            get_mount(look.mount);
    }

    SAVE_PROFILE_INTERVAL(path_lookup_dcache_for_open_namei);

    if (err < 0) {
        unlock(dcache_lock);
        SAVE_PROFILE_INTERVAL(end_open_namei);
        return err;
    }
#endif

    if (look.dentry) {
        if (look.dentry->state & DENTRY_NEGATIVE) {
            if (!(flags & O_CREAT)) {
                err = -ENOENT;
                goto exit;
            }

            dir = look.dentry->parent;
            get_dentry(dir);
            goto do_creat;
        }

        if (flags & O_EXCL) {
            err = -EEXIST;
            goto exit;
        }

        goto do_open_locked;
    }

    /* no create, just look it up. */
    if (!(flags & O_CREAT)) {
        err = path_lookup_walk(start, path, lookup_flags|LOOKUP_OPEN,
                               &look, cur_thread);
        SAVE_PROFILE_INTERVAL(path_lookup_walk_for_open_namei);
        if (err) {
            debug("path_lookup error in open_namei\n");
            goto exit;
        }

do_open_locked:
        unlock(dcache_lock);
do_open:
        if ((err = permission(look.dentry, acc_mode, true)) < 0)
            goto exit;
        SAVE_PROFILE_INTERVAL(open_namei_permission);
        if (hdl) {
            if (look.dentry->state & DENTRY_ISDIRECTORY) {
                if ((err = directory_open(hdl, look.dentry, flags)) < 0)
                    goto exit;
                SAVE_PROFILE_INTERVAL(open_namei_dir_open);
            } else {
                err = -ENOTDIR;
                if (flags & O_DIRECTORY) {
                    debug("%s is not a directory\n",
                          dentry_get_path(look.dentry, true, NULL));
                    goto exit;
                }
                if ((err = dentry_open(hdl, look.dentry, flags)) < 0)
                    goto exit;
                SAVE_PROFILE_INTERVAL(open_namei_dentry_open);
            }
        }

        goto done;
    }

    /* create, so we need the parent */
    err = path_lookup_walk(start, path, LOOKUP_PARENT|LOOKUP_OPEN|LOOKUP_CREATE,
                           &look, cur_thread);

    SAVE_PROFILE_INTERVAL(path_lookup_walk_2_for_open_namei);

    if (err < 0 || look.last_type != LAST_NORM)
        goto exit;

    struct shim_dentry * new = NULL;
    dir = look.dentry;
    get_dentry(dir);
    err = lookup_dentry(dir, look.last, strlen(look.last), true, &new);
    SAVE_PROFILE_INTERVAL(open_namei_lookup_2);
    if (err < 0 && (err != -ENOENT || !new))
        goto exit;

    path_reacquire(&look, new);
    SAVE_PROFILE_INTERVAL(open_namei_path_reacquire);

do_creat:
    assert(dir);
    unlock(dcache_lock);

    /* negative dentry */
    if (look.dentry->state & DENTRY_NEGATIVE) {
        if (flags & O_DIRECTORY) {
            if ((err = create_directory(dir, look.dentry, mode)) < 0) {
                debug("error: create directory in open_namei\n");
                goto exit;
            }
            SAVE_PROFILE_INTERVAL(open_namei_create_dir);
            look.dentry->state |= DENTRY_ISDIRECTORY;
        } else {
            if ((err = create_dentry(hdl, dir, look.dentry, flags,
                                     mode)) < 0) {
                debug("error: create file in open_namei\n");
                goto exit;
            }
            SAVE_PROFILE_INTERVAL(open_namei_create_dentry);
        }

        look.dentry->state &= ~DENTRY_NEGATIVE;

        if (hdl && (flags & O_DIRECTORY))
            goto do_open;
        else
            goto done;
    }

    /* existing dentry */
    if (flags & O_EXCL) {
        err = -EEXIST;
        debug("error: existing dentry with O_EXCL\n");
        goto exit;
    }

    if (look.dentry->state & DENTRY_ISLINK) {
        if (flags & O_NOFOLLOW) {
            err = -ELOOP;
            debug("error: linked dentry with O_NOFOLLOW\n");
            goto exit;
        }

        if ((err = follow_link(&look)) < 0)
            goto exit;
    }

    assert(!(look.dentry->state & DENTRY_MOUNTPOINT));
    goto do_open;

done:
    if (dent) {
        get_dentry(look.dentry);
        *dent = look.dentry;
    }

    path_release(&look);

    if (locked(dcache_lock))
        unlock(dcache_lock);

    SAVE_PROFILE_INTERVAL(end_open_namei);
    return 0;

exit:
    path_release(&look);

    if (dir)
        put_dentry(dir);

    if (locked(dcache_lock))
        unlock(dcache_lock);

    SAVE_PROFILE_INTERVAL(end_open_namei);
    return err;
}

DEFINE_PROFILE_CATAGORY(dentry_open, dcache);
DEFINE_PROFILE_INTERVAL(dentry_open_open, dentry_open);
DEFINE_PROFILE_INTERVAL(dentry_open_truncate, dentry_open);
DEFINE_PROFILE_INTERVAL(dentry_open_set_path, dentry_open);

int dentry_open (struct shim_handle * hdl, struct shim_dentry * dent,
                 int flags)
{
    int ret = 0;

    struct shim_mount * fs = dent->fs;
    BEGIN_PROFILE_INTERVAL();

    if (!fs->d_ops || !fs->d_ops->open) {
        ret = -EACCES;
        goto out;
    }

    if ((ret = fs->d_ops->open(hdl, dent, flags)) < 0)
        goto out;

    SAVE_PROFILE_INTERVAL(dentry_open_open);

    set_handle_fs(hdl, fs);
    get_dentry(dent);
    hdl->dentry = dent;
    hdl->flags = flags;

    /* truncate the file if O_TRUNC is given */
    if (ret >= 0 && (flags & O_TRUNC) && fs->fs_ops->truncate) {
        ret = fs->fs_ops->truncate(hdl, 0);
        SAVE_PROFILE_INTERVAL(dentry_open_truncate);
    }

    if (ret < 0)
        goto out;

    int size;
    char *path = dentry_get_path(dent, true, &size);
    qstrsetstr(&hdl->path, path, size);
    SAVE_PROFILE_INTERVAL(dentry_open_set_path);
out:
    return ret;
}

static inline void set_dirent_type (mode_t * type, int d_type)
{
    switch (d_type) {
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

int directory_open (struct shim_handle * hdl, struct shim_dentry * dent,
                    int flags)
{
    struct shim_mount * fs = dent->fs;
    int ret = 0;

    if (!fs->d_ops || !fs->d_ops->readdir) {
        ret = -EACCES;
        goto out;
    }

    int size;
    const char * path = dentry_get_path(dent, true, &size);

    lock(dcache_lock);

    if (!(dent->state & DENTRY_LISTED)) {
        struct shim_dirent * dirent = NULL;

        if ((ret = fs->d_ops->readdir(dent, &dirent)) < 0 || !dirent)
            goto done_read;

        struct shim_dirent * d = dirent;
        for ( ; d ; d = d->next) {
            debug("read %s from %s\n", d->name, path);

            struct shim_dentry * child;
            if ((ret = lookup_dentry(dent, d->name, strlen(d->name), false,
                                     &child)) < 0)
                goto done_read;

            if (child->state & DENTRY_NEGATIVE)
                continue;

            if (!(child->state & DENTRY_VALID)) {
                set_dirent_type(&child->type, d->type);
                child->state |= DENTRY_VALID|DENTRY_RECENTLY;
            }

            child->ino = d->ino;
        }

        free(dirent);
        dent->state |= DENTRY_LISTED;
    }

done_read:
    unlock(dcache_lock);

    struct shim_dentry ** children = NULL;

    if (dent->state & DENTRY_LISTED) {
        int nchildren = dent->nchildren, count = 0;
        struct shim_dentry * child;

        children = malloc(sizeof(struct shim_dentry *) * (nchildren + 1));

        listp_for_each_entry(child, &dent->children, siblings) {
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
    }

    qstrsetstr(&hdl->path, path, size);
    hdl->type = TYPE_DIR;
    hdl->fs = fs;
    memcpy(hdl->fs_type, fs->type, sizeof(fs->type));
    hdl->dentry = dent;
    hdl->flags = flags;

    get_dentry(dent);
    hdl->info.dir.dot = dent;

    if (dent->parent) {
        get_dentry(dent->parent);
        hdl->info.dir.dotdot = dent->parent;
    }

    hdl->info.dir.buf = children;
    hdl->info.dir.ptr = children;
out:
    return ret;
}

int path_startat (int dfd, struct shim_dentry ** dir)
{
    if (dfd == AT_FDCWD) {
        struct shim_thread * cur = get_cur_thread();
        get_dentry(cur->cwd);
        *dir = cur->cwd;
        return 0;
    } else if (dfd < 0) {
        return -EBADF;
    } else {
        struct shim_handle * hdl = get_fd_handle(dfd, NULL, NULL);
        if (!hdl)
            return -EBADF;

        if (hdl->type != TYPE_DIR) {
            put_handle(hdl);
            return -ENOTDIR;
        }

        get_dentry(hdl->dentry);
        put_handle(hdl);
        *dir = hdl->dentry;
        return 0;
    }
}
