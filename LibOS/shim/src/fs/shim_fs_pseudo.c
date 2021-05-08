/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Labs
 */

/*!
 * \file
 *
 * This file contains common code for pseudo-filesystems (e.g., /dev and /proc).
 */

#include <stdalign.h>

#include "shim_fs.h"
#include "stat.h"

/*!
 * \brief Find entry corresponding to path, starting from \p root_ent.
 *
 * Generic function for pseudo-filesystems. Example usage for the `/proc` FS is
 * `pseudo_findent("/proc/3/cwd", proc_root_ent, &cwd_ent_for_third_thread)`.
 *
 * \param[in]  path       Path to the requested entry.
 * \param[in]  root_ent   Root entry to start search from (e.g., `proc_root_ent`).
 * \param[out] found_ent  Pointer to found entry.
 * \return                0 if entry was found, negative Linux error code otherwise.
 */
static int pseudo_findent(const char* path, const struct pseudo_ent* root_ent,
                          const struct pseudo_ent** found_ent) {
    assert(path);

    size_t token_len = 0;
    const char* token = path;
    const char* next_token = NULL;
    const struct pseudo_ent* ent = root_ent;

    while (*token == '/')
        token++;

    while (token && *token) {
        char* slash_ptr = strchr(token, '/');
        if (!slash_ptr) {
            next_token = NULL;
            token_len  = strlen(token);
        } else {
            next_token = slash_ptr + 1; /* set it past '/' */
            token_len  = slash_ptr - token;
        }

        const struct pseudo_dir* dir = ent->dir;

        for (ent = dir->ent; ent < dir->ent + dir->size; ent++) {
            if (ent->name && !memcmp(ent->name, token, token_len)) {
                /* directory entry has a hardcoded name that matches current token: found ent */
                break;
            }

            if (ent->name_ops && ent->name_ops->match_name && ent->name_ops->match_name(token)) {
                /* directory entry has a calculated at runtime name (via match_name) that matches
                 * current token: found ent */
                break;
            }
        }

        if (ent == dir->ent + dir->size) {
            /* traversed all entries in directory but couldn't find entry matching the token */
            return -ENOENT;
        }

        if (!ent->dir && next_token) {
            /* still tokens left (subdirs left), but current entry doesn't have subdirs/files */
            return -ENOENT;
        }

        token = next_token;
    }

    *found_ent = ent;
    return 0;
}

/*! Generic callback to mount a pseudo-filesystem. */
int pseudo_mount(const char* uri, void** mount_data) {
    __UNUSED(uri);
    __UNUSED(mount_data);
    return 0;
}

/*! Generic callback to unmount a pseudo-filesystem. */
int pseudo_unmount(void* mount_data) {
    __UNUSED(mount_data);
    return 0;
}

/*! Generic callback to obtain mode of a directory in a pseudo-filesystem. */
int pseudo_dir_mode(const char* name, mode_t* mode) {
    __UNUSED(name);
    *mode = DIR_RX_MODE | S_IFDIR;
    return 0;
}

/*! Generic callback to obtain stat of a directory in a pseudo-filesystem. */
int pseudo_dir_stat(const char* name, struct stat* buf) {
    __UNUSED(name);
    memset(buf, 0, sizeof(*buf));

    buf->st_dev     = 1;    /* dummy ID of device containing file */
    buf->st_size    = 4096; /* dummy total size, in bytes */
    buf->st_blksize = 4096; /* dummy bulk size, in bytes */
    buf->st_mode    = DIR_RX_MODE | S_IFDIR;
    return 0;
}

/*! Generic callback to open a directory in a pseudo-filesystem. */
int pseudo_dir_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(name);

    if (flags & (O_WRONLY | O_RDWR)) {
        /* cannot write in pseudo-directory */
        return -EISDIR;
    }

    if (*name == '\0') {
        hdl->is_dir = true;
        hdl->type = TYPE_PSEUDO;
        hdl->flags = flags & ~O_ACCMODE;
        hdl->acc_mode = 0;
    }

    /* pseudo-dirs are emulated completely in LibOS, so nothing to open */
    return 0;
}

/*! Generic callback to obtain a mode of an entry in a pseudo-filesystem. */
int pseudo_mode(struct shim_dentry* dent, mode_t* mode, const struct pseudo_ent* root_ent) {
    if (!dent->parent) {
        /* root of pseudo-FS */
        return pseudo_dir_mode(/*name=*/NULL, mode);
    }

    char* rel_path;
    int ret = dentry_rel_path(dent, &rel_path, /*size=*/NULL);
    if (ret < 0)
        return ret;

    const struct pseudo_ent* ent = NULL;
    ret = pseudo_findent(rel_path, root_ent, &ent);
    if (ret < 0)
        goto out;

    if (ent->fs_ops && ent->fs_ops->mode) {
        ret = ent->fs_ops->mode(rel_path, mode);
    } else if (ent->dir) {
        ret = pseudo_dir_mode(rel_path, mode);
    } else {
        ret = -EACCES;
    }
out:
    free(rel_path);
    return ret;
}

/*! Generic callback to check if an entry exists in a pseudo-filesystem (and populate \p dent). */
int pseudo_lookup(struct shim_dentry* dent, const struct pseudo_ent* root_ent) {
    if (!dent->parent) {
        /* root of pseudo-FS */
        dent->state |= DENTRY_ISDIRECTORY;
        return 0;
    }

    char* rel_path;
    int ret = dentry_rel_path(dent, &rel_path, /*size=*/NULL);
    if (ret < 0)
        return ret;

    const struct pseudo_ent* ent = NULL;
    ret = pseudo_findent(rel_path, root_ent, &ent);
    if (ret < 0)
        goto out;

    if (ent->dir)
        dent->state |= DENTRY_ISDIRECTORY;

    if (ent->fs_ops && ent->fs_ops->follow_link)
        dent->state |= DENTRY_ISLINK;

    ret = 0;

out:
    free(rel_path);
    return ret;
}

/*! Generic callback to open an entry in a pseudo-filesystem (and populate \p hdl). */
int pseudo_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags,
                const struct pseudo_ent* root_ent) {
    char* rel_path;
    int ret = dentry_rel_path(dent, &rel_path, /*size=*/NULL);
    if (ret < 0)
        return ret;

    const struct pseudo_ent* ent = NULL;

    ret = pseudo_findent(rel_path, root_ent, &ent);
    if (ret < 0)
        goto out;

    if (!ent->fs_ops || !ent->fs_ops->open) {
        ret = -EACCES;
        goto out;
    }

    hdl->is_dir = !!ent->dir;
    /* Initialize as an empty TYPE_PSEUDO handle, fs_ops->open may override that */
    hdl->type = TYPE_PSEUDO;
    hdl->flags = flags & ~O_ACCMODE;
    hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);

    ret = ent->fs_ops->open(hdl, rel_path, flags);

out:
    free(rel_path);
    return ret;
}

/*!
 * \brief `readdir` implementation for pseudo-filesystems.
 *
 * Generic function for pseudo-filesystems. For example, if in `/proc` FS the function is called
 * with `pseudo_readdir("/proc/3", callback, arg, proc_root_ent)`, it will call `callback` on
 * "root", "cwd", "exe", "fd", etc.
 *
 * \param[in]  dent       Dentry with path to the requested directory.
 * \param[in]  callback   Callback to call on each name.
 * \param[in]  arg        Argument to pass to the callback.
 * \param[in]  root_ent   Root entry to start search from (e.g., `proc_root_ent`).
 * \return                0 on success, negative Linux error code otherwise.
 */
int pseudo_readdir(struct shim_dentry* dent, readdir_callback_t callback, void* arg,
                   const struct pseudo_ent* root_ent) {
    char* rel_path;
    int ret = dentry_rel_path(dent, &rel_path, /*size=*/NULL);
    if (ret < 0)
        return ret;

    const struct pseudo_ent* ent = NULL;

    ret = pseudo_findent(rel_path, root_ent, &ent);
    if (ret < 0)
        goto out;

    if (!ent->dir) {
        ret = -ENOTDIR;
        goto out;
    }

    const struct pseudo_dir* dir = ent->dir;
    for (const struct pseudo_ent* child = dir->ent; child < dir->ent + dir->size; child++) {
        if (child->name) {
            /* directory entry has a hardcoded name */
            ret = callback(child->name, arg);
            if (ret < 0)
                goto out;
        } else {
            /* directory entry has a list of entries calculated at runtime (via list_name) */
            ret = child->name_ops->list_name(rel_path, callback, arg);
            if (ret < 0)
                goto out;
        }
    }

out:
    free(rel_path);
    return ret;
}

/*! Generic callback to obtain stat of an entry in a pseudo-filesystem. */
int pseudo_stat(struct shim_dentry* dent, struct stat* buf, const struct pseudo_ent* root_ent) {
    if (!dent->parent) {
        /* root of pseudo-FS */
        return pseudo_dir_stat(/*name=*/NULL, buf);
    }

    char* rel_path;
    int ret = dentry_rel_path(dent, &rel_path, /*size=*/NULL);
    if (ret < 0)
        return ret;

    const struct pseudo_ent* ent = NULL;

    ret = pseudo_findent(rel_path, root_ent, &ent);
    if (ret < 0)
        goto out;

    if (!ent->fs_ops || !ent->fs_ops->stat) {
        ret = -EACCES;
        goto out;
    }

    ret = ent->fs_ops->stat(rel_path, buf);

out:
    free(rel_path);
    return ret;
}

/*! Generic callback to obtain stat of an entry in a pseudo-filesystem via its open \p hdl. */
int pseudo_hstat(struct shim_handle* hdl, struct stat* buf, const struct pseudo_ent* root_ent) {
    struct shim_dentry* dent = hdl->dentry;
    assert(dent);
    return pseudo_stat(dent, buf, root_ent);
}

/*! Generic callback to obtain a target string of a link entry in a pseudo-filesystem. */
int pseudo_follow_link(struct shim_dentry* dent, struct shim_qstr* link,
                       const struct pseudo_ent* root_ent) {
    char* rel_path;
    int ret = dentry_rel_path(dent, &rel_path, /*size=*/NULL);
    if (ret < 0)
        return ret;

    const struct pseudo_ent* ent = NULL;

    ret = pseudo_findent(rel_path, root_ent, &ent);
    if (ret < 0)
        goto out;

    if (!ent->fs_ops || !ent->fs_ops->follow_link) {
        ret = -EINVAL;
        goto out;
    }

    ret = ent->fs_ops->follow_link(rel_path, link);

out:
    free(rel_path);
    return ret;
}
