/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*!
 * \file
 *
 * This file contains the implementation of `/proc` pseudo-filesystem.
 */

#include "shim_fs.h"

extern const struct pseudo_name_ops nm_thread;
extern const struct pseudo_fs_ops fs_thread;
extern const struct pseudo_dir dir_thread;

extern const struct pseudo_name_ops nm_ipc_thread;
extern const struct pseudo_fs_ops fs_ipc_thread;
extern const struct pseudo_dir dir_ipc_thread;

extern const struct pseudo_fs_ops fs_meminfo;

extern const struct pseudo_fs_ops fs_cpuinfo;

static const struct pseudo_dir proc_root_dir = {
    .size = 5,
    .ent  = {
        {.name     = "self",
         .fs_ops   = &fs_thread,
         .dir      = &dir_thread},
        {.name_ops = &nm_thread,
         .fs_ops   = &fs_thread,
         .dir      = &dir_thread},
        {.name_ops = &nm_ipc_thread,
         .fs_ops   = &fs_ipc_thread,
         .dir      = &dir_ipc_thread},
        {.name     = "meminfo",
         .fs_ops   = &fs_meminfo,
         .type     = LINUX_DT_REG},
        {.name     = "cpuinfo",
         .fs_ops   = &fs_cpuinfo,
         .type     = LINUX_DT_REG},
    }};

static const struct pseudo_fs_ops proc_root_fs = {
    .open = &pseudo_dir_open,
    .mode = &pseudo_dir_mode,
    .stat = &pseudo_dir_stat,
};

static const struct pseudo_ent proc_root_ent = {
    .name   = "",
    .fs_ops = &proc_root_fs,
    .dir    = &proc_root_dir,
};

static int proc_mode(struct shim_dentry* dent, mode_t* mode) {
    return pseudo_mode(dent, mode, &proc_root_ent);
}

static int proc_lookup(struct shim_dentry* dent) {
    return pseudo_lookup(dent, &proc_root_ent);
}

static int proc_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags) {
    return pseudo_open(hdl, dent, flags, &proc_root_ent);
}

static int proc_readdir(struct shim_dentry* dent, struct shim_dirent** dirent) {
    return pseudo_readdir(dent, dirent, &proc_root_ent);
}

static int proc_stat(struct shim_dentry* dent, struct stat* buf) {
    return pseudo_stat(dent, buf, &proc_root_ent);
}

static int proc_hstat(struct shim_handle* hdl, struct stat* buf) {
    return pseudo_hstat(hdl, buf, &proc_root_ent);
}

static int proc_follow_link(struct shim_dentry* dent, struct shim_qstr* link) {
    return pseudo_follow_link(dent, link, &proc_root_ent);
}

struct shim_fs_ops proc_fs_ops = {
    .mount   = &pseudo_mount,
    .unmount = &pseudo_unmount,
    .close   = &str_close,
    .read    = &str_read,
    .write   = &str_write,
    .seek    = &str_seek,
    .flush   = &str_flush,
    .hstat   = &proc_hstat,
};

struct shim_d_ops proc_d_ops = {
    .open        = &proc_open,
    .stat        = &proc_stat,
    .mode        = &proc_mode,
    .lookup      = &proc_lookup,
    .follow_link = &proc_follow_link,
    .readdir     = &proc_readdir,
};
