/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*!
 * \file
 *
 * This file contains the implementation of `/proc` pseudo-filesystem.
 */

#include "shim_fs.h"
#include "shim_fs_pseudo.h"
#include "shim_thread.h"

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

static int proc_readdir(struct shim_dentry* dent, readdir_callback_t callback, void* arg) {
    return pseudo_readdir(dent, callback, arg, &proc_root_ent);
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

static int proc_close(struct shim_handle* hdl) {
    if (hdl->type == TYPE_PSEUDO) {
        /* e.g. a directory */
        return 0;
    }
    assert(hdl->type == TYPE_STR);
    return str_close(hdl);
}

struct shim_fs_ops proc_fs_ops = {
    .mount   = &pseudo_mount,
    .unmount = &pseudo_unmount,
    .close   = &proc_close,
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

struct shim_fs proc_builtin_fs = {
    .name   = "proc",
    .fs_ops = &proc_fs_ops,
    .d_ops  = &proc_d_ops,
};

int proc_self_follow_link(struct shim_dentry* dent, struct shim_qstr* link) {
    __UNUSED(dent);
    IDTYPE pid = get_cur_tid();
    char str[11];
    snprintf(str, sizeof(str), "%u", pid);
    if (!qstrsetstr(link, str, strlen(str)))
        return -ENOMEM;
    return 0;
}

static void init_thread_dir(struct pseudo2_ent* ent) {
    ent->match_name = proc_thread_match_name;
    ent->list_names = proc_thread_list_names;

    pseudo_add_link(ent, "root", proc_thread_follow_link);
    pseudo_add_link(ent, "cwd", proc_thread_follow_link);
    pseudo_add_link(ent, "exe", proc_thread_follow_link);
    pseudo_add_str(ent, "maps", proc_thread_maps_get_content);
    pseudo_add_str(ent, "cmdline", proc_thread_cmdline_get_content);

    struct pseudo2_ent* fd = pseudo_add_dir(ent, "fd");
    struct pseudo2_ent* fd_link = pseudo_add_link(fd, NULL, &proc_thread_fd_follow_link);
    fd_link->match_name = proc_thread_fd_match_name;
    fd_link->list_names = proc_thread_fd_list_names;
}

int init_procfs(void) {
    struct pseudo2_ent* root = pseudo_add_root_dir("proc");

    pseudo_add_link(root, "self", &proc_self_follow_link);

    struct pseudo2_ent* thread_pid = pseudo_add_dir(root, NULL);
    init_thread_dir(thread_pid);

    struct pseudo2_ent* thread_task = pseudo_add_dir(thread_pid, "task");
    struct pseudo2_ent* thread_tid = pseudo_add_dir(thread_task, NULL);
    init_thread_dir(thread_tid);

    return 0;
}
