/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

#ifndef SHIM_FS_PSEUDO_H_
#define SHIM_FS_PSEUDO_H_

#include "perm.h"
#include "list.h"
#include "shim_fs.h"

enum pseudo_type {
    PSEUDO_DIR = 1,
    PSEUDO_LINK = 2,
    PSEUDO_STR = 3,
    PSEUDO_DEV = 4,
};

#define PSEUDO_MODE_DIR     PERM_r_xr_xr_x
#define PSEUDO_MODE_FILE_R  PERM_r__r__r__
#define PSEUDO_MODE_FILE_RW PERM_rw_rw_rw_
#define PSEUDO_MODE_LINK    PERM_rwxrwxrwx

DEFINE_LIST(pseudo2_ent);
DEFINE_LISTP(pseudo2_ent);
struct pseudo2_ent {
    struct pseudo2_ent* parent;

    const char* name;
    int (*match_name)(struct shim_dentry* parent, const char* name);
    int (*list_names)(struct shim_dentry* parent, readdir_callback_t callback, void* arg);

    enum pseudo_type type;

    mode_t perm;

    LIST_TYPE(pseudo2_ent) siblings;

    union {
        struct {
            LISTP_TYPE(pseudo2_ent) children;
        } dir;

        struct {
            int (*follow_link)(struct shim_dentry* dent, struct shim_qstr* link);
            const char* target;
        } link;

        struct {
            int (*get_content)(struct shim_dentry* dent, char** content, size_t* size);
        } str;

        struct {
            struct shim_dev_ops dev_ops;
            unsigned int major;
            unsigned int minor;
        } dev;
    };
};

struct pseudo2_ent* pseudo_add_root_dir(const char* name);

struct pseudo2_ent* pseudo_add_dir(struct pseudo2_ent* parent_ent, const char* name);

struct pseudo2_ent* pseudo_add_link(struct pseudo2_ent* parent_ent, const char* name,
                                    int (*follow_link)(struct shim_dentry*, struct shim_qstr*));

struct pseudo2_ent* pseudo_add_str(struct pseudo2_ent* parent_ent, const char* name,
                                   int (*get_content)(struct shim_dentry*, char**, size_t*));

struct pseudo2_ent* pseudo_add_dev(struct pseudo2_ent* parent_ent, const char* name);

extern struct shim_fs pseudo_builtin_fs;

/* procfs */

int init_procfs(void);
int proc_meminfo_get_content(struct shim_dentry* dent, char** content, size_t* size);
int proc_cpuinfo_get_content(struct shim_dentry* dent, char** content, size_t* size);
int proc_self_follow_link(struct shim_dentry* dent, struct shim_qstr* link);
int proc_thread_pid_match_name(struct shim_dentry* parent, const char* name);
int proc_thread_pid_list_names(struct shim_dentry* parent, readdir_callback_t callback, void* arg);
int proc_thread_tid_match_name(struct shim_dentry* parent, const char* name);
int proc_thread_tid_list_names(struct shim_dentry* parent, readdir_callback_t callback, void* arg);
int proc_thread_follow_link(struct shim_dentry* dent, struct shim_qstr* link);
int proc_thread_maps_get_content(struct shim_dentry* dent, char** content, size_t* size);
int proc_thread_cmdline_get_content(struct shim_dentry* dent, char** content, size_t* size);
int proc_thread_fd_match_name(struct shim_dentry* parent, const char* name);
int proc_thread_fd_list_names(struct shim_dentry* parent, readdir_callback_t callback, void* arg);
int proc_thread_fd_follow_link(struct shim_dentry* dent, struct shim_qstr* link);
int proc_ipc_thread_pid_match_name(struct shim_dentry* parent, const char* name);
int proc_ipc_thread_pid_list_names(struct shim_dentry* parent, readdir_callback_t callback, void* arg);
int proc_ipc_thread_follow_link(struct shim_dentry* dent, struct shim_qstr* link);

/* devfs */

int init_devfs(void);
ssize_t dev_null_read(struct shim_handle* hdl, void* buf, size_t count);
ssize_t dev_null_write(struct shim_handle* hdl, const void* buf, size_t count);
off_t dev_null_seek(struct shim_handle* hdl, off_t offset, int whence);
int dev_null_truncate(struct shim_handle* hdl, uint64_t size);
ssize_t dev_zero_read(struct shim_handle* hdl, void* buf, size_t count);
ssize_t dev_random_read(struct shim_handle* hdl, void* buf, size_t count);

/* sysfs */

int init_sysfs(void);
int sys_get_content(const char* str, char** content, size_t* size);
int sys_resource_find(struct shim_dentry* parent, const char* name);
int sys_resource_match_name(struct shim_dentry* parent, const char* name);
int sys_resource_list_names(struct shim_dentry* parent, readdir_callback_t callback, void* arg);
int sys_node_general_get_content(struct shim_dentry* dent, char** content, size_t* size);
int sys_node_get_content(struct shim_dentry* dent, char** content, size_t* size);
int sys_cpu_general_get_content(struct shim_dentry* dent, char** content, size_t* size);
int sys_cpu_get_content(struct shim_dentry* dent, char** content, size_t* size);
int sys_cache_get_content(struct shim_dentry* dent, char** content, size_t* size);
int sys_cpu_online_match_name(struct shim_dentry* parent, const char* name);
int sys_cpu_online_list_names(struct shim_dentry* parent, readdir_callback_t callback, void* arg);

#endif /* SHIM_FS_PSEUDO_H_ */
