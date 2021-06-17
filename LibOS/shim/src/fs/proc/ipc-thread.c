/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Implementation of `/proc/<remote-pid>`. Currently supports only `root`, `cwd` and `exe` symlinks,
 * and does not do any caching.
 */

#include "shim_fs.h"
#include "shim_fs_pseudo.h"
#include "shim_ipc.h"

int proc_ipc_thread_pid_match_name(struct shim_dentry* parent, const char* name) {
    __UNUSED(parent);

    unsigned long pid;
    const char* end;
    if (str_to_ulong(name, 10, &pid, &end) < 0 || *end != '\0' || pid > IDTYPE_MAX)
        return -ENOENT;

    int ret;

    struct pid_status* status;
    ret = get_all_pid_status(&status);
    if (ret < 0)
        return ret;

    size_t status_num = ret;
    bool found = false;
    for (size_t i = 0; i < status_num; i++)
        if (status[i].pid == status[i].tgid && status[i].pid == pid) {
            found = true;
            break;
        }

    free(status);
    if (!found)
        return -ENOENT;

    return 0;
}

int proc_ipc_thread_pid_list_names(struct shim_dentry* parent, readdir_callback_t callback,
                                   void* arg) {
    __UNUSED(parent);

    int ret;

    struct pid_status* status;
    ret = get_all_pid_status(&status);
    if (ret < 0)
        return ret;

    size_t status_num = ret;
    for (size_t i = 0; i < status_num; i++)
        if (status[i].pid == status[i].tgid) {
            char name[11];
            snprintf(name, sizeof(name), "%u", status[i].pid);
            ret = callback(name, arg);
            if (ret < 0)
                goto out;
        }

    ret = 0;
out:
    free(status);
    return ret;
}

int proc_ipc_thread_follow_link(struct shim_dentry* dent, char** target) {
    assert(dent->parent);
    const char* parent_name = qstrgetstr(&dent->parent->name);
    const char* name = qstrgetstr(&dent->name);

    unsigned long pid;
    const char* end;
    if (str_to_ulong(parent_name, 10, &pid, &end) < 0 || *end != '\0' || pid > IDTYPE_MAX)
        return -ENOENT;

    enum pid_meta_code ipc_code;
    if (strcmp(name, "root") == 0) {
        ipc_code = PID_META_ROOT;
    } else if (strcmp(name, "cwd") == 0) {
        ipc_code = PID_META_CWD;
    } else if (strcmp(name, "exe") == 0) {
        ipc_code = PID_META_EXEC;
    } else {
        return -ENOENT;
    }

    struct shim_ipc_pid_retmeta* ipc_data;
    int ret = ipc_pid_getmeta(pid, ipc_code, &ipc_data);
    if (ret < 0)
        return ret;

    *target = strdup(ipc_data->data);
    if (!target) {
        ret = -ENOMEM;
        goto out;
    }
    ret = 0;
out:
    free(ipc_data);
    return ret;
}
