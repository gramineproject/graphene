/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "api.h"
#include "shim_checkpoint.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_table.h"
#include "shim_thread.h"
#include "shim_types.h"

uid_t shim_do_getuid(void) {
    struct shim_thread* current = get_cur_thread();
    lock(&current->lock);
    uid_t uid = current->uid;
    unlock(&current->lock);
    return uid;
}

gid_t shim_do_getgid(void) {
    struct shim_thread* current = get_cur_thread();
    lock(&current->lock);
    gid_t gid = current->gid;
    unlock(&current->lock);
    return gid;
}

uid_t shim_do_geteuid(void) {
    struct shim_thread* current = get_cur_thread();
    lock(&current->lock);
    uid_t euid = current->euid;
    unlock(&current->lock);
    return euid;
}

gid_t shim_do_getegid(void) {
    struct shim_thread* current = get_cur_thread();
    lock(&current->lock);
    gid_t egid = current->egid;
    unlock(&current->lock);
    return egid;
}

int shim_do_setuid(uid_t uid) {
    struct shim_thread* current = get_cur_thread();
    lock(&current->lock);
    current->euid = uid;
    unlock(&current->lock);
    return 0;
}

int shim_do_setgid(gid_t gid) {
    struct shim_thread* current = get_cur_thread();
    lock(&current->lock);
    current->egid = gid;
    unlock(&current->lock);
    return 0;
}

#define NGROUPS_MAX 65536 /* # of supplemental group IDs; has to be same as host OS */

/* TODO: group IDs should be thread based, not global. */
static struct groups_info_t {
    size_t count;
    gid_t* groups;
} g_groups_info = { .count = 0, .groups = NULL };

int shim_do_setgroups(int gidsetsize, gid_t* grouplist) {
    if (gidsetsize < 0 || (unsigned int)gidsetsize > NGROUPS_MAX)
        return -EINVAL;

    if (gidsetsize && test_user_memory(grouplist, gidsetsize * sizeof(gid_t), /*write=*/false))
        return -EFAULT;

    size_t groups_len = (size_t)gidsetsize;
    gid_t* groups = (gid_t*)malloc(groups_len * sizeof(*groups));
    if (!groups) {
        return -ENOMEM;
    }
    for (size_t i = 0; i < groups_len; i++) {
        groups[i] = grouplist[i];
    }

    void* old_groups = NULL;
    lock(&g_process_ipc_info.lock);
    g_groups_info.count = groups_len;
    old_groups = g_groups_info.groups;
    g_groups_info.groups = groups;
    unlock(&g_process_ipc_info.lock);

    free(old_groups);

    return 0;
}

int shim_do_getgroups(int gidsetsize, gid_t* grouplist) {
    if (gidsetsize < 0)
        return -EINVAL;

    if (gidsetsize && test_user_memory(grouplist, gidsetsize * sizeof(gid_t), /*write=*/true))
        return -EFAULT;

    lock(&g_process_ipc_info.lock);
    size_t ret_size = g_groups_info.count;

    if (gidsetsize) {
        if (ret_size > (size_t)gidsetsize) {
            unlock(&g_process_ipc_info.lock);
            return -EINVAL;
        }

        for (size_t i = 0; i < g_groups_info.count; i++) {
            grouplist[i] = g_groups_info.groups[i];
        }
    }

    unlock(&g_process_ipc_info.lock);

    return (int)ret_size;
}

BEGIN_CP_FUNC(groups_info) {
    __UNUSED(size);
    __UNUSED(objp);
    __UNUSED(obj);

    lock(&g_process_ipc_info.lock);

    size_t copy_size = g_groups_info.count * sizeof(*g_groups_info.groups);

    size_t off = ADD_CP_OFFSET(sizeof(size_t) + copy_size);

    *(size_t*)((char*)base + off) = g_groups_info.count;
    gid_t* new_groups = (gid_t*)((char*)base + off + sizeof(size_t));

    memcpy(new_groups, g_groups_info.groups, copy_size);

    unlock(&g_process_ipc_info.lock);

    ADD_CP_FUNC_ENTRY(off);
}
END_CP_FUNC(groups_info)

BEGIN_RS_FUNC(groups_info) {
    __UNUSED(offset);
    __UNUSED(rebase);
    size_t off = GET_CP_FUNC_ENTRY();
    g_groups_info.count = *(size_t*)((char*)base + off);
    g_groups_info.groups = (gid_t*)((char*)base + off + sizeof(size_t));
}
END_RS_FUNC(groups_info)
