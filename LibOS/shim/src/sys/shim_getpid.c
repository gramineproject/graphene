/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system calls "getpid", "gettid", "getppid", "set_tid_address", "getuid",
 * "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", "getpgid", "getpgrp", "setgroups",
 * "getgroups", "setsid" and "getsid".
 */

#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_checkpoint.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_table.h"
#include "shim_thread.h"

pid_t shim_do_getpid(void) {
    struct shim_thread* cur = get_cur_thread();
    return cur ? cur->tgid : 0;
}

pid_t shim_do_gettid(void) {
    struct shim_thread* cur = get_cur_thread();
    return cur ? cur->tid : 0;
}

pid_t shim_do_getppid(void) {
    struct shim_thread* cur = get_cur_thread();
    return cur ? (cur->parent ? cur->parent->tid : cur->ppid) : 0;
}

int shim_do_set_tid_address(int* tidptr) {
    /* http://man7.org/linux/man-pages/man2/set_tid_address.2.html */
    struct shim_thread* cur = get_cur_thread();
    cur->clear_child_tid    = tidptr;
    return cur->tid;
}

uid_t shim_do_getuid(void) {
    struct shim_thread* cur = get_cur_thread();
    return cur ? cur->uid : 0;
}

gid_t shim_do_getgid(void) {
    struct shim_thread* cur = get_cur_thread();
    return cur ? cur->gid : 0;
}

int shim_do_setuid(uid_t uid) {
    struct shim_thread* cur = get_cur_thread();
    cur->euid               = (uint16_t)uid;
    return 0;
}

int shim_do_setgid(gid_t gid) {
    struct shim_thread* cur = get_cur_thread();
    cur->egid               = (uint16_t)gid;
    return 0;
}

/* shim_do_set{get}groups() do not propagate group info to host OS but rather are dummies */
#define NGROUPS_MAX 65536 /* # of supplemental group IDs; has to be same as host OS */

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

uid_t shim_do_geteuid(void) {
    struct shim_thread* cur = get_cur_thread();
    return cur ? cur->euid : 0;
}

gid_t shim_do_getegid(void) {
    struct shim_thread* cur = get_cur_thread();
    return cur ? cur->egid : 0;
}

int shim_do_setpgid(pid_t pid, pid_t pgid) {
    struct shim_thread* thread;

    if (pid) {
        thread = lookup_thread(pid);
        if (!thread) {
            return -ESRCH;
        }
    } else {
        thread = get_cur_thread();
        get_thread(thread);
    }

    thread->pgid = (IDTYPE)pgid ?: thread->tgid;

    put_thread(thread);
    return 0;
}

int shim_do_getpgid(pid_t pid) {
    if (!pid) {
        return get_cur_thread()->pgid;
    }

    struct shim_thread* thread = lookup_thread(pid);

    if (!thread) {
        return -ESRCH;
    }

    int ret = thread->pgid;
    put_thread(thread);
    return ret;
}

pid_t shim_do_getpgrp(void) {
    struct shim_thread* cur_thread = get_cur_thread();
    assert(cur_thread);
    return cur_thread->pgid;
}

int shim_do_setsid(void) {
    struct shim_thread* cur_thread = get_cur_thread();
    assert(cur_thread);

    if (cur_thread->pgid == cur_thread->tgid)
        return -EPERM;

    cur_thread->pgid = cur_thread->tgid;

    /* TODO: the calling process may haveto be detached from the
       tty, but there is no need to handle it for now. */
    return 0;
}

int shim_do_getsid(pid_t pid) {
    return shim_do_getpgid(pid);
}
