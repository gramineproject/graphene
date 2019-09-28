/* Copyright (C) 2014 Stony Brook University
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
 * shim_getpid.c
 *
 * Implementation of system call "getpid", "gettid", "getppid",
 * "set_tid_address", "getuid", "getgid", "setuid", "setgid", "geteuid",
 * "getegid", "setpgid", "getpgid", "getpgrp", "setgroups", "getgroups",
 * "setsid" and "getsid".
 */

#include <asm/prctl.h>
#include <errno.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_checkpoint.h>
#include <shim_internal.h>
#include <shim_ipc.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <sys/mman.h>
#include <sys/syscall.h>

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
    int size;
    gid_t spl_gid[NGROUPS_MAX];
} g_groups_info __attribute_migratable = {.size = -1};

int shim_do_setgroups(int gidsetsize, gid_t* grouplist) {
    if ((unsigned)gidsetsize > NGROUPS_MAX)
        return -EINVAL;

    if (gidsetsize && test_user_memory(grouplist, gidsetsize * sizeof(gid_t), true))
        return -EFAULT;

    lock(&cur_process.lock);
    g_groups_info.size = gidsetsize;
    for (int i = 0; i < gidsetsize; i++) {
        g_groups_info.spl_gid[i] = grouplist[i];
    }
    unlock(&cur_process.lock);

    return 0;
}

int shim_do_getgroups(int gidsetsize, gid_t* grouplist) {
    int cur_groups_size;

    if (gidsetsize < 0)
        return -EINVAL;

    if (gidsetsize && test_user_memory(grouplist, gidsetsize * sizeof(gid_t), true))
        return -EFAULT;

    lock(&cur_process.lock);

    if (g_groups_info.size == -1) {
        /* initialize with getgid() */
        g_groups_info.size       = 1;
        g_groups_info.spl_gid[0] = shim_do_getgid();
    }

    cur_groups_size = g_groups_info.size;
    if (gidsetsize) {
        if (cur_groups_size > gidsetsize) {
            unlock(&cur_process.lock);
            return -EINVAL;
        }

        for (int i = 0; i < cur_groups_size; i++) {
            grouplist[i] = g_groups_info.spl_gid[i];
        }
    }

    unlock(&cur_process.lock);
    return cur_groups_size;
}

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
