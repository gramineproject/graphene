/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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
 * "getegid", "setpgid", "getpgid", "getpgrp", "setsid" and "getsid".
 */

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>

#include <pal.h>
#include <pal_error.h>

#include <sys/syscall.h>
#include <sys/mman.h>
#include <asm/prctl.h>
#include <errno.h>

pid_t shim_do_getpid (void)
{
    struct shim_thread * cur = get_cur_thread();
    return cur ? cur->tgid : 0;
}

pid_t shim_do_gettid (void)
{
    struct shim_thread * cur = get_cur_thread();
    return cur ? cur->tid : 0;
}

pid_t shim_do_getppid (void)
{
    struct shim_thread * cur = get_cur_thread();
    return cur ? (cur->parent ? cur->parent->tid : cur->ppid) : 0;
}

int shim_do_set_tid_address (int * tidptr)
{
    struct shim_thread * cur = get_cur_thread();
    cur->set_child_tid = tidptr;
    return cur->tid;
}

uid_t shim_do_getuid (void)
{
    struct shim_thread * cur = get_cur_thread();
    return cur ? cur->uid : 0;
}

gid_t shim_do_getgid (void)
{
    struct shim_thread * cur = get_cur_thread();
    return cur ? cur->gid : 0;
}

int shim_do_setuid (uid_t uid)
{
    struct shim_thread * cur = get_cur_thread();
    cur->euid = (uint16_t) uid;
    return 0;
}

int shim_do_setgid (gid_t gid)
{
    struct shim_thread * cur = get_cur_thread();
    cur->egid = (uint16_t) gid;
    return 0;
}

uid_t shim_do_geteuid (void)
{
    struct shim_thread * cur = get_cur_thread();
    return cur ? cur->euid : 0;
}

gid_t shim_do_getegid (void)
{
    struct shim_thread * cur = get_cur_thread();
    return cur ? cur->egid : 0;
}

int shim_do_setpgid (pid_t pid, pid_t pgid)
{
    struct shim_thread * thread =
            pid ? lookup_thread(pid) : get_cur_thread();

    if (!pid)
        assert(thread);

    if (!thread)
        return -ESRCH;

    thread->pgid = pgid ? : thread->tgid;

    return 0;
}

int shim_do_getpgid (pid_t pid)
{
    struct shim_thread * thread =
            pid ? lookup_thread(pid) : get_cur_thread();

    if (!thread)
        return -ESRCH;

    return thread->pgid;
}

pid_t shim_do_getpgrp (void)
{
    struct shim_thread * cur_thread = get_cur_thread();
    assert(cur_thread);
    return cur_thread->pgid;
}

int shim_do_setsid (void)
{
    struct shim_thread * cur_thread = get_cur_thread();
    assert(cur_thread);

    if (cur_thread->pgid == cur_thread->tgid)
        return -EPERM;

    cur_thread->pgid = cur_thread->tgid;

    /* TODO: the calling process may haveto be detached from the
       tty, but there is no need to handle it for now. */
    return 0;
}

int shim_do_getsid (pid_t pid)
{
    struct shim_thread * thread =
            pid ? lookup_thread(pid) : get_cur_thread();

    if (!thread)
        return -ESRCH;

    return thread->pgid;
}
