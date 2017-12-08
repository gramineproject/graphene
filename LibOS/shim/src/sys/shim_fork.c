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
 * shim_fork.c
 *
 * Implementation of system call "fork".
 */

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_ipc.h>
#include <shim_profile.h>
#include <shim_checkpoint.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <asm/prctl.h>
#include <linux/futex.h>

int migrate_fork (struct shim_cp_store * store,
                  struct shim_thread * thread,
                  struct shim_process * process, va_list ap)
{
    BEGIN_MIGRATION_DEF(fork, struct shim_thread * thread,
                        struct shim_process * process)
    {
        DEFINE_MIGRATE(process, process, sizeof(struct shim_process));
        DEFINE_MIGRATE(all_mounts, NULL, 0);
        DEFINE_MIGRATE(all_vmas, NULL, 0);
        DEFINE_MIGRATE(running_thread, thread, sizeof(struct shim_thread));
        DEFINE_MIGRATE(handle_map, thread->handle_map,
                       sizeof (struct shim_handle_map));
        DEFINE_MIGRATE(brk, NULL, 0);
        DEFINE_MIGRATE(loaded_libraries, NULL, 0);
#ifdef DEBUG
        DEFINE_MIGRATE(gdb_map, NULL, 0);
#endif
        DEFINE_MIGRATE(migratable, NULL, 0);
    }
    END_MIGRATION_DEF(fork)

    int ret = START_MIGRATE(store, fork, thread, process);

    thread->in_vm = false;

    if (thread->exec) {
        put_handle(thread->exec);
        thread->exec = NULL;
    }

    return ret;
}

int shim_do_fork (void)
{
    int ret = 0;
    INC_PROFILE_OCCURENCE(syscall_use_ipc);

    if ((ret = prepare_ns_leaders()) < 0)
        return ret;

    struct shim_thread * cur_thread = get_cur_thread();
    struct shim_thread * new_thread = get_new_thread(0);

    if (!new_thread)
        return -ENOMEM;

    new_thread->tcb      = cur_thread->tcb;
    new_thread->user_tcb = cur_thread->user_tcb;
    new_thread->tgid     = new_thread->tid;
    new_thread->in_vm    = false;
    new_thread->is_alive = true;
    add_thread(new_thread);
    set_as_child(cur_thread, new_thread);

    if ((ret = do_migrate_process(&migrate_fork, NULL, NULL, new_thread)) < 0) {
        put_thread(new_thread);
        return ret;
    }

    lock(new_thread->lock);
    struct shim_handle_map * handle_map = new_thread->handle_map;
    new_thread->handle_map = NULL;
    unlock(new_thread->lock);
    if (handle_map)
        put_handle_map(handle_map);

    IDTYPE tid = new_thread->tid;
    put_thread(new_thread);
    return tid;
}
