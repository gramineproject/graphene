/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * shim_fork.c
 *
 * Implementation of system calls "fork" and "vfork".
 */

#include "shim_fork.h"

#include <errno.h>
#include <linux/futex.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_checkpoint.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_table.h"
#include "shim_thread.h"

static BEGIN_MIGRATION_DEF(fork, struct shim_thread* thread, struct shim_process* process) {
    DEFINE_MIGRATE(process, process, sizeof(struct shim_process));
    DEFINE_MIGRATE(all_mounts, NULL, 0);
    DEFINE_MIGRATE(all_vmas, NULL, 0);
    DEFINE_MIGRATE(running_thread, thread, sizeof(struct shim_thread));
    DEFINE_MIGRATE(handle_map, thread->handle_map, sizeof(struct shim_handle_map));
    DEFINE_MIGRATE(migratable, NULL, 0);
    DEFINE_MIGRATE(brk, NULL, 0);
    DEFINE_MIGRATE(loaded_libraries, NULL, 0);
#ifdef DEBUG
    DEFINE_MIGRATE(gdb_map, NULL, 0);
#endif
}
END_MIGRATION_DEF(fork)

int migrate_fork(struct shim_cp_store* store, struct shim_thread* thread,
                 struct shim_process* process, va_list ap) {
    __UNUSED(ap);
    int ret = START_MIGRATE(store, fork, thread, process);

    thread->in_vm = false;

    if (thread->exec) {
        put_handle(thread->exec);
        thread->exec = NULL;
    }

    return ret;
}

int shim_do_fork(void) {
    int ret = 0;

    if ((ret = prepare_ns_leaders()) < 0)
        return ret;

    struct shim_thread* cur_thread = get_cur_thread();
    struct shim_thread* new_thread = get_new_thread(0);

    if (!new_thread)
        return -ENOMEM;

    new_thread->shim_tcb = cur_thread->shim_tcb;
    new_thread->tgid     = new_thread->tid;
    new_thread->in_vm    = false;
    new_thread->is_alive = true;
    add_thread(new_thread);
    set_as_child(cur_thread, new_thread);

    ret = create_process_and_send_checkpoint(&migrate_fork, /*exec=*/NULL, new_thread);
    if (ret < 0) {
        put_thread(new_thread);
        return ret;
    }

    lock(&new_thread->lock);
    struct shim_handle_map* handle_map = new_thread->handle_map;
    new_thread->handle_map             = NULL;
    new_thread->shim_tcb               = NULL;
    unlock(&new_thread->lock);
    if (handle_map)
        put_handle_map(handle_map);

    IDTYPE tid = new_thread->tid;
    put_thread(new_thread);
    return tid;
}

/* Instead of trying to support Linux semantics for vfork() -- which requires adding corner-cases in
 * signal handling and syscalls -- we simply treat vfork() as fork(). We assume that performance hit
 * is negligible (Graphene has to migrate internal state anyway which is slow) and apps do not rely
 * on insane Linux-specific semantics of vfork().  */
int shim_do_vfork(void) {
    debug("vfork() was called by the application, implemented as alias to fork() in Graphene\n");
    return shim_do_fork();
}
