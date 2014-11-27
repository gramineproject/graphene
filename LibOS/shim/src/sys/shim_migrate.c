/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_migrate.c
 *
 * Implementation of system call "checkpoint" and "restore".
 */

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_vma.h>
#include <shim_fs.h>
#include <shim_ipc.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>
#include <fcntl.h>
#include <asm/mman.h>

#define malloc_method(size)     malloc_method_file(size)
#include <shim_checkpoint.h>

LIST_HEAD(created_sessions);

struct cpsession {
    IDTYPE                  session;
    struct shim_handle *    cpfile;
    struct list_head        registered_threads;
    struct list_head        list;
    PAL_HANDLE              finish_event;
};

struct cpthread {
    struct shim_thread *    thread;
    struct list_head        list;
};

static struct cpsession * current_cpsession = NULL;

int create_checkpoint (const char * cpdir, IDTYPE * session)
{
    struct cpsession * cpsession = malloc(sizeof(struct cpsession));
    if (!cpsession)
        return -ENOMEM;

    int ret = 0;

    INIT_LIST_HEAD(&cpsession->registered_threads);
    INIT_LIST_HEAD(&cpsession->list);
    cpsession->finish_event = DkNotificationEventCreate(0);
    cpsession->cpfile = NULL;

    int len = strlen(cpdir);
    char * filename = __alloca(len + 10);
    memcpy(filename, cpdir, len);
    filename[len] = '/';
    snprintf(filename + len + 1, 9, "%08x", cur_process.vmid);

    cpsession->cpfile = get_new_handle();
    if (!cpsession->cpfile) {
        ret = -ENOMEM;
        goto err;
    }

    /* the directory might not be created. At least try to create it */
    if ((ret = open_namei(NULL, NULL, cpdir, O_CREAT|O_DIRECTORY, 0700,
                          NULL)) < 0
        && ret != -EEXIST)
        goto err;

    if ((ret = open_namei(cpsession->cpfile, NULL, filename,
                          O_CREAT|O_EXCL|O_RDWR, 0600, NULL)) < 0)
        goto err;

    open_handle(cpsession->cpfile);

    master_lock();

    if (*session) {
        struct cpsession * cps;
        list_for_each_entry(cps, &created_sessions, list)
            if (cps->session == *session) {
                ret = 0;
                goto err_locked;
            }
    } else {
        struct cpsession * cps;
retry:
        getrand(session, sizeof(IDTYPE));
        list_for_each_entry(cps, &created_sessions, list)
            if (cps->session == *session)
                goto retry;
    }

    list_add_tail(&cpsession->list, &created_sessions);

    if (!current_cpsession)
        current_cpsession = cpsession;

    master_unlock();
    return 0;

err_locked:
    master_unlock();
err:
    if (cpsession->cpfile)
        close_handle(cpsession->cpfile);

    DkObjectClose(cpsession->finish_event);
    free(cpsession);
    return ret;
}

static int finish_checkpoint (void);

static int check_thread (struct shim_thread * thread, void * arg,
                         bool * unlocked)
{
    struct list_head * registered = (struct list_head *) arg;
    struct cpthread * cpt;

    if (!thread->in_vm || !thread->is_alive)
        return 0;

    list_for_each_entry(cpt, registered, list)
        if (cpt->thread == thread)
            return 0;

    return 1;
}

int join_checkpoint (struct shim_thread * cur, ucontext_t * context)
{
    struct cpthread cpt;
    int ret = 0;
    bool do_checkpoint = false;

    master_lock();

    if (!current_cpsession) {
        master_unlock();
        return -EINVAL;
    }

    INIT_LIST_HEAD(&cpt.list);
    cpt.thread = cur;
    list_add_tail(&cpt.list, &current_cpsession->registered_threads);

    /* find out if there is any thread that is not registered yet */
    ret = walk_thread_list(&check_thread,
                           &current_cpsession->registered_threads,
                           false);

    if (ret == -ESRCH)
        do_checkpoint = true;

    PAL_HANDLE finish_event = current_cpsession->finish_event;
    master_unlock();

    if (!do_checkpoint) {
        debug("waiting for checkpointing\n");
        DkObjectsWaitAny(1, &finish_event, NO_TIMEOUT);
        return 0;
    }

    debug("ready for checkpointing\n");

    ret = finish_checkpoint();
    if (ret < 0)
        debug("failed creating checkpoint: %e\n", -ret);
    else
        debug("finish checkpointing, time to wake up all threads\n");

    DkEventSet(finish_event);
    return ret;
}

void * malloc_method_file (size_t size)
{
    struct shim_handle * cpfile;

    master_lock();
    if (!current_cpsession || !current_cpsession->cpfile) {
        master_unlock();
        return NULL;
    }
    cpfile = current_cpsession->cpfile;
    get_handle(cpfile);
    master_unlock();

    struct shim_mount * fs = cpfile->fs;

    if (!fs || !fs->fs_ops ||
        !fs->fs_ops->truncate || !fs->fs_ops->mmap)
        return NULL;

    if (fs->fs_ops->truncate(cpfile, size) < 0)
        return NULL;

    void * addr = NULL;
    void * mem = fs->fs_ops->mmap(cpfile, &addr, ALIGN_UP(size),
                            PROT_READ|PROT_WRITE,
                            MAP_FILE|MAP_SHARED, 0) < 0 ? NULL : addr;

    put_handle(cpfile);
    return mem;
}

static int finish_checkpoint (void)
{
    struct shim_cp_store cpstore;

again:
    INIT_CP_STORE(&cpstore);

    BEGIN_MIGRATION_DEF(checkpoint)
    {
        store->use_gipc = false;
        DEFINE_MIGRATE(process, &cur_process, sizeof(struct shim_process),
                       false);
        DEFINE_MIGRATE(all_mounts, NULL, 0, false);
        DEFINE_MIGRATE(all_vmas, NULL, 0, true);
        DEFINE_MIGRATE(all_running_threads, NULL, 0, true);
        DEFINE_MIGRATE(brk, NULL, 0, false);
        DEFINE_MIGRATE(loaded_libraries, NULL, 0, false);
        DEFINE_MIGRATE(gdb_map, NULL, 0, false);
        DEFINE_MIGRATE(migratable, NULL, 0, false);
    }
    END_MIGRATION_DEF

    int ret = START_MIGRATE(&cpstore, checkpoint, sizeof(struct cp_header));

    if (ret < 0)
        return ret;

    struct shim_cp_entry * cpent = cpstore.cpdata;
    for ( ; cpent->cp_type != CP_NULL ; cpent++)
        if (cpent->cp_type == CP_PALHDL &&
            cpent->cp_un.cp_val) {
            PAL_HANDLE * pal_hdl = cpstore.cpdata + cpent->cp_un.cp_val;
            assert(*pal_hdl);
            *pal_hdl = NULL;
        }

    struct cp_header * hdr = (struct cp_header *) cpstore.cpaddr;
    hdr->cpaddr = cpstore.cpaddr;
    hdr->cpsize = cpstore.cpsize;
    hdr->cpoffset = cpstore.cpdata - cpstore.cpaddr;

    DkStreamUnmap(cpstore.cpaddr, cpstore.cpsize);

    master_lock();
    assert(current_cpsession);
    struct shim_handle * cpfile = current_cpsession->cpfile;
    bool do_again = false;
    current_cpsession->cpfile = NULL;
    if (current_cpsession->list.next != &created_sessions) {
        current_cpsession = list_entry(current_cpsession->list.next,
                                       struct cpsession, list);
        do_again = true;
    } else {
        current_cpsession = NULL;
    }
    master_unlock();

    close_handle(cpfile);

    if (do_again)
        goto again;

    return 0;
}

int shim_do_checkpoint (const char * filename)
{
    IDTYPE session = 0;
    int ret = 0;

    ret = shim_do_mkdir(filename, 0700);
    if (ret < 0)
        return ret;

    shim_tcb_t * tcb = SHIM_GET_TLS();
    assert(tcb && tcb->tp);
    struct shim_signal signal;
    __store_context(tcb, NULL, &signal);

    ret = create_checkpoint(filename, &session);
    if (ret < 0) {
        shim_do_rmdir(filename);
        return ret;
    }

    ipc_checkpoint_send(filename, session);
    kill_all_threads(tcb->tp, CHECKPOINT_REQUESTED, SIGINT);

    ret = join_checkpoint(tcb->tp, &signal.context);
    if (ret < 0) {
        shim_do_rmdir(filename);
        return ret;
    }

    return 0;
}
