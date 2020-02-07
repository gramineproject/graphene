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
 * shim_migrate.c
 *
 * Implementation of system call "checkpoint" and "restore".
 */

#include <asm/mman.h>
#include <errno.h>
#include <linux/fcntl.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_checkpoint.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_ipc.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_vma.h>

/* cp_session objects are on the cp_sessions list, by the list field */
/* cp_threads are organized onto a list, handing off of the
 * cp_session->registered_threads list. */

DEFINE_LIST(cp_thread);
struct cp_thread {
    struct shim_thread* thread;
    LIST_TYPE(cp_thread) list;
};

DEFINE_LIST(cp_session);
DEFINE_LISTP(cp_thread);
struct cp_session {
    IDTYPE sid;
    struct shim_handle* cpfile;
    LISTP_TYPE(cp_thread) registered_threads;
    LIST_TYPE(cp_session) list;
    PAL_HANDLE finish_event;
    struct shim_cp_store cpstore;
};

DEFINE_LISTP(cp_session);
LISTP_TYPE(cp_session) cp_sessions;

int create_checkpoint(const char* cpdir, IDTYPE* sid) {
    struct cp_session* cpsession = malloc(sizeof(struct cp_session));
    if (!cpsession)
        return -ENOMEM;

    int ret = 0;

    INIT_LISTP(&cpsession->registered_threads);
    INIT_LIST_HEAD(cpsession, list);
    cpsession->finish_event = DkNotificationEventCreate(PAL_FALSE);
    cpsession->cpfile       = NULL;

    int len        = strlen(cpdir);
    char* filename = __alloca(len + 10);
    memcpy(filename, cpdir, len);
    filename[len] = '/';
    snprintf(filename + len + 1, 9, "%08x", cur_process.vmid);

    cpsession->cpfile = get_new_handle();
    if (!cpsession->cpfile) {
        ret = -ENOMEM;
        goto err;
    }

    /* the directory might not be created. At least try to create it */
    if ((ret = open_namei(NULL, NULL, cpdir, O_CREAT | O_DIRECTORY, 0700, NULL)) < 0 &&
        ret != -EEXIST)
        goto err;

    if ((ret = open_namei(cpsession->cpfile, NULL, filename, O_CREAT | O_EXCL | O_RDWR, 0600,
                          NULL)) < 0)
        goto err;

    get_handle(cpsession->cpfile);
    MASTER_LOCK();

    struct cp_session* s;
    if (*sid) {
        LISTP_FOR_EACH_ENTRY(s, &cp_sessions, list) {
            if (s->sid == *sid) {
                ret = 0;
                goto err_locked;
            }
        }
    } else {
    retry:
        ret = DkRandomBitsRead(&cpsession->sid, sizeof(cpsession->sid));
        if (ret < 0) {
            ret = -convert_pal_errno(-ret);
            goto err_locked;
        }

        LISTP_FOR_EACH_ENTRY(s, &cp_sessions, list) {
            if (s->sid == cpsession->sid)
                goto retry;
        }

        *sid = cpsession->sid;
    }

    LISTP_ADD_TAIL(cpsession, &cp_sessions, list);
    MASTER_UNLOCK();
    return 0;

err_locked:
    MASTER_UNLOCK();
err:
    if (cpsession->cpfile)
        put_handle(cpsession->cpfile);

    DkObjectClose(cpsession->finish_event);
    free(cpsession);
    return ret;
}

static int finish_checkpoint(struct cp_session* session);

static int check_thread(struct shim_thread* thread, void* arg, bool* unlocked) {
    __UNUSED(unlocked);  // Retained for API compatibility
    LISTP_TYPE(cp_thread)* registered = (LISTP_TYPE(cp_thread)*)arg;
    struct cp_thread* t;

    if (!thread->in_vm || !thread->is_alive)
        return 0;

    LISTP_FOR_EACH_ENTRY(t, registered, list) {
        if (t->thread == thread)
            return 0;
    }

    return 1;
}

int join_checkpoint(struct shim_thread* thread, IDTYPE sid) {
    struct cp_session* s;
    struct cp_session* cpsession = NULL;
    struct cp_thread cpthread;
    int ret            = 0;
    bool do_checkpoint = false;

    MASTER_LOCK();

    LISTP_FOR_EACH_ENTRY(s, &cp_sessions, list) {
        if (s->sid == sid) {
            cpsession = s;
            break;
        }
    }

    if (!cpsession) {
        MASTER_UNLOCK();
        return -EINVAL;
    }

    INIT_LIST_HEAD(&cpthread, list);
    cpthread.thread = thread;
    LISTP_ADD_TAIL(&cpthread, &cpsession->registered_threads, list);

    /* find out if there is any thread that is not registered yet */
    ret = walk_thread_list(&check_thread, &cpsession->registered_threads);

    if (ret == -ESRCH)
        do_checkpoint = true;

    PAL_HANDLE finish_event = cpsession->finish_event;
    MASTER_UNLOCK();

    if (!do_checkpoint) {
        debug("waiting for checkpointing\n");
        object_wait_with_retry(finish_event);
        return 0;
    }

    debug("ready for checkpointing\n");

    ret = finish_checkpoint(cpsession);
    if (ret < 0)
        debug("failed creating checkpoint\n");
    else
        debug("finish checkpointing, time to wake up all threads\n");

    DkEventSet(finish_event);
    return ret;
}

static void* file_alloc(struct shim_cp_store* store, void* addr, size_t size) {
    assert(store->cp_file);
    struct shim_mount* fs = store->cp_file->fs;

    if (!fs || !fs->fs_ops || !fs->fs_ops->truncate || !fs->fs_ops->mmap)
        return NULL;

    if (fs->fs_ops->truncate(store->cp_file, size) < 0)
        return NULL;

    if (fs->fs_ops->mmap(store->cp_file, &addr, size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED,
                         0) < 0)
        return NULL;

    return addr;
}

static BEGIN_MIGRATION_DEF(checkpoint) {
    DEFINE_MIGRATE(process, &cur_process, sizeof(struct shim_process));
    DEFINE_MIGRATE(all_mounts, NULL, 0);
    DEFINE_MIGRATE(all_vmas, NULL, 0);
    DEFINE_MIGRATE(all_running_threads, NULL, 0);
    DEFINE_MIGRATE(brk, NULL, 0);
    DEFINE_MIGRATE(loaded_libraries, NULL, 0);
#ifdef DEBUG
    DEFINE_MIGRATE(gdb_map, NULL, 0);
#endif
    DEFINE_MIGRATE(migratable, NULL, 0);
}
END_MIGRATION_DEF(checkpoint)

static int finish_checkpoint(struct cp_session* cpsession) {
    struct shim_cp_store* cpstore = &cpsession->cpstore;
    int ret;

    cpstore->alloc = file_alloc;

    if ((ret = START_MIGRATE(cpstore, checkpoint)) < 0)
        return ret;

    struct cp_header* hdr = (struct cp_header*)cpstore->base;
    hdr->addr             = (void*)cpstore->base;
    hdr->size             = cpstore->offset;

    DkStreamUnmap((void*)cpstore->base, cpstore->bound);

    put_handle(cpstore->cp_file);
    return 0;
}

int shim_do_checkpoint(const char* filename) {
    IDTYPE session = 0;
    int ret        = 0;

    ret = shim_do_mkdir(filename, 0700);
    if (ret < 0)
        return ret;

    shim_tcb_t* tcb = shim_get_tcb();
    assert(tcb && tcb->tp);
    struct shim_signal signal;
    __store_context(tcb, NULL, &signal);

    ret = create_checkpoint(filename, &session);
    if (ret < 0) {
        shim_do_rmdir(filename);
        return ret;
    }

    ipc_checkpoint_send(filename, session);
    kill_all_threads(tcb->tp, session, SIGCP);

    ret = join_checkpoint(tcb->tp, session);
    if (ret < 0) {
        shim_do_rmdir(filename);
        return ret;
    }

    return 0;
}
