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
 * shim_async.c
 *
 * This file contains functions to add asyncronous events triggered by timer.
 */

#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_thread.h>

#include <pal.h>
#include <linux_list.h>

struct async_event {
    IDTYPE              caller;
    struct list_head    list;
    void                (*callback) (IDTYPE caller, void * arg);
    void *              arg;
    unsigned long       install_time;
    unsigned long       expire_time;
};

static LIST_HEAD(async_list);

enum {  HELPER_NOTALIVE, HELPER_ALIVE };

static struct shim_atomic       async_helper_state;
static struct shim_thread *     async_helper_thread;
static PAL_HANDLE               async_helper_event;

static LOCKTYPE async_helper_lock;

int install_async_event (unsigned long time,
                         void (*callback) (IDTYPE caller, void * arg),
                         void * arg)
{
    struct async_event * event =
                    malloc(sizeof(struct async_event));

    unsigned long install_time = DkSystemTimeQuery();

    debug("install async event at %llu\n", install_time);

    event->callback     = callback;
    event->arg          = arg;
    event->caller       = get_cur_tid();
    event->install_time = install_time;
    event->expire_time  = install_time + time;

    lock(async_helper_lock);

    struct async_event * tmp;
    struct list_head * prev = &async_list;

    list_for_each_entry(tmp, &async_list, list) {
        if (tmp->expire_time > event->expire_time)
            break;
        prev = &tmp->list;
    }

    INIT_LIST_HEAD(&event->list);
    list_add(&event->list, prev);

    unlock(async_helper_lock);

    if (atomic_read(&async_helper_state) == HELPER_NOTALIVE)
        create_async_helper();

    DkEventSet(async_helper_event);
    return 0;
}

int init_async (void)
{
    atomic_set(&async_helper_state, HELPER_NOTALIVE);
    create_lock(async_helper_lock);
    async_helper_event = DkSynchronizationEventCreate(0);
    return 0;
}

#define IDLE_SLEEP_TIME     1000
#define MAX_IDLE_CYCLES     100

static void shim_async_helper (void * arg)
{
    struct shim_thread * self = (struct shim_thread *) arg;
    if (!arg)
        return;

    __libc_tcb_t tcb;
    allocate_tls(&tcb, self);
    debug_setbuf(&tcb.shim_tcb, true);

    lock(async_helper_lock);

    if (self != async_helper_thread) {
        put_thread(self);
        DkThreadExit();
        return;
    }

    debug("async helper thread started\n");

    /* TSAI: we assume async helper thread will not drain the
       stack that PAL provides, so for efficiency, we don't
       swap any stack */
    unsigned long idle_cycles = 0;
    unsigned long latest_time;
    struct async_event * next_event, * finished_event = NULL;

    goto update;

    while (atomic_read(&async_helper_state) == HELPER_ALIVE) {
        lock(async_helper_lock);
update:
        latest_time = DkSystemTimeQuery();
        next_event = NULL;

        if (!list_empty(&async_list)) {
            if (finished_event) {
                list_del(&finished_event->list);
                free(finished_event);
                finished_event = NULL;
            }

            struct async_event * tmp, * n;

            list_for_each_entry_safe(tmp, n, &async_list, list) {
                if (tmp->expire_time > latest_time) {
                    next_event = tmp;
                    break;
                }

                debug("async event trigger at %llu (expect expiring at %llu)\n",
                      latest_time, tmp->expire_time);

                list_del(&tmp->list);
                tmp->callback(tmp->caller, tmp->arg);
                free(tmp);
            }

            idle_cycles = 0;
        }

        unlock(async_helper_lock);

        if (!next_event && idle_cycles++ == MAX_IDLE_CYCLES) {
            debug("async helper thread reach helper cycle\n");
            /* walking away, if someone is issueing an event,
               they have to create another thread */
            break;
        }

        unsigned long sleep_time = next_event ?
                                   next_event->expire_time - latest_time :
                                   IDLE_SLEEP_TIME;

        PAL_HANDLE notify = DkObjectsWaitAny(1, &async_helper_event,
                                             sleep_time);

        /* if we are not waken up by someone, the waiting has finished */
        if (!notify && next_event) {
            debug("async event trigger at %llu\n", next_event->expire_time);

            finished_event = next_event;
            next_event->callback(next_event->caller, next_event->arg);
        }
    }

    atomic_set(&async_helper_state, HELPER_NOTALIVE);
    lock(async_helper_lock);
    async_helper_thread = NULL;
    unlock(async_helper_lock);
    put_thread(self);
    debug("async helper thread terminated\n");

    DkThreadExit();
}

int create_async_helper (void)
{
    int ret = 0;

    if (atomic_read(&async_helper_state) == HELPER_ALIVE)
        return 0;

    enable_locking();

    struct shim_thread * new = get_new_internal_thread();
    if (!new)
        return -ENOMEM;

    lock(async_helper_lock);
    if (atomic_read(&async_helper_state) == HELPER_ALIVE) {
        unlock(async_helper_lock);
        put_thread(new);
        return 0;
    }

    async_helper_thread = new;
    atomic_xchg(&async_helper_state, HELPER_ALIVE);
    unlock(async_helper_lock);

    PAL_HANDLE handle = thread_create(shim_async_helper, new, 0);

    if (!handle) {
        ret = -PAL_ERRNO;
        lock(async_helper_lock);
        async_helper_thread = NULL;
        atomic_xchg(&async_helper_state, HELPER_NOTALIVE);
        unlock(async_helper_lock);
        put_thread(new);
        return ret;
    }

    new->pal_handle = handle;
    return 0;
}

int terminate_async_helper (void)
{
    if (atomic_read(&async_helper_state) != HELPER_ALIVE)
        return 0;

    lock(async_helper_lock);
    atomic_xchg(&async_helper_state, HELPER_NOTALIVE);
    unlock(async_helper_lock);
    DkEventSet(async_helper_event);
    return 0;
}
