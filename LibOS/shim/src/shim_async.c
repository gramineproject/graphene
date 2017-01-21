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
    PAL_HANDLE          object;
    unsigned long       install_time;
    unsigned long       expire_time;
};

static LIST_HEAD(async_list);

enum {  HELPER_NOTALIVE, HELPER_ALIVE };

static struct shim_atomic   async_helper_state;
static struct shim_thread * async_helper_thread;
static AEVENTTYPE           async_helper_event;

static LOCKTYPE async_helper_lock;

int install_async_event (PAL_HANDLE object, unsigned long time,
                         void (*callback) (IDTYPE caller, void * arg),
                         void * arg)
{
    struct async_event * event =
                    malloc(sizeof(struct async_event));

    unsigned long install_time = DkSystemTimeQuery();

    event->callback     = callback;
    event->arg          = arg;
    event->caller       = get_cur_tid();
    event->object       = object;
    event->install_time = time ? install_time : 0;
    event->expire_time  = time ? install_time + time : 0;

    lock(async_helper_lock);

    struct async_event * tmp;
    struct list_head * prev = &async_list;

    list_for_each_entry(tmp, &async_list, list) {
        if (event->expire_time && tmp->expire_time > event->expire_time)
            break;
        prev = &tmp->list;
    }

    /* 
     * man page of alarm system call :
     * DESCRIPTION
     * alarm() arranges for a SIGALRM signal to be delivered to the 
	 * calling process in seconds seconds.
     * If seconds is zero, any pending alarm is canceled.
     * In any event any previously set alarm() is canceled.
     */
    if (!list_empty(&async_list)) {
        tmp = list_entry((&async_list)->prev, struct async_event, list);
        /*
         * any previously set alarm() is canceled.
         * There should be exactly only one timer pending
         */
		list_del(&tmp->list);
        free(tmp);
    } else
	   tmp = NULL;
    
    INIT_LIST_HEAD(&event->list);
    if (!time)    // If seconds is zero, any pending alarm is canceled.
        free(event);
    else
        list_add_tail(&event->list, &async_list);   
    
    unlock(async_helper_lock);

    if (atomic_read(&async_helper_state) == HELPER_NOTALIVE)
        create_async_helper();

    DkEventSet(async_helper_event);

    /* 
     * man page of alarm system call :
     * RETURN VALUE
     * alarm()  returns the number of seconds remaining until 
     * any previously scheduled alarm was due to be delivered,
     * or zero if there was no previously scheduled alarm.
     * reference : lxr.free-electrons.com/source/kernel/itimer.c?v=2.6.35#L272
     */
    unsigned long ret;
    unsigned long sec = 0;
    unsigned long usec = 0;
    
    if (tmp) {
    	ret = tmp->expire_time - install_time;
    	sec = ret / 1000000;
    	usec = ret % 1000000;
    	if ((!sec && usec) || usec >=500000)
    		sec++;
    }
    return sec;
}

int init_async (void)
{
    atomic_set(&async_helper_state, HELPER_NOTALIVE);
    create_lock(async_helper_lock);
    create_event(&async_helper_event);
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
    allocate_tls(&tcb, false, self);
    debug_setbuf(&tcb.shim_tcb, true);
    debug("set tcb to %p\n", &tcb);

    lock(async_helper_lock);
    bool notme = (self != async_helper_thread);
    unlock(async_helper_lock);

    if (notme) {
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
    struct async_event * next_event = NULL;
    PAL_HANDLE async_event_handle = event_handle(&async_helper_event);

    int object_list_size = 32, object_num;
    PAL_HANDLE polled;
    PAL_HANDLE * local_objects =
            malloc(sizeof(PAL_HANDLE) * (1 + object_list_size));
    local_objects[0] = async_event_handle;

    goto update_status;

    while (atomic_read(&async_helper_state) == HELPER_ALIVE) {
        unsigned long sleep_time;
        if (next_event) {
            sleep_time = next_event->expire_time - latest_time;
            idle_cycles = 0;
        } else if (object_num) {
            sleep_time = NO_TIMEOUT;
            idle_cycles = 0;
        } else {
            sleep_time = IDLE_SLEEP_TIME;
            idle_cycles++;
        }

        polled = DkObjectsWaitAny(object_num + 1, local_objects, sleep_time);

        if (!polled) {
            if (next_event) {
                debug("async event trigger at %llu\n",
                      next_event->expire_time);

                next_event->callback(next_event->caller, next_event->arg);

                lock(async_helper_lock);
                list_del(&next_event->list);
                free(next_event);
                goto update_list;
            }
            continue;
        }

        if (polled == async_event_handle) {
            clear_event(&async_helper_event);
update_status:
            latest_time = DkSystemTimeQuery();
            if (atomic_read(&async_helper_state) == HELPER_NOTALIVE) {
                break;
            } else {
                lock(async_helper_lock);
                goto update_list;
            }
        }

        struct async_event * tmp, * n;

        lock(async_helper_lock);

        list_for_each_entry_safe(tmp, n, &async_list, list) {
            if (tmp->object == polled) {
                debug("async event trigger at %llu\n",
                      latest_time);
                unlock(async_helper_lock);
                tmp->callback(tmp->caller, tmp->arg);
                lock(async_helper_lock);
                break;
            }
        }

update_list:
        next_event = NULL;
        object_num = 0;

        if (!list_empty(&async_list)) {
            struct async_event * tmp, * n;

            list_for_each_entry_safe(tmp, n, &async_list, list) {
                if (tmp->object) {
                    local_objects[object_num + 1] = tmp->object;
                    object_num++;
                }

                if (!tmp->install_time)
                    continue;

                if (tmp->expire_time > latest_time) {
                    next_event = tmp;
                    break;
                }

                debug("async event trigger at %llu (expire at %llu)\n",
                      latest_time, tmp->expire_time);
                list_del(&tmp->list);
                unlock(async_helper_lock);
                tmp->callback(tmp->caller, tmp->arg);
                free(tmp);
                lock(async_helper_lock);
            }

            idle_cycles = 0;
        }

        unlock(async_helper_lock);

        if (idle_cycles++ == MAX_IDLE_CYCLES) {
            debug("async helper thread reach helper cycle\n");
            /* walking away, if someone is issueing an event,
               they have to create another thread */
            break;
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
    set_event(&async_helper_event, 1);
    return 0;
}
