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
 * shim_async.c
 *
 * This file contains functions to add asyncronous events triggered by timer.
 */

#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_thread.h>

#include <pal.h>
#include <list.h>

#define IDLE_SLEEP_TIME     1000
#define MAX_IDLE_CYCLES     100

DEFINE_LIST(async_event);
struct async_event {
    IDTYPE                 caller;        /* thread installing this event */
    LIST_TYPE(async_event) list;
    void                   (*callback) (IDTYPE caller, void * arg);
    void *                 arg;
    PAL_HANDLE             object;        /* handle (async IO) to wait on */
    uint64_t               expire_time;   /* alarm/timer to wait on */
};
DEFINE_LISTP(async_event);
static LISTP_TYPE(async_event) async_list;

/* can be read without async_helper_lock but always written with lock held */
static enum {  HELPER_NOTALIVE, HELPER_ALIVE } async_helper_state;

static struct shim_thread* async_helper_thread;
static struct shim_lock async_helper_lock;

static AEVENTTYPE install_new_event;

static int create_async_helper(void);

/* Threads register async events like alarm(), setitimer(), ioctl(FIOASYNC)
 * using this function. These events are enqueued in async_list and delivered
 * to Async Helper thread by triggering install_new_event. When event is
 * triggered in Async Helper thread, the corresponding event's callback with
 * arguments `arg` is called. This callback typically sends a signal to the
 * thread who registered the event (saved in `event->caller`).
 *
 * We distinguish between alarm/timer events and async IO events:
 *   - alarm/timer events set object = NULL and time = seconds
 *     (time = 0 cancels all pending alarms/timers).
 *   - async IO events set object = handle and time = 0.
 *
 * Function returns remaining usecs for alarm/timer events (same as alarm())
 * or 0 for async IO events. On error, it returns -1.
 */
int64_t install_async_event(PAL_HANDLE object, uint64_t time,
                            void (*callback) (IDTYPE caller, void * arg),
                            void * arg) {
    /* if event happens on object, time must be zero */
    assert(!object || (object && !time));

    uint64_t now = DkSystemTimeQuery();
    uint64_t max_prev_expire_time = now;

    struct async_event* event = malloc(sizeof(struct async_event));
    event->callback     = callback;
    event->arg          = arg;
    event->caller       = get_cur_tid();
    event->object       = object;
    event->expire_time  = time ? now + time : 0;

    lock(&async_helper_lock);

    if (!object) {
        /* This is alarm() or setitimer() emulation, treat both according to
         * alarm() syscall semantics: cancel any pending alarm/timer. */
        struct async_event * tmp, * n;
        LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &async_list, list) {
            if (tmp->expire_time) {
                /* this is a pending alarm/timer, cancel it and save its expiration time */
                if (max_prev_expire_time < tmp->expire_time)
                    max_prev_expire_time = tmp->expire_time;

                LISTP_DEL(tmp, &async_list, list);
                free(tmp);
            }
        }

        if (!time) {
            /* This is alarm(0), we cancelled all pending alarms/timers
             * and user doesn't want to set a new alarm: we are done. */
            free(event);
            unlock(&async_helper_lock);
            return max_prev_expire_time - now;
        }
    }

    INIT_LIST_HEAD(event, list);
    LISTP_ADD_TAIL(event, &async_list, list);

    if (async_helper_state == HELPER_NOTALIVE) {
        int ret = create_async_helper();
        if (ret < 0)
            return ret;
    }

    unlock(&async_helper_lock);

    debug("Installed async event at %lu\n", now);
    set_event(&install_new_event, 1);
    return max_prev_expire_time - now;
}

int init_async(void) {
    /* early enough in init, can write global vars without the lock */
    async_helper_state = HELPER_NOTALIVE;
    create_lock(&async_helper_lock);
    create_event(&install_new_event);

    /* enable locking mechanisms since we are going in multi-threaded mode */
    enable_locking();

    return 0;
}

static void shim_async_helper(void * arg) {
    struct shim_thread * self = (struct shim_thread *) arg;
    if (!arg)
        return;

    __libc_tcb_t tcb;
    allocate_tls(&tcb, false, self);
    debug_setbuf(&tcb.shim_tcb, true);
    debug("Set tcb to %p\n", &tcb);

    lock(&async_helper_lock);
    bool notme = (self != async_helper_thread);
    unlock(&async_helper_lock);

    if (notme) {
        put_thread(self);
        DkThreadExit();
        return;
    }

    /* Assume async helper thread will not drain the stack that PAL provides,
     * so for efficiency we don't swap the stack. */
    debug("Async helper thread started\n");

    /* Simple heuristic to not burn cycles when no async events are installed:
     * async helper thread sleeps IDLE_SLEEP_TIME for MAX_IDLE_CYCLES and
     * if nothing happens, dies. It will be re-spawned if some thread wants
     * to install a new event. */
    uint64_t idle_cycles = 0;

    PAL_HANDLE polled = NULL;

    /* init object_list so that it always contains at least install_new_event */
    size_t object_list_size = 32;
    PAL_HANDLE * object_list =
            malloc(sizeof(PAL_HANDLE) * (1 + object_list_size));

    PAL_HANDLE install_new_event_hdl = event_handle(&install_new_event);
    object_list[0] = install_new_event_hdl;

    while (async_helper_state == HELPER_ALIVE) {
        uint64_t now = DkSystemTimeQuery();

        if (polled == install_new_event_hdl) {
            /* Some thread wants to install new event; this event is found
             * in async_list below, so just re-init install_new_event. */
            clear_event(&install_new_event);
        }

        lock(&async_helper_lock);

        /* Iterate through all async IO events and alarm/timer events to:
         *   - call callbacks for all triggered events, and
         *   - repopulate object_list with async IO events (if any), and
         *   - find the next expiring alarm/timer (if any) */
        uint64_t next_expire_time = 0;
        size_t object_num = 0;

        struct async_event * tmp, * n;
        LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &async_list, list) {
            /* First check if this event was triggered; note that IO events
             * stay in the list whereas alarms/timers are fired only once. */
            if (polled && tmp->object == polled) {
                debug("Async IO event triggered at %lu\n", now);
                unlock(&async_helper_lock);
                tmp->callback(tmp->caller, tmp->arg);
                lock(&async_helper_lock);
            } else if (tmp->expire_time && tmp->expire_time <= now) {
                debug("Async alarm/timer triggered at %lu (expired at %lu)\n",
                        now, tmp->expire_time);
                LISTP_DEL(tmp, &async_list, list);
                unlock(&async_helper_lock);
                tmp->callback(tmp->caller, tmp->arg);
                free(tmp);
                lock(&async_helper_lock);
                continue;
            }

            /* Now re-add this IO event to the list or re-add this timer */
            if (tmp->object) {
                if (object_num == object_list_size) {
                    /* grow object_list to accomodate more objects */
                    PAL_HANDLE * tmp_array = malloc(
                            sizeof(PAL_HANDLE) * (1 + object_list_size * 2));
                    memcpy(tmp_array, object_list,
                            sizeof(PAL_HANDLE) * (1 + object_list_size));
                    object_list_size *= 2;
                    free(object_list);
                    object_list = tmp_array;
                }
                object_list[object_num + 1] = tmp->object;
                object_num++;
            } else if (tmp->expire_time && tmp->expire_time > now) {
                if (!next_expire_time || next_expire_time > tmp->expire_time) {
                    /* use time of the next expiring alarm/timer */
                    next_expire_time = tmp->expire_time;
                }
            }
        }

        unlock(&async_helper_lock);

        uint64_t sleep_time;
        if (next_expire_time) {
            sleep_time = next_expire_time - now;
            idle_cycles = 0;
        } else if (object_num) {
            sleep_time = NO_TIMEOUT;
            idle_cycles = 0;
        } else {
            /* no async IO events and no timers/alarms: thread is idling */
            sleep_time = IDLE_SLEEP_TIME;
            idle_cycles++;
        }

        if (idle_cycles == MAX_IDLE_CYCLES) {
            debug("Async helper thread has been idle for some time; stopping it\n");
            break;
        }

        /* wait on async IO events + install_new_event + next expiring alarm/timer */
        polled = DkObjectsWaitAny(object_num + 1, object_list, sleep_time);
        /* ensure that while loop breaks on async_helper_state change */
        COMPILER_BARRIER();
    }

    lock(&async_helper_lock);
    async_helper_state = HELPER_NOTALIVE;
    async_helper_thread = NULL;
    unlock(&async_helper_lock);
    put_thread(self);
    debug("Async helper thread terminated\n");
    free(object_list);

    DkThreadExit();
}

/* this should be called with the async_helper_lock held */
static int create_async_helper(void) {
    if (async_helper_state == HELPER_ALIVE)
        return 0;

    struct shim_thread* new = get_new_internal_thread();
    if (!new)
        return -ENOMEM;

    async_helper_thread = new;
    async_helper_state = HELPER_ALIVE;

    PAL_HANDLE handle = thread_create(shim_async_helper, new);

    if (!handle) {
        async_helper_thread = NULL;
        async_helper_state = HELPER_NOTALIVE;
        put_thread(new);
        return -PAL_ERRNO;
    }

    new->pal_handle = handle;
    return 0;
}

/* On success, the reference to async helper thread is returned with refcount
 * incremented. It is the responsibility of caller to wait for async helper's
 * exit and then release the final reference to free related resources (it is
 * problematic for the thread itself to release its own resources e.g. stack).
 */
struct shim_thread* terminate_async_helper(void) {
    if (async_helper_state != HELPER_ALIVE)
        return NULL;

    lock(&async_helper_lock);
    struct shim_thread* ret = async_helper_thread;
    if (ret)
        get_thread(ret);
    async_helper_state = HELPER_NOTALIVE;
    unlock(&async_helper_lock);

    /* force wake up of async helper thread so that it exits */
    set_event(&install_new_event, 1);
    return ret;
}
