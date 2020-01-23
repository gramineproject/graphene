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

#include <list.h>
#include <pal.h>
#include <shim_internal.h>
#include <shim_thread.h>
#include <shim_utils.h>

#define IDLE_SLEEP_TIME 1000
#define MAX_IDLE_CYCLES 100

DEFINE_LIST(async_event);
struct async_event {
    IDTYPE caller;  /* thread installing this event */
    LIST_TYPE(async_event) list;
    void (*callback)(IDTYPE caller, void* arg);
    void* arg;
    PAL_HANDLE object;     /* handle (async IO) to wait on */
    uint64_t expire_time;  /* alarm/timer to wait on */
};
DEFINE_LISTP(async_event);
static LISTP_TYPE(async_event) async_list;

/* Should be accessed with async_helper_lock held. */
static enum { HELPER_NOTALIVE, HELPER_ALIVE } async_helper_state;

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
 * or 0 for async IO events. On error, it returns a negated error code.
 */
int64_t install_async_event(PAL_HANDLE object, uint64_t time,
                            void (*callback)(IDTYPE caller, void* arg), void* arg) {
    /* if event happens on object, time must be zero */
    assert(!object || (object && !time));

    uint64_t now = DkSystemTimeQuery();
    if ((int64_t)now < 0) {
        return (int64_t)now;
    }

    uint64_t max_prev_expire_time = now;

    struct async_event* event = malloc(sizeof(struct async_event));
    if (!event) {
        return -ENOMEM;
    }

    event->callback           = callback;
    event->arg                = arg;
    event->caller             = get_cur_tid();
    event->object             = object;
    event->expire_time        = time ? now + time : 0;

    lock(&async_helper_lock);

    if (callback != &cleanup_thread && !object) {
        /* This is alarm() or setitimer() emulation, treat both according to
         * alarm() syscall semantics: cancel any pending alarm/timer. */
        struct async_event* tmp;
        struct async_event* n;
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
        if (ret < 0) {
            unlock(&async_helper_lock);
            return ret;
        }
    }

    unlock(&async_helper_lock);

    debug("Installed async event at %lu\n", now);
    set_event(&install_new_event, 1);
    return max_prev_expire_time - now;
}

int init_async(void) {
    /* early enough in init, can write global vars without the lock */
    async_helper_state = HELPER_NOTALIVE;
    if (!create_lock(&async_helper_lock)) {
        return -ENOMEM;
    }
    create_event(&install_new_event);

    /* enable locking mechanisms since we are going in multi-threaded mode */
    enable_locking();

    return 0;
}

static void shim_async_helper(void* arg) {
    struct shim_thread* self = (struct shim_thread*)arg;
    if (!arg)
        return;

    shim_tcb_init();
    set_cur_thread(self);
    update_fs_base(0);
    debug_setbuf(shim_get_tcb(), true);

    lock(&async_helper_lock);
    bool notme = (self != async_helper_thread);
    unlock(&async_helper_lock);

    if (notme) {
        put_thread(self);
        DkThreadExit(/*clear_child_tid=*/NULL);
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

    /* init `pals` so that it always contains at least install_new_event */
    size_t pals_max_cnt = 32;
    PAL_HANDLE* pals = malloc(sizeof(*pals) * (1 + pals_max_cnt));
    if (!pals) {
        debug("Allocation of pals failed\n");
        goto out_err;
    }

    /* allocate one memory region to hold two PAL_FLG arrays: events and revents */
    PAL_FLG* pal_events = malloc(sizeof(*pal_events) * (1 + pals_max_cnt) * 2);
    if (!pal_events) {
        debug("Allocation of pal_events failed\n");
        goto out_err;
    }
    PAL_FLG* ret_events = pal_events + 1 + pals_max_cnt;

    PAL_HANDLE install_new_event_pal = event_handle(&install_new_event);
    pals[0]       = install_new_event_pal;
    pal_events[0] = PAL_WAIT_READ;
    ret_events[0] = 0;

    while (true) {
        uint64_t now = DkSystemTimeQuery();
        if ((int64_t)now < 0) {
            debug("DkSystemTimeQuery failed with: %ld\n", (int64_t)now);
            goto out_err;
        }

        lock(&async_helper_lock);
        if (async_helper_state != HELPER_ALIVE) {
            async_helper_thread = NULL;
            unlock(&async_helper_lock);
            break;
        }

        uint64_t next_expire_time = 0;
        size_t pals_cnt            = 0;

        struct async_event* tmp;
        struct async_event* n;
        LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &async_list, list) {
            /* repopulate `pals` with IO events and find the next expiring alarm/timer */
            if (tmp->object) {
                if (pals_cnt == pals_max_cnt) {
                    /* grow `pals` to accommodate more objects */
                    PAL_HANDLE* tmp_pals = malloc(sizeof(*tmp_pals) * (1 + pals_max_cnt * 2));
                    if (!tmp_pals) {
                        debug("tmp_pals allocation failed\n");
                        goto out_err_unlock;
                    }
                    PAL_FLG* tmp_pal_events = malloc(sizeof(*tmp_pal_events) * (2 + pals_max_cnt * 4));
                    if (!tmp_pal_events) {
                        debug("tmp_pal_events allocation failed\n");
                        goto out_err_unlock;
                    }
                    PAL_FLG* tmp_ret_events = tmp_pal_events + 1 + pals_max_cnt * 2;

                    memcpy(tmp_pals, pals, sizeof(*tmp_pals) * (1 + pals_max_cnt));
                    memcpy(tmp_pal_events, pal_events, sizeof(*tmp_pal_events) * (1 + pals_max_cnt));
                    memcpy(tmp_ret_events, ret_events, sizeof(*tmp_ret_events) * (1 + pals_max_cnt));

                    pals_max_cnt *= 2;

                    free(pals);
                    free(pal_events);

                    pals = tmp_pals;
                    pal_events = tmp_pal_events;
                    ret_events = tmp_ret_events;
                }

                pals[pals_cnt + 1]       = tmp->object;
                pal_events[pals_cnt + 1] = PAL_WAIT_READ;
                ret_events[pals_cnt + 1] = 0;
                pals_cnt++;
            } else if (tmp->expire_time && tmp->expire_time > now) {
                if (!next_expire_time || next_expire_time > tmp->expire_time) {
                    /* use time of the next expiring alarm/timer */
                    next_expire_time = tmp->expire_time;
                }
            }
        }

        uint64_t sleep_time;
        if (next_expire_time) {
            sleep_time  = next_expire_time - now;
            idle_cycles = 0;
        } else if (pals_cnt) {
            sleep_time = NO_TIMEOUT;
            idle_cycles = 0;
        } else {
            /* no async IO events and no timers/alarms: thread is idling */
            sleep_time = IDLE_SLEEP_TIME;
            idle_cycles++;
        }

        if (idle_cycles == MAX_IDLE_CYCLES) {
            async_helper_state  = HELPER_NOTALIVE;
            async_helper_thread = NULL;
            unlock(&async_helper_lock);
            debug("Async helper thread has been idle for some time; stopping it\n");
            break;
        }
        unlock(&async_helper_lock);

        /* wait on async IO events + install_new_event + next expiring alarm/timer */
        PAL_BOL polled = DkStreamsWaitEvents(pals_cnt + 1, pals, pal_events, ret_events, sleep_time);

        now = DkSystemTimeQuery();
        if ((int64_t)now < 0) {
            debug("DkSystemTimeQuery failed with: %ld\n", (int64_t)now);
            goto out_err;
        }

        LISTP_TYPE(async_event) triggered;
        INIT_LISTP(&triggered);

        /* acquire lock because we read/modify async_list below */
        lock(&async_helper_lock);

        for (size_t i = 0; polled && i < pals_cnt + 1; i++) {
            if (ret_events[i]) {
                if (pals[i] == install_new_event_pal) {
                    /* some thread wants to install new event; this event is found in async_list,
                     * so just re-init install_new_event */
                    clear_event(&install_new_event);
                    continue;
                }

                /* check if this event is an IO event found in async_list */
                LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &async_list, list) {
                    if (tmp->object == pals[i]) {
                        debug("Async IO event triggered at %lu\n", now);
                        LISTP_ADD_TAIL(tmp, &triggered, list);
                        break;
                    }
                }
            }
        }

        /* check if exit-child or alarm/timer events were triggered */
        LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &async_list, list) {
            if (tmp->callback == &cleanup_thread) {
                debug("Thread exited, cleaning up\n");
                LISTP_DEL(tmp, &async_list, list);
                LISTP_ADD_TAIL(tmp, &triggered, list);
            } else if (tmp->expire_time && tmp->expire_time <= now) {
                debug("Alarm/timer triggered at %lu (expired at %lu)\n", now, tmp->expire_time);
                LISTP_DEL(tmp, &async_list, list);
                LISTP_ADD_TAIL(tmp, &triggered, list);
            }
        }

        unlock(&async_helper_lock);

        /* call callbacks for all triggered events */
        if (!LISTP_EMPTY(&triggered)) {
            LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &triggered, list) {
                LISTP_DEL(tmp, &triggered, list);
                tmp->callback(tmp->caller, tmp->arg);
                if (!tmp->object) {
                    /* this is a one-off exit-child or alarm/timer event */
                    free(tmp);
                }
            }
        }
    }

    __disable_preempt(self->shim_tcb);
    put_thread(self);
    debug("Async helper thread terminated\n");

    free(pals);
    free(pal_events);

    DkThreadExit(/*clear_child_tid=*/NULL);
    return;

out_err_unlock:
    unlock(&async_helper_lock);
out_err:
    debug("Terminating the process due to a fatal error in async helper\n");
    put_thread(self);
    DkProcessExit(1);
}

/* this should be called with the async_helper_lock held */
static int create_async_helper(void) {
    assert(locked(&async_helper_lock));

    if (async_helper_state == HELPER_ALIVE)
        return 0;

    struct shim_thread* new = get_new_internal_thread();
    if (!new)
        return -ENOMEM;

    async_helper_thread = new;
    async_helper_state  = HELPER_ALIVE;

    PAL_HANDLE handle = thread_create(shim_async_helper, new);

    if (!handle) {
        async_helper_thread = NULL;
        async_helper_state  = HELPER_NOTALIVE;
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
    lock(&async_helper_lock);

    if (async_helper_state != HELPER_ALIVE) {
        unlock(&async_helper_lock);
        return NULL;
    }

    struct shim_thread* ret = async_helper_thread;
    if (ret)
        get_thread(ret);
    async_helper_state = HELPER_NOTALIVE;
    unlock(&async_helper_lock);

    /* force wake up of async helper thread so that it exits */
    set_event(&install_new_event, 1);
    return ret;
}
