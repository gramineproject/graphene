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
 * shim_alarm.c
 *
 * Implementation of system call "alarm", "setitmer" and "getitimer".
 */

#include <shim_internal.h>
#include <shim_signal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_utils.h>

static void signal_alarm(IDTYPE target, void* arg) {
    // Kept for API compatibility wtih signal_itimer
    __UNUSED(arg);

    debug("alarm goes off, signaling thread %u\n", target);

    struct shim_thread* thread = lookup_thread(target);
    if (!thread)
        return;

    lock(&thread->lock);
    append_signal(thread, SIGALRM, NULL, true);
    unlock(&thread->lock);
    put_thread(thread);
}

int shim_do_alarm(unsigned int seconds) {
    uint64_t usecs = 1000000ULL * seconds;

    int64_t ret = install_async_event(NULL, usecs, &signal_alarm, NULL);
    if (ret < 0)
        return ret;

    uint64_t usecs_left = (uint64_t)ret;
    int secs            = usecs_left / 1000000ULL;
    if (usecs_left % 1000000ULL)
        secs++;
    return secs;
}

static struct {
    unsigned long timeout;
    unsigned long reset;
} real_itimer;

void signal_itimer(IDTYPE target, void* arg) {
    // XXX: Can we simplify this code or streamline with the other callback?
    __UNUSED(target);

    MASTER_LOCK();

    if (real_itimer.timeout != (unsigned long)arg) {
        MASTER_UNLOCK();
        return;
    }

    real_itimer.timeout += real_itimer.reset;
    real_itimer.reset = 0;
    MASTER_UNLOCK();
}

#ifndef ITIMER_REAL
#define ITIMER_REAL 0
#endif

int shim_do_setitimer(int which, struct __kernel_itimerval* value,
                      struct __kernel_itimerval* ovalue) {
    if (which != ITIMER_REAL)
        return -ENOSYS;

    if (!value)
        return -EFAULT;
    if (test_user_memory(value, sizeof(*value), false))
        return -EFAULT;
    if (ovalue && test_user_memory(ovalue, sizeof(*ovalue), true))
        return -EFAULT;

    unsigned long setup_time = DkSystemTimeQuery();

    unsigned long next_value = value->it_value.tv_sec * 1000000 + value->it_value.tv_usec;
    unsigned long next_reset = value->it_interval.tv_sec * 1000000 + value->it_interval.tv_usec;

    MASTER_LOCK();

    unsigned long current_timeout =
        real_itimer.timeout > setup_time ? real_itimer.timeout - setup_time : 0;
    unsigned long current_reset = real_itimer.reset;

    int64_t ret =
        install_async_event(NULL, next_value, &signal_itimer, (void*)(setup_time + next_value));

    if (ret < 0) {
        MASTER_UNLOCK();
        return ret;
    }

    real_itimer.timeout = setup_time + next_value;
    real_itimer.reset   = next_reset;

    MASTER_UNLOCK();

    if (ovalue) {
        ovalue->it_interval.tv_sec  = current_reset / 1000000;
        ovalue->it_interval.tv_usec = current_reset % 1000000;
        ovalue->it_value.tv_sec     = current_timeout / 1000000;
        ovalue->it_value.tv_usec    = current_timeout % 1000000;
    }

    return 0;
}

int shim_do_getitimer(int which, struct __kernel_itimerval* value) {
    if (which != ITIMER_REAL)
        return -ENOSYS;

    if (!value)
        return -EFAULT;
    if (test_user_memory(value, sizeof(*value), true))
        return -EFAULT;

    unsigned long setup_time = DkSystemTimeQuery();

    MASTER_LOCK();
    unsigned long current_timeout =
        real_itimer.timeout > setup_time ? real_itimer.timeout - setup_time : 0;
    unsigned long current_reset = real_itimer.reset;
    MASTER_UNLOCK();

    value->it_interval.tv_sec  = current_reset / 1000000;
    value->it_interval.tv_usec = current_reset % 1000000;
    value->it_value.tv_sec     = current_timeout / 1000000;
    value->it_value.tv_usec    = current_timeout % 1000000;
    return 0;
}
