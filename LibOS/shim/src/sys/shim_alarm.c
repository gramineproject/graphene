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
 * shim_alarm.c
 *
 * Implementation of system call "alarm", "setitmer" and "getitimer".
 */

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_utils.h>
#include <shim_signal.h>

void signal_alarm (IDTYPE target, void * arg)
{
    debug("alarm goes off, signaling thread %u\n", target);

    struct shim_thread * thread = lookup_thread(target);
    if (!thread)
        return;

    append_signal(thread, SIGALRM, NULL, true);
}

int shim_do_alarm (unsigned int seconds)
{
    uint64_t usecs = 1000000ULL * seconds;
    return install_async_event(NULL, usecs, &signal_alarm, NULL);
}

static struct {
    unsigned long   timeout;
    unsigned long   reset;
} real_itimer;

void signal_itimer (IDTYPE target, void * arg)
{
    master_lock();

    if (real_itimer.timeout != (unsigned long) arg) {
        master_unlock();
        return;
    }

    real_itimer.timeout += real_itimer.reset;
    real_itimer.reset = 0;
    master_unlock();
}

#ifndef ITIMER_REAL
# define ITIMER_REAL 0
#endif

int shim_do_setitimer (int which, struct __kernel_itimerval * value,
                       struct __kernel_itimerval * ovalue)
{
    if (which != ITIMER_REAL)
        return -ENOSYS;

    if (!value)
        return -EFAULT;

    unsigned long setup_time = DkSystemTimeQuery();

    unsigned long next_value = value->it_value.tv_sec * 1000000
                               + value->it_value.tv_usec;
    unsigned long next_reset = value->it_interval.tv_sec * 1000000
                               + value->it_interval.tv_usec;

    master_lock();

    unsigned long current_timeout = real_itimer.timeout > setup_time ?
                                    real_itimer.timeout - setup_time : 0;
    unsigned long current_reset = real_itimer.reset;

    int ret = install_async_event(NULL, next_value, &signal_itimer,
                                  (void *) (setup_time + next_value));

    if (ret < 0) {
        master_unlock();
        return ret;
    }

    real_itimer.timeout = setup_time + next_value;
    real_itimer.reset = next_reset;

    master_unlock();

    if (ovalue) {
        ovalue->it_interval.tv_sec = current_reset / 1000000;
        ovalue->it_interval.tv_usec = current_reset % 1000000;
        ovalue->it_value.tv_sec = current_timeout / 1000000;
        ovalue->it_value.tv_usec = current_timeout % 1000000;
    }

    return 0;
}

int shim_do_getitimer (int which, struct __kernel_itimerval * value)
{
    if (which != ITIMER_REAL)
        return -ENOSYS;

    if (!value)
        return -EFAULT;

    unsigned long setup_time = DkSystemTimeQuery();

    master_lock();
    unsigned long current_timeout = real_itimer.timeout > setup_time ?
                                    real_itimer.timeout - setup_time : 0;
    unsigned long current_reset = real_itimer.reset;
    master_unlock();

    value->it_interval.tv_sec = current_reset / 1000000;
    value->it_interval.tv_usec = current_reset % 1000000;
    value->it_value.tv_sec = current_timeout / 1000000;
    value->it_value.tv_usec = current_timeout % 1000000;
    return 0;
}
