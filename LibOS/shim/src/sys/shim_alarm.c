/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system calls "alarm", "setitmer" and "getitimer".
 */

#include <stdint.h>

#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_signal.h"
#include "shim_table.h"
#include "shim_utils.h"

static void signal_alarm(IDTYPE caller, void* arg) {
    __UNUSED(caller);
    __UNUSED(arg);
    siginfo_t info = {
        .si_signo = SIGALRM,
        .si_pid = g_process.pid,
        .si_code = SI_USER,
    };
    if (kill_current_proc(&info) < 0) {
        debug("signal_alarm: failed to deliver a signal\n");
    }
}

long shim_do_alarm(unsigned int seconds) {
    uint64_t usecs = 1000000ULL * seconds;

    int64_t ret = install_async_event(NULL, usecs, &signal_alarm, NULL);
    if (ret < 0)
        return ret;

    uint64_t usecs_left = (uint64_t)ret;
    int secs = usecs_left / 1000000ULL;
    if (usecs_left % 1000000ULL)
        secs++;
    return secs;
}

static struct {
    unsigned long timeout;
    unsigned long reset;
} real_itimer;

static void signal_itimer(IDTYPE target, void* arg) {
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

long shim_do_setitimer(int which, struct __kernel_itimerval* value,
                       struct __kernel_itimerval* ovalue) {
    if (which != ITIMER_REAL)
        return -ENOSYS;

    if (!value)
        return -EFAULT;
    if (test_user_memory(value, sizeof(*value), false))
        return -EFAULT;
    if (ovalue && test_user_memory(ovalue, sizeof(*ovalue), true))
        return -EFAULT;

    uint64_t setup_time = DkSystemTimeQuery();

    uint64_t next_value = value->it_value.tv_sec * (uint64_t)1000000 + value->it_value.tv_usec;
    uint64_t next_reset = value->it_interval.tv_sec * (uint64_t)1000000
                          + value->it_interval.tv_usec;

    MASTER_LOCK();

    uint64_t current_timeout = real_itimer.timeout > setup_time
                               ? real_itimer.timeout - setup_time
                               : 0;
    uint64_t current_reset = real_itimer.reset;

    int64_t ret = install_async_event(NULL, next_value, &signal_itimer,
                                      (void*)(setup_time + next_value));

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

long shim_do_getitimer(int which, struct __kernel_itimerval* value) {
    if (which != ITIMER_REAL)
        return -ENOSYS;

    if (!value)
        return -EFAULT;
    if (test_user_memory(value, sizeof(*value), true))
        return -EFAULT;

    uint64_t setup_time = DkSystemTimeQuery();

    MASTER_LOCK();
    uint64_t current_timeout = real_itimer.timeout > setup_time
                               ? real_itimer.timeout - setup_time
                               : 0;
    uint64_t current_reset = real_itimer.reset;
    MASTER_UNLOCK();

    value->it_interval.tv_sec  = current_reset / 1000000;
    value->it_interval.tv_usec = current_reset % 1000000;
    value->it_value.tv_sec     = current_timeout / 1000000;
    value->it_value.tv_usec    = current_timeout % 1000000;
    return 0;
}
