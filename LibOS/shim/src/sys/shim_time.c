/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system calls "gettimeofday", "time" and "clock_gettime".
 */

#include <errno.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_table.h"

int shim_do_gettimeofday(struct __kernel_timeval* tv, struct __kernel_timezone* tz) {
    if (!tv)
        return -EINVAL;

    if (test_user_memory(tv, sizeof(*tv), /*write=*/true))
        return -EFAULT;

    if (tz && test_user_memory(tz, sizeof(*tz), /*write=*/true))
        return -EFAULT;

    uint64_t time = DkSystemTimeQuery();

    if (time == (uint64_t)-1)
        return -PAL_ERRNO();

    tv->tv_sec  = time / 1000000;
    tv->tv_usec = time % 1000000;
    return 0;
}

time_t shim_do_time(time_t* tloc) {
    uint64_t time = DkSystemTimeQuery();

    if (time == (uint64_t)-1)
        return -PAL_ERRNO();

    if (tloc && test_user_memory(tloc, sizeof(*tloc), /*write=*/true))
        return -EFAULT;

    time_t t = time / 1000000;

    if (tloc)
        *tloc = t;

    return t;
}

int shim_do_clock_gettime(clockid_t which_clock, struct timespec* tp) {
    /* all clocks are the same */
    if (!(0 <= which_clock && which_clock < MAX_CLOCKS))
        return -EINVAL;

    if (!tp)
        return -EINVAL;

    if (test_user_memory(tp, sizeof(*tp), /*write=*/true))
        return -EFAULT;

    uint64_t time = DkSystemTimeQuery();

    if (time == (uint64_t)-1)
        return -PAL_ERRNO();

    tp->tv_sec  = time / 1000000;
    tp->tv_nsec = (time % 1000000) * 1000;
    return 0;
}

int shim_do_clock_getres(clockid_t which_clock, struct timespec* tp) {
    /* all clocks are the same */
    if (!(0 <= which_clock && which_clock < MAX_CLOCKS))
        return -EINVAL;

    if (tp) {
        if (test_user_memory(tp, sizeof(*tp), /*write=*/true))
            return -EFAULT;

        tp->tv_sec  = 0;
        tp->tv_nsec = 1000;
    }
    return 0;
}
