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
 * shim_time.c
 *
 * Implementation of system call "gettimeofday", "time" and "clock_gettime".
 */

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_handle.h>
#include <shim_fs.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>

int shim_do_gettimeofday (struct __kernel_timeval * tv,
                          struct __kernel_timezone * tz)
{
    if (!tv)
        return -EINVAL;

    if (test_user_memory(tv, sizeof(*tv), true))
        return -EFAULT;

    if (tz && test_user_memory(tz, sizeof(*tz), true))
        return -EFAULT;

    long time = DkSystemTimeQuery();

    if (time == -1)
        return -PAL_ERRNO;

    tv->tv_sec  = time / 1000000;
    tv->tv_usec = time % 1000000;
    return 0;
}

time_t shim_do_time (time_t * tloc)
{
    long time = DkSystemTimeQuery();

    if (time == -1)
        return -PAL_ERRNO;

    if (tloc && test_user_memory(tloc, sizeof(*tloc), true))
        return -EFAULT;

    time_t t = time / 1000000;

    if (tloc)
        *tloc = t;

    return t;
}

int shim_do_clock_gettime (clockid_t which_clock,
                           struct timespec * tp)
{
    /* all clock are the same */

    if (!tp)
        return -EINVAL;

    if (test_user_memory(tp, sizeof(*tp), true))
        return -EFAULT;

    long time = DkSystemTimeQuery();

    if (time == -1)
        return -PAL_ERRNO;

    tp->tv_sec  = time / 1000000;
    tp->tv_nsec = (time % 1000000) * 1000;
    return 0;
}

int shim_do_clock_getres (clockid_t which_clock,
                          struct timespec * tp)
{
    /* all clock are the same */

    if (!tp)
        return -EINVAL;

    if (test_user_memory(tp, sizeof(*tp), true))
        return -EFAULT;

    tp->tv_sec  = 0;
    tp->tv_nsec = 1000;
    return 0;
}
