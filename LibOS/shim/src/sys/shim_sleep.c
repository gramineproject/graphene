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
 * shim_sleep.c
 *
 * Implementation of system call "pause" and "nanosleep".
 */

#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_table.h>
#include <shim_handle.h>
#include <shim_vma.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>

#define SHIM_DEFAULT_SLEEP 1000

int shim_do_pause (void)
{
    while (1) {
        unsigned long ret = DkThreadDelayExecution(SHIM_DEFAULT_SLEEP);

        if (!ret)
            break;
    }

    return 0;
}

int shim_do_nanosleep (const struct __kernel_timespec * rqtp,
                       struct __kernel_timespec * rmtp)
{
    if (!rqtp)
        return -EFAULT;

    unsigned long time = rqtp->tv_sec * 1000000L + rqtp->tv_nsec / 1000;
    unsigned long ret = DkThreadDelayExecution(time);

    if (ret < time) {
        if (rmtp) {
            unsigned long remtime = time - ret;
            rmtp->tv_sec = remtime / 1000000L;
            rmtp->tv_nsec = (remtime - rmtp->tv_sec * 1000) * 1000;
        }
        return -EINTR;
    }

    return 0;
}
