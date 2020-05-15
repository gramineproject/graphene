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

#include <errno.h>

#include <pal.h>
#include <pal_error.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_utils.h>
#include <shim_vma.h>

int shim_do_pause(void) {
    /* ~0ULL micro sec ~= 805675 years */
    DkThreadDelayExecution(~((PAL_NUM)0));
    return -EINTR;
}

int shim_do_nanosleep(const struct __kernel_timespec* rqtp, struct __kernel_timespec* rmtp) {
    if (!rqtp)
        return -EFAULT;

    unsigned long time = rqtp->tv_sec * 1000000L + rqtp->tv_nsec / 1000;
    unsigned long ret = DkThreadDelayExecution(time);

    if (ret < time) {
        if (rmtp) {
            unsigned long remtime = time - ret;
            rmtp->tv_sec  = remtime / 1000000L;
            rmtp->tv_nsec = (remtime - rmtp->tv_sec * 1000) * 1000;
        }
        return -EINTR;
    }

    return 0;
}

int shim_do_clock_nanosleep(clockid_t clock_id, int flags, const struct __kernel_timespec* rqtp,
                            struct __kernel_timespec* rmtp) {
    /* all clocks are the same */
    __UNUSED(clock_id);

    if (flags) {
        debug("Graphene's clock_nanosleep does not support non-zero flags (%d)\n", flags);
        return -EINVAL;
    }

    return shim_do_nanosleep(rqtp, rmtp);
}
