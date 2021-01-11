/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system calls "pause" and "nanosleep".
 */

#include <errno.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_table.h"
#include "shim_thread.h"
#include "shim_utils.h"
#include "shim_vma.h"

long shim_do_pause(void) {
    /* ~0ULL micro sec ~= 805675 years */
    DkThreadDelayExecution(~((PAL_NUM)0));
    return -EINTR;
}

long shim_do_nanosleep(const struct __kernel_timespec* rqtp, struct __kernel_timespec* rmtp) {
    if (!rqtp)
        return -EFAULT;

    if (!(rqtp->tv_sec >= 0 && 0 <= rqtp->tv_nsec && rqtp->tv_nsec < 1000000000L))
        return -EINVAL;

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

long shim_do_clock_nanosleep(clockid_t clock_id, int flags, const struct __kernel_timespec* rqtp,
                            struct __kernel_timespec* rmtp) {
    /* all clocks are the same */
    if (!(0 <= clock_id && clock_id < MAX_CLOCKS))
        return -EINVAL;

    if (flags) {
        debug("Graphene's clock_nanosleep does not support non-zero flags (%d)\n", flags);
        return -EINVAL;
    }

    return shim_do_nanosleep(rqtp, rmtp);
}
