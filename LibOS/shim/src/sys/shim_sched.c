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
 * shim_sched.c
 *
 * Implementation of system call "sched_yield".
 */

#include <shim_internal.h>
#include <shim_table.h>
#include <api.h>
#include <pal.h>

#include <errno.h>

int shim_do_sched_yield (void)
{
    DkThreadYieldExecution();
    return 0;
}

int shim_do_sched_getaffinity (pid_t pid, size_t len,
                               __kernel_cpu_set_t * user_mask_ptr)
{
    int ncpus = PAL_CB(cpu_info.cpu_num);
    /* Linux kernel bitmap is based on long. So according to its
     * implementation, round up the result to sizeof(long) */
    int bitmask_long_count = (ncpus + sizeof(long) * 8 - 1) /
        (sizeof(long) * 8);
    int bitmask_size_in_bytes = bitmask_long_count * sizeof(long);
    if (len < bitmask_size_in_bytes)
        return -EINVAL;
    /* Linux kernel also rejects non-natural size */
    if (len & (sizeof(long) - 1))
        return -EINVAL;

    memset(user_mask_ptr, 0, len);
    for (int i = 0 ; i < ncpus ; i++)
        ((uint8_t *) user_mask_ptr)[i / 8] |= 1 << (i % 8);
    /* imitate the Linux kernel implementation
     * See SYSCALL_DEFINEE3(sched_getaffinity) */
    return bitmask_size_in_bytes;
}
