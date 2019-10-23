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
 * Implementation of system calls "sched_yield", "setpriority", "getpriority",
 * "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler",
 * "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval",
 * "sched_setaffinity", "sched_getaffinity".
 */

#include <api.h>
#include <errno.h>
#include <linux/resource.h>
#include <linux/sched.h>
#include <pal.h>
#include <shim_internal.h>
#include <shim_table.h>

int shim_do_sched_yield(void) {
    DkThreadYieldExecution();
    return 0;
}

/* dummy implementation: ignore user-supplied niceval and return success */
int shim_do_setpriority(int which, int who, int niceval) {
    __UNUSED(who);

    if (which != PRIO_PROCESS && which != PRIO_PGRP && which != PRIO_USER)
        return -EINVAL;

    if (niceval < 1 || niceval > 40)
        return -EACCES;

    return 0;
}

/* dummy implementation: always return the default nice value of 0 */
int shim_do_getpriority(int which, int who) {
    __UNUSED(who);

    if (which != PRIO_PROCESS && which != PRIO_PGRP && which != PRIO_USER)
        return -EINVAL;

    return 20; /* default nice value on Linux */
}

/* dummy implementation: ignore user-supplied param and return success */
int shim_do_sched_setparam(pid_t pid, struct __kernel_sched_param* param) {
    if (pid < 0 || param == NULL)
        return -EINVAL;

    return 0;
}

/* dummy implementation: always return sched_priority of 0 (implies non-real-time sched policy) */
int shim_do_sched_getparam(pid_t pid, struct __kernel_sched_param* param) {
    if (pid < 0 || param == NULL)
        return -EINVAL;

    param->__sched_priority = 0;
    return 0;
}

/* dummy implementation: ignore user-supplied policy & param and return success */
int shim_do_sched_setscheduler(pid_t pid, int policy, struct __kernel_sched_param* param) {
    policy &= ~SCHED_RESET_ON_FORK; /* ignore reset-on-fork flag */

    if (pid < 0 || param == NULL)
        return -EINVAL;

    /* fail on unrecognized policies */
    if (policy != SCHED_NORMAL && policy != SCHED_BATCH && policy != SCHED_IDLE && /* non-real-time */
        policy != SCHED_FIFO && policy != SCHED_RR /* real-time */)
        return -EINVAL;

    /* non-real-time policies must have priority of 0 */
    if ((policy == SCHED_NORMAL || policy == SCHED_BATCH || policy == SCHED_IDLE) &&
        (param->__sched_priority != 0))
        return -EINVAL;

    /* real-time policies must have priority in range [1, 99] */
    if ((policy == SCHED_FIFO || policy == SCHED_RR) &&
        (param->__sched_priority < 1 || param->__sched_priority > 99))
        return -EINVAL;

    return 0;
}

/* dummy implementation: always return SCHED_NORMAL (default round-robin time-sharing policy) */
int shim_do_sched_getscheduler(pid_t pid) {
    if (pid < 0)
        return -EINVAL;

    return SCHED_NORMAL;
}

int shim_do_sched_get_priority_max(int policy) {
    /* fail on unrecognized policies */
    if (policy != SCHED_NORMAL && policy != SCHED_BATCH && policy != SCHED_IDLE && /* non-real-time */
        policy != SCHED_FIFO && policy != SCHED_RR /* real-time */)
        return -EINVAL;

    /* real-time policies have max priority of 99 */
    if (policy == SCHED_FIFO || policy == SCHED_RR)
        return 99;

    /* non-real-time policies have max priority of 0 */
    return 0;
}

int shim_do_sched_get_priority_min(int policy) {
    /* fail on unrecognized policies */
    if (policy != SCHED_NORMAL && policy != SCHED_BATCH && policy != SCHED_IDLE && /* non-real-time */
        policy != SCHED_FIFO && policy != SCHED_RR /* real-time */)
        return -EINVAL;

    /* real-time policies have min priority of 1 */
    if (policy == SCHED_FIFO || policy == SCHED_RR)
        return 1;

    /* non-real-time policies have min priority of 0 */
    return 0;
}

/* dummy implementation: always return 100 ms (default in Linux) */
int shim_do_sched_rr_get_interval(pid_t pid, struct timespec* interval) {
    if (pid < 0)
        return -EINVAL;

    if (test_user_memory(interval, sizeof(*interval), true))
        return -EFAULT;

    interval->tv_sec  = 0;
    interval->tv_nsec = 100000000; /* default value of 100 ms in Linux */
    return 0;
}

static int check_affinity_params(int ncpus, size_t len, __kernel_cpu_set_t* user_mask_ptr) {
    /* Check that user_mask_ptr is valid; if not, should return -EFAULT */
    if (test_user_memory(user_mask_ptr, len, true))
        return -EFAULT;

    /* Linux kernel bitmap is based on long. So according to its
     * implementation, round up the result to sizeof(long) */
    size_t bitmask_long_count    = (ncpus + sizeof(long) * 8 - 1) / (sizeof(long) * 8);
    size_t bitmask_size_in_bytes = bitmask_long_count * sizeof(long);
    if (len < bitmask_size_in_bytes)
        return -EINVAL;
    /* Linux kernel also rejects non-natural size */
    if (len & (sizeof(long) - 1))
        return -EINVAL;

    return bitmask_size_in_bytes;
}

/* dummy implementation: ignore user-supplied mask and return success */
int shim_do_sched_setaffinity(pid_t pid, size_t len, __kernel_cpu_set_t* user_mask_ptr) {
    __UNUSED(pid);
    int ncpus = PAL_CB(cpu_info.cpu_num);

    int bitmask_size_in_bytes = check_affinity_params(ncpus, len, user_mask_ptr);
    if (bitmask_size_in_bytes < 0)
        return bitmask_size_in_bytes;

    return 0;
}

/* dummy implementation: always return all-ones (as many as there are host CPUs)  */
int shim_do_sched_getaffinity(pid_t pid, size_t len, __kernel_cpu_set_t* user_mask_ptr) {
    __UNUSED(pid);
    int ncpus = PAL_CB(cpu_info.cpu_num);

    int bitmask_size_in_bytes = check_affinity_params(ncpus, len, user_mask_ptr);
    if (bitmask_size_in_bytes < 0)
        return bitmask_size_in_bytes;

    memset(user_mask_ptr, 0, len);
    for (int i = 0; i < ncpus; i++) {
        ((uint8_t*)user_mask_ptr)[i / 8] |= 1 << (i % 8);
    }
    /* imitate the Linux kernel implementation
     * See SYSCALL_DEFINE3(sched_getaffinity) */
    return bitmask_size_in_bytes;
}
