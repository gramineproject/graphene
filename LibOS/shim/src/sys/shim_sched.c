/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * shim_sched.c
 *
 * Implementation of system calls "sched_yield", "setpriority", "getpriority",
 * "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler",
 * "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval",
 * "sched_setaffinity", "sched_getaffinity", "getcpu".
 */

#include <errno.h>
#include <linux/resource.h>
#include <linux/sched.h>

#include "api.h"
#include "pal.h"
#include "shim_internal.h"
#include "shim_table.h"
#include "shim_thread.h"

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

/* dummy implementation: always return the default nice value of 20 */
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
    if (policy != SCHED_NORMAL && policy != SCHED_BATCH &&
            policy != SCHED_IDLE && /* non-real-time */
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
    if (policy != SCHED_NORMAL && policy != SCHED_BATCH &&
            policy != SCHED_IDLE && /* non-real-time */
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
    if (policy != SCHED_NORMAL && policy != SCHED_BATCH &&
            policy != SCHED_IDLE && /* non-real-time */
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

static int check_affinity_params(bool is_getaffinity,
                                 int ncpus, 
                                 size_t cpumask_size,
                                 __kernel_cpu_set_t* user_mask_ptr) {
    /* Check that user_mask_ptr is valid; if not, should return -EFAULT */
    if (test_user_memory(user_mask_ptr, cpumask_size, true))
        return -EFAULT;

    /* Linux kernel bitmap is based on long. So according to its
     * implementation, round up the result to sizeof(long) */
    size_t bitmask_long_count    = (ncpus + sizeof(long) * 8 - 1) / (sizeof(long) * 8);
    size_t bitmask_size_in_bytes = bitmask_long_count * sizeof(long);
    
    /* Return -EINVAL for sched_getaffinity() when cpumask_size is 
     * smaller than size of aafinity mask used by kernel.
     * Refer: https://man7.org/linux/man-pages/man2/sched_getaffinity.2.html -EINVAL error notes.
     */
    if (is_getaffinity && (cpumask_size < bitmask_size_in_bytes)) {
        debug("size of cpumask in affinity syscall must be %lu but supplied cpumask is only %lu\n",
               bitmask_size_in_bytes,
               cpumask_size);
        return -EINVAL;
    }

    /* Linux kernel also rejects non-natural size */
    if (cpumask_size & (sizeof(long) - 1))
        return -EINVAL;

    return bitmask_size_in_bytes;
}

int shim_do_sched_setaffinity(pid_t pid, size_t cpusetsize, __kernel_cpu_set_t* user_mask_ptr) {
    int ret;
    PAL_HANDLE pal_thread = NULL;
    struct shim_thread* thread;
    int ncpus = PAL_CB(cpu_info.cpu_num);

    if (pid) {
        thread = lookup_thread(pid);
    } else {
        thread = get_cur_thread();
        get_thread(thread);
    }

    if (!thread)
        return -ESRCH;

    pal_thread = thread->pal_handle;
    if (!pal_thread)
        return -ESRCH;

    put_thread(thread);

    int bitmask_size_in_bytes = check_affinity_params(false, ncpus, cpusetsize, user_mask_ptr);
    if (bitmask_size_in_bytes < 0)
        return bitmask_size_in_bytes;

    ret = DkThreadSetCpuAffinity(pal_thread, bitmask_size_in_bytes, user_mask_ptr);
    if (ret < 0)
        return -convert_pal_errno(-ret);

    return 0;
}

int shim_do_sched_getaffinity(pid_t pid, size_t cpusetsize, __kernel_cpu_set_t* user_mask_ptr) {
    int ret;
    PAL_HANDLE pal_thread = NULL;
    struct shim_thread* thread;
    int ncpus = PAL_CB(cpu_info.cpu_num);

    if (pid) {
        thread = lookup_thread(pid);
    } else {
        thread = get_cur_thread();
        get_thread(thread);
    }

    if (!thread)
        return -ESRCH;

    pal_thread = thread->pal_handle;
    if (!pal_thread)
        return -ESRCH;

    put_thread(thread);

    int bitmask_size_in_bytes = check_affinity_params(true, ncpus, cpusetsize, user_mask_ptr);
    if (bitmask_size_in_bytes < 0)
        return bitmask_size_in_bytes;

    ret = DkThreadGetCpuAffinity(pal_thread, bitmask_size_in_bytes, user_mask_ptr);
    if (ret < 0)
      return -convert_pal_errno(-ret);

    /* on success, imitate Linux kernel implementation: see SYSCALL_DEFINE3(sched_getaffinity) */
    return bitmask_size_in_bytes;
}

/* dummy implementation: always return cpu0  */
int shim_do_getcpu(unsigned* cpu, unsigned* node, struct getcpu_cache* unused) {
    __UNUSED(unused);

    if (cpu) {
        if (test_user_memory(cpu, sizeof(*cpu), /*write=*/true)) {
            return -EFAULT;
        }
        *cpu = 0;
    }

    if (node) {
        if (test_user_memory(node, sizeof(*node), /*write=*/true)) {
            return -EFAULT;
        }
        *node = 0;
    }

    return 0;
}
