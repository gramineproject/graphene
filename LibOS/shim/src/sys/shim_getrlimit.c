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
 * shim_getrlimit.c
 *
 * Implementation of system call "getrlimit" and "setrlimit".
 */

#include <asm/resource.h>
#include <shim_checkpoint.h>
#include <shim_internal.h>
#include <shim_table.h>
#include <shim_utils.h>
#include <shim_vma.h>

/*
 * TODO: implement actual limitation on each resource.
 *
 * The current behavor(i.e. sys_stack_size, brk_max_size) may be subject
 * to be fixed.
 */

#define MAX_THREADS     (0x3fffffff / 2)
#define DEFAULT_MAX_FDS (1024)
#define MAX_MAX_FDS     (65536) /* 4096: Linux initial value */
#define MLOCK_LIMIT     (64 * 1024)
#define MQ_BYTES_MAX    819200

static struct __kernel_rlimit64 __rlim[RLIM_NLIMITS] __attribute_migratable = {
    [RLIMIT_CPU]     = {RLIM_INFINITY, RLIM_INFINITY},
    [RLIMIT_FSIZE]   = {RLIM_INFINITY, RLIM_INFINITY},
    [RLIMIT_DATA]    = {RLIM_INFINITY, RLIM_INFINITY},
    [RLIMIT_STACK]   = {DEFAULT_SYS_STACK_SIZE, RLIM_INFINITY},
    [RLIMIT_CORE]    = {0, RLIM_INFINITY},
    [RLIMIT_RSS]     = {RLIM_INFINITY, RLIM_INFINITY},
    [RLIMIT_NPROC]   = {MAX_THREADS, MAX_THREADS},
    [RLIMIT_NOFILE]  = {DEFAULT_MAX_FDS, MAX_MAX_FDS},
    [RLIMIT_MEMLOCK] = {MLOCK_LIMIT, MLOCK_LIMIT},
    [RLIMIT_AS]      = {RLIM_INFINITY, RLIM_INFINITY},
    [RLIMIT_LOCKS]   = {RLIM_INFINITY, RLIM_INFINITY},
    /* [RLIMIT_SIGPENDING] = [RLIMIT_NPROC] for initial value */
    [RLIMIT_SIGPENDING] = {MAX_THREADS, MAX_THREADS},
    [RLIMIT_MSGQUEUE]   = {MQ_BYTES_MAX, MQ_BYTES_MAX},
    [RLIMIT_NICE]       = {0, 0},
    [RLIMIT_RTPRIO]     = {0, 0},
    [RLIMIT_RTTIME]     = {RLIM_INFINITY, RLIM_INFINITY},
};

static struct shim_lock rlimit_lock;

int init_rlimit(void) {
    if (!create_lock(&rlimit_lock)) {
        return -ENOMEM;
    }
    return 0;
}

uint64_t get_rlimit_cur(int resource) {
    assert(resource >= 0 && RLIM_NLIMITS > resource);
    lock(&rlimit_lock);
    uint64_t rlim = __rlim[resource].rlim_cur;
    unlock(&rlimit_lock);
    return rlim;
}

void set_rlimit_cur(int resource, uint64_t rlim) {
    assert(resource >= 0 && RLIM_NLIMITS > resource);
    lock(&rlimit_lock);
    __rlim[resource].rlim_cur = rlim;
    unlock(&rlimit_lock);
}

int shim_do_getrlimit(int resource, struct __kernel_rlimit* rlim) {
    if (resource < 0 || RLIM_NLIMITS <= resource)
        return -EINVAL;
    if (!rlim || test_user_memory(rlim, sizeof(*rlim), true))
        return -EFAULT;

    lock(&rlimit_lock);
    rlim->rlim_cur = __rlim[resource].rlim_cur;
    rlim->rlim_max = __rlim[resource].rlim_max;
    unlock(&rlimit_lock);
    return 0;
}

int shim_do_setrlimit(int resource, struct __kernel_rlimit* rlim) {
    struct shim_thread* cur_thread = get_cur_thread();
    assert(cur_thread);

    if (resource < 0 || RLIM_NLIMITS <= resource)
        return -EINVAL;
    if (!rlim || test_user_memory(rlim, sizeof(*rlim), false))
        return -EFAULT;
    if (rlim->rlim_cur > rlim->rlim_max)
        return -EINVAL;

    lock(&rlimit_lock);
    if (rlim->rlim_max > __rlim[resource].rlim_max && cur_thread->euid) {
        unlock(&rlimit_lock);
        return -EPERM;
    }

    __rlim[resource].rlim_cur = rlim->rlim_cur;
    __rlim[resource].rlim_max = rlim->rlim_max;
    unlock(&rlimit_lock);
    return 0;
}

int shim_do_prlimit64(pid_t pid, int resource, const struct __kernel_rlimit64* new_rlim,
                      struct __kernel_rlimit64* old_rlim) {
    struct shim_thread* cur_thread = get_cur_thread();
    assert(cur_thread);
    int ret = 0;

    // XXX: Do not support setting/getting the rlimit of other processes yet.
    if (pid && pid != (pid_t)cur_thread->tgid)
        return -ENOSYS;

    if (resource < 0 || RLIM_NLIMITS <= resource)
        return -EINVAL;

    if (old_rlim) {
        if (test_user_memory(old_rlim, sizeof(*old_rlim), true))
            return -EFAULT;
    }

    if (new_rlim) {
        if (test_user_memory((void*)new_rlim, sizeof(*new_rlim), false)) {
            ret = -EFAULT;
            goto out;
        }
        if (new_rlim->rlim_cur > new_rlim->rlim_max) {
            ret = -EINVAL;
            goto out;
        }
    }

    lock(&rlimit_lock);

    if (new_rlim) {
        if (new_rlim->rlim_max > __rlim[resource].rlim_max && cur_thread->euid) {
            ret = -EPERM;
            goto out;
        }
    }

    if (old_rlim)
        *old_rlim = __rlim[resource];
    if (new_rlim)
        __rlim[resource] = *new_rlim;

out:
    unlock(&rlimit_lock);
    return ret;
}
