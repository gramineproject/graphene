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
 * shim_getrlimit.c
 *
 * Implementation of system call "getrlimit" and "setrlimit".
 */

#include <shim_internal.h>
#include <shim_checkpoint.h>
#include <shim_table.h>
#include <shim_utils.h>
#include <shim_vma.h>

#include <asm/resource.h>


/*
 * TODO: implement actual limitation on each resource.
 *
 * The current behavor(i.e. sys_stack_size, brk_max_size) may be subject
 * to be fixed.
 */

#define _STK_LIM        (8*1024*1024)
#define MAX_THREADS     (0x3fffffff / 2)
#define DEFAULT_MAX_FDS (1024)
#define MAX_MAX_FDS     (65536) /* 4096: Linux initial value */
#define MLOCK_LIMIT     (64*1024)
#define MQ_BYTES_MAX    819200

struct __kernel_rlimit __rlim[RLIM_NLIMITS] __attribute_migratable = {
    [RLIMIT_CPU]        = {   RLIM_INFINITY, RLIM_INFINITY },
    [RLIMIT_FSIZE]      = {   RLIM_INFINITY, RLIM_INFINITY },
    [RLIMIT_DATA]       = {   RLIM_INFINITY, RLIM_INFINITY },
    [RLIMIT_STACK]      = {        _STK_LIM, RLIM_INFINITY },
    [RLIMIT_CORE]       = {               0, RLIM_INFINITY },
    [RLIMIT_RSS]        = {   RLIM_INFINITY, RLIM_INFINITY },
    [RLIMIT_NPROC]      = {     MAX_THREADS,   MAX_THREADS },
    [RLIMIT_NOFILE]     = { DEFAULT_MAX_FDS,   MAX_MAX_FDS },
    [RLIMIT_MEMLOCK]    = {     MLOCK_LIMIT,   MLOCK_LIMIT },
    [RLIMIT_AS]         = {   RLIM_INFINITY, RLIM_INFINITY },
    [RLIMIT_LOCKS]      = {   RLIM_INFINITY, RLIM_INFINITY },
    /* [RLIMIT_SIGPENDING] = [RLIMIT_NPROC] for initial value */
    [RLIMIT_SIGPENDING] = {     MAX_THREADS,   MAX_THREADS },
    [RLIMIT_MSGQUEUE]   = {    MQ_BYTES_MAX,  MQ_BYTES_MAX },
    [RLIMIT_NICE]       = {               0,             0 },
    [RLIMIT_RTPRIO]     = {               0,             0 },
    [RLIMIT_RTTIME]     = {   RLIM_INFINITY, RLIM_INFINITY },
};

int shim_do_getrlimit (int resource, struct __kernel_rlimit * rlim)
{
    if (resource < 0 || RLIM_NLIMITS <= resource)
        return -EINVAL;

    switch (resource) {
        case RLIMIT_STACK:
            rlim->rlim_cur = sys_stack_size;
            rlim->rlim_max = sys_stack_size;
            return 0;

        case RLIMIT_DATA:
            rlim->rlim_cur = brk_max_size;
            rlim->rlim_max = brk_max_size;
            return 0;

        default:
            *rlim = __rlim[resource];
            return 0;
    }
}

int shim_do_setrlimit (int resource, struct __kernel_rlimit * rlim)
{
    if (resource < 0 || RLIM_NLIMITS <= resource)
        return -EINVAL;
    if (!rlim || test_user_memory(rlim, sizeof(*rlim), false))
        return -EFAULT;
    if (rlim->rlim_cur > rlim->rlim_max)
        return -EINVAL;

    if (rlim->rlim_cur > __rlim->rlim_max)
        return -EINVAL;
    switch (resource) {
        case RLIMIT_STACK:
            sys_stack_size = rlim->rlim_cur;
            return 0;

        default:
            __rlim[resource].rlim_cur = rlim->rlim_cur;
            return 0;
    }
}
