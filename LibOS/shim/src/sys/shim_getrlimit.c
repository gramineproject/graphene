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
#include <shim_table.h>
#include <shim_utils.h>
#include <shim_vma.h>

#include <asm/resource.h>

unsigned int max_fds = DEFAULT_MAX_FDS;

int shim_do_getrlimit (int resource, struct __kernel_rlimit * rlim)
{
    switch (resource) {
        case RLIMIT_NOFILE:
            rlim->rlim_cur = max_fds;
            rlim->rlim_max = MAX_MAX_FDS;
            return 0;

        case RLIMIT_RSS:
            rlim->rlim_cur = RLIM_INFINITY;
            rlim->rlim_max = RLIM_INFINITY;
            return 0;

        case RLIMIT_AS:
            rlim->rlim_cur = RLIM_INFINITY;
            rlim->rlim_max = RLIM_INFINITY;
            return 0;

        case RLIMIT_STACK:
            rlim->rlim_cur = sys_stack_size;
            rlim->rlim_max = sys_stack_size;
            return 0;

        case RLIMIT_DATA:
            rlim->rlim_cur = brk_max_size;
            rlim->rlim_max = brk_max_size;
            return 0;

        default:
            return -ENOSYS;
    }
}

int shim_do_setrlimit (int resource, struct __kernel_rlimit * rlim)
{
    switch (resource) {
        case RLIMIT_NOFILE:
            if (rlim->rlim_cur > MAX_MAX_FDS)
                return -EINVAL;
            max_fds = rlim->rlim_cur;
            return 0;

        case RLIMIT_STACK:
            sys_stack_size = rlim->rlim_cur;
            return 0;

        default:
            return -ENOSYS;
    }
}
