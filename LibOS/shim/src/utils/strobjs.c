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
 * shim_syscalls.c
 *
 * This file contain functions to allocate / free a fixed-size string object.
 */

#include <shim_internal.h>
#include <shim_utils.h>

static LOCKTYPE str_mgr_lock;

#define system_lock()       lock(str_mgr_lock)
#define system_unlock()     unlock(str_mgr_lock)

#define STR_MGR_ALLOC  32
#define PAGE_SIZE      allocsize

#define OBJ_TYPE struct shim_str
#include "memmgr.h"

static MEM_MGR str_mgr = NULL;

int init_str_mgr (void)
{
    create_lock(str_mgr_lock);
    str_mgr = create_mem_mgr(init_align_up(STR_MGR_ALLOC));
    return 0;
}

struct shim_str * get_str_obj (void)
{
    return get_mem_obj_from_mgr_enlarge(str_mgr,
                                        size_align_up(STR_MGR_ALLOC));
}

int free_str_obj (struct shim_str * str)
{
    if (str == NULL)
        return -ENOMEM;

    if (MEMORY_MIGRATED(str)) {
        memset(str, 0, sizeof(struct shim_str));
        return 0;
    }

    free_mem_obj_to_mgr(str_mgr, str);
    return 0;
}
