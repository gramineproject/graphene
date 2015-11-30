/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_brk.c
 *
 * Implementation of system call "brk".
 */

#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_table.h>
#include <shim_vma.h>
#include <shim_checkpoint.h>
#include <shim_profile.h>

#include <pal.h>

#include <sys/mman.h>

#define BRK_SIZE           4096

unsigned long brk_max_size = 0;

struct shim_brk_info {
    void * brk_start;
    void * brk_end;
    void * brk_current;
};

static struct shim_brk_info region;

DEFINE_PROFILE_OCCURENCE(brk, memory);
DEFINE_PROFILE_OCCURENCE(brk_count, memory);
DEFINE_PROFILE_OCCURENCE(brk_migrate_count, memory);

void get_brk_region (void ** start, void ** end, void ** current)
{
    master_lock();
    *start   = region.brk_start;
    *end     = region.brk_end;
    *current = region.brk_current;
    master_unlock();
}

int init_brk_region (void)
{
    if (region.brk_start)
        return 0;

    if (!brk_max_size) {
        char brk_cfg[CONFIG_MAX];
        if (root_config &&
            get_config(root_config, "sys.brk.size", brk_cfg, CONFIG_MAX) > 0)
            brk_max_size = atoi(brk_cfg);
        if (!brk_max_size)
            brk_max_size = DEFAULT_BRK_MAX_SIZE;
    }

    void * brk_region = get_unmapped_vma(brk_max_size,
                                         MAP_PRIVATE|MAP_ANONYMOUS);
    void * end_brk_region = NULL;

    // brk region assigned
    brk_region = (void *) DkVirtualMemoryAlloc(brk_region, brk_max_size, 0,
                                    PAL_PROT_READ|PAL_PROT_WRITE);
    if (!brk_region)
        return -ENOMEM;

    ADD_PROFILE_OCCURENCE(brk, brk_max_size);
    INC_PROFILE_OCCURENCE(brk_count);

    end_brk_region = brk_region + BRK_SIZE;

    region.brk_start = brk_region;
    region.brk_end = end_brk_region;
    region.brk_current = brk_region;

    debug("brk area: %p - %p\n", brk_region, end_brk_region);
    debug("brk reserved area: %p - %p\n", end_brk_region,
          brk_region + brk_max_size);

    bkeep_mmap(brk_region, BRK_SIZE, PROT_READ|PROT_WRITE,
               MAP_ANONYMOUS|MAP_PRIVATE, NULL, 0, "[heap]");
    bkeep_mmap(end_brk_region, brk_max_size - BRK_SIZE,
               PROT_READ|PROT_WRITE,
               MAP_ANONYMOUS|MAP_PRIVATE|VMA_UNMAPPED,
               NULL, 0, NULL);

    return 0;
}

int init_brk (void)
{
    master_lock();

    if (!region.brk_start) {
        master_unlock();
        return 0;
    }

    int ret = shim_do_munmap(region.brk_start,
                             region.brk_end - region.brk_start);

    if (ret < 0) {
        master_unlock();
        return ret;
    }

    region.brk_start = region.brk_end = region.brk_current = NULL;

    master_unlock();
    return 0;
}

void * shim_do_brk (void * brk)
{
    master_lock();
    init_brk_region();

    if (!brk) {
unchanged:
        brk = region.brk_current;
        goto out;
    }

    if (brk < region.brk_start)
        goto unchanged;

    if (brk > region.brk_end) {
        if (brk > region.brk_start + brk_max_size)
            goto unchanged;

        void * brk_end = region.brk_end;
        while (brk_end < brk)
            brk_end += BRK_SIZE;

        debug("brk area: %p - %p\n", region.brk_start, brk_end);
        debug("brk reserved area: %p - %p\n", brk_end,
              region.brk_start + brk_max_size);

        bkeep_mmap(region.brk_start, brk_end - region.brk_start,
                   PROT_READ|PROT_WRITE,
                   MAP_ANONYMOUS|MAP_PRIVATE, NULL, 0, "heap");

        region.brk_current = brk;
        region.brk_end = brk_end;
        goto out;
    }
    region.brk_current = brk;

out:
    master_unlock();
    return brk;
}

BEGIN_CP_FUNC(brk)
{
    if (region.brk_start) {
        ADD_CP_FUNC_ENTRY(region.brk_start);
        ADD_CP_ENTRY(ADDR, region.brk_current);
        ADD_CP_ENTRY(SIZE, region.brk_end - region.brk_start);
        assert(brk_max_size);
        ADD_CP_ENTRY(SIZE, brk_max_size);
    }
}
END_CP_FUNC(bek)

BEGIN_RS_FUNC(brk)
{
    region.brk_start   = (void *) GET_CP_FUNC_ENTRY();
    region.brk_current = (void *) GET_CP_ENTRY(ADDR);
    region.brk_end     = region.brk_start + GET_CP_ENTRY(SIZE);
    brk_max_size       = GET_CP_ENTRY(SIZE);

    debug("brk area: %p - %p\n", region.brk_start, region.brk_end);

    unsigned long brk_size = region.brk_end - region.brk_start;

    if (brk_size < brk_max_size) {
        void * brk_region = (void *) DkVirtualMemoryAlloc(region.brk_end,
                                            brk_max_size - brk_size, 0,
                                            PAL_PROT_READ|PAL_PROT_WRITE);
        if (brk_region != region.brk_end)
            return -EACCES;

        ADD_PROFILE_OCCURENCE(brk, brk_max_size - brk_size);
        INC_PROFILE_OCCURENCE(brk_migrate_count);

        debug("brk reserved area: %p - %p\n", region.brk_end,
              region.brk_start + brk_max_size);

        bkeep_mmap(region.brk_end, brk_max_size - brk_size,
                   PROT_READ|PROT_WRITE,
                   MAP_ANONYMOUS|MAP_PRIVATE|VMA_UNMAPPED, NULL, 0,
                   NULL);
    }

    DEBUG_RS("current=%p,region=%p-%p", region.brk_current, region.brk_start,
             region.brk_end);
}
END_RS_FUNC(brk)
