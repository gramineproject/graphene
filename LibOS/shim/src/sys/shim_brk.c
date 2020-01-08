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
 * shim_brk.c
 *
 * Implementation of system call "brk".
 */

#include <sys/mman.h>

#include <pal.h>
#include <shim_checkpoint.h>
#include <shim_internal.h>
#include <shim_profile.h>
#include <shim_table.h>
#include <shim_utils.h>
#include <shim_vma.h>

#define BRK_SIZE 4096

struct shim_brk_info {
    size_t data_segment_size;
    void* brk_start;
    void* brk_end;
    void* brk_current;
};

static struct shim_brk_info region;

DEFINE_PROFILE_OCCURENCE(brk, memory);
DEFINE_PROFILE_OCCURENCE(brk_count, memory);
DEFINE_PROFILE_OCCURENCE(brk_migrate_count, memory);

void get_brk_region(void** start, void** end, void** current) {
    MASTER_LOCK();
    *start   = region.brk_start;
    *end     = region.brk_end;
    *current = region.brk_current;
    MASTER_UNLOCK();
}

int init_brk_region(void* brk_region, size_t data_segment_size) {
    if (region.brk_start)
        return 0;

    data_segment_size     = ALLOC_ALIGN_UP(data_segment_size);
    uint64_t brk_max_size = DEFAULT_BRK_MAX_SIZE;

    if (root_config) {
        char brk_cfg[CONFIG_MAX];
        if (get_config(root_config, "sys.brk.size", brk_cfg, sizeof(brk_cfg)) > 0)
            brk_max_size = parse_int(brk_cfg);
    }

    set_rlimit_cur(RLIMIT_DATA, brk_max_size + data_segment_size);

    int flags        = MAP_PRIVATE | MAP_ANONYMOUS;
    bool brk_on_heap = true;
    const int TRIES  = 10;

    /*
     * Chia-Che 8/24/2017
     * Adding an argument to specify the initial starting address of brk region. The general
     * assumption of Linux is that the brk region should be within
     * [exec-data-end, exec-data-end + 0x2000000).
     */
    if (brk_region) {
        size_t max_brk = 0;
        if (PAL_CB(user_address.end) >= PAL_CB(executable_range.end))
            max_brk = PAL_CB(user_address.end) - PAL_CB(executable_range.end);

        if (PAL_CB(user_address_hole.end) - PAL_CB(user_address_hole.start) > 0) {
            /* XXX: This assumes that we always want brk to be after the hole. */
            brk_region = MAX(brk_region, PAL_CB(user_address_hole.end));
            max_brk =
                MIN(max_brk, (size_t)(PAL_CB(user_address.end) - PAL_CB(user_address_hole.end)));
        }

        /* Check whether the brk region can potentially be located after exec at all. */
        if (brk_max_size <= max_brk) {
            int try;
            for (try = TRIES; try > 0; try--) {
                uint32_t rand = 0;
#if ENABLE_ASLR == 1
                int ret = DkRandomBitsRead(&rand, sizeof(rand));
                if (ret < 0)
                    return -convert_pal_errno(-ret);
                rand %= MIN((size_t)0x2000000,
                            (size_t)(PAL_CB(user_address.end) - brk_region - brk_max_size));
                rand = ALLOC_ALIGN_DOWN(rand);

                if (brk_region + rand + brk_max_size >= PAL_CB(user_address.end))
                    continue;
#else
                /* Without randomization there is no point to retry here */
                if (brk_region + rand + brk_max_size >= PAL_CB(user_address.end))
                    break;
#endif

                struct shim_vma_val vma;
                if (lookup_overlap_vma(brk_region + rand, brk_max_size, &vma) == -ENOENT) {
                    /* Found a place for brk */
                    brk_region += rand;
                    brk_on_heap = false;
                    break;
                }
#if !(ENABLE_ASLR == 1)
                /* Without randomization, try memory directly after the overlapping block */
                brk_region = vma.addr + vma.length;
#endif
            }
        }
    }

    if (brk_on_heap) {
        brk_region = bkeep_unmapped_heap(brk_max_size, PROT_READ | PROT_WRITE, flags | VMA_UNMAPPED,
                                         NULL, 0, "brk");
        if (!brk_region) {
            return -ENOMEM;
        }
    } else {
        /*
         * Create the bookkeeping before allocating the brk region. The bookkeeping should never
         * fail because we've already confirmed the availability.
         */
        if (bkeep_mmap(brk_region, brk_max_size, PROT_READ | PROT_WRITE, flags | VMA_UNMAPPED, NULL,
                       0, "brk") < 0)
            BUG();
    }

    void* end_brk_region = NULL;

    /* Allocate the whole brk region */
    void* ret =
        (void*)DkVirtualMemoryAlloc(brk_region, brk_max_size, 0, PAL_PROT_READ | PAL_PROT_WRITE);

    /* Checking if the PAL call succeeds. */
    if (!ret) {
        bkeep_munmap(brk_region, brk_max_size, flags);
        return -ENOMEM;
    }

    ADD_PROFILE_OCCURENCE(brk, brk_max_size);
    INC_PROFILE_OCCURENCE(brk_count);

    end_brk_region = brk_region + BRK_SIZE;

    region.data_segment_size = data_segment_size;
    region.brk_start         = brk_region;
    region.brk_end           = end_brk_region;
    region.brk_current       = brk_region;

    debug("brk area: %p - %p\n", brk_region, end_brk_region);
    debug("brk reserved area: %p - %p\n", end_brk_region, brk_region + brk_max_size);

    /*
     * Create another bookkeeping for the current brk region. The remaining space will be marked as
     * unmapped so that the library OS can reuse the space for other purpose.
     */
    if (bkeep_mmap(brk_region, BRK_SIZE, PROT_READ | PROT_WRITE, flags, NULL, 0, "brk") < 0)
        BUG();

    return 0;
}

int reset_brk(void) {
    MASTER_LOCK();

    if (!region.brk_start) {
        MASTER_UNLOCK();
        return 0;
    }

    int ret = shim_do_munmap(region.brk_start, region.brk_end - region.brk_start);

    if (ret < 0) {
        MASTER_UNLOCK();
        return ret;
    }

    region.brk_start = region.brk_end = region.brk_current = NULL;

    MASTER_UNLOCK();
    return 0;
}

void* shim_do_brk(void* brk) {
    MASTER_LOCK();

    if (init_brk_region(NULL, 0) < 0) {  // If brk is never initialized, assume no executable
        debug("Failed to initialize brk!\n");
        brk = NULL;
        goto out;
    }

    if (!brk) {
    unchanged:
        brk = region.brk_current;
        goto out;
    }

    if (brk < region.brk_start)
        goto unchanged;

    if (brk > region.brk_end) {
        uint64_t rlim_data = get_rlimit_cur(RLIMIT_DATA);

        // Check if there is enough space within the system limit
        if (rlim_data < region.data_segment_size) {
            brk = NULL;
            goto out;
        }

        uint64_t brk_max_size = rlim_data - region.data_segment_size;

        if (brk > region.brk_start + brk_max_size)
            goto unchanged;

        void* brk_end = region.brk_end;
        while (brk_end < brk)
            brk_end += BRK_SIZE;

        debug("brk area: %p - %p\n", region.brk_start, brk_end);
        debug("brk reserved area: %p - %p\n", brk_end, region.brk_start + brk_max_size);

        bkeep_mmap(region.brk_start, brk_end - region.brk_start, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE, NULL, 0, "brk");

        region.brk_current = brk;
        region.brk_end     = brk_end;
        goto out;
    }
    region.brk_current = brk;

out:
    MASTER_UNLOCK();
    return brk;
}

BEGIN_CP_FUNC(brk) {
    __UNUSED(obj);
    __UNUSED(size);
    __UNUSED(objp);
    if (region.brk_start) {
        ADD_CP_FUNC_ENTRY((ptr_t)region.brk_start);
        ADD_CP_ENTRY(ADDR, region.brk_current);
        ADD_CP_ENTRY(SIZE, region.brk_end - region.brk_start);
        ADD_CP_ENTRY(SIZE, region.data_segment_size);
    }
}
END_CP_FUNC(bek)

BEGIN_RS_FUNC(brk) {
    __UNUSED(rebase);
    region.brk_start         = (void*)GET_CP_FUNC_ENTRY();
    region.brk_current       = (void*)GET_CP_ENTRY(ADDR);
    region.brk_end           = region.brk_start + GET_CP_ENTRY(SIZE);
    region.data_segment_size = GET_CP_ENTRY(SIZE);

    debug("brk area: %p - %p\n", region.brk_start, region.brk_end);

    size_t brk_size    = region.brk_end - region.brk_start;
    uint64_t rlim_data = get_rlimit_cur(RLIMIT_DATA);
    assert(rlim_data > region.data_segment_size);
    uint64_t brk_max_size = rlim_data - region.data_segment_size;

    if (brk_size < brk_max_size) {
        void* alloc_addr  = region.brk_end;
        size_t alloc_size = brk_max_size - brk_size;
        struct shim_vma_val vma;

        if (!lookup_overlap_vma(alloc_addr, alloc_size, &vma)) {
            /* if memory are already allocated here, adjust RLIMIT_DATA */
            alloc_size = vma.addr - alloc_addr;
            set_rlimit_cur(RLIMIT_DATA, (uint64_t)brk_size + alloc_size + region.data_segment_size);
        }

        int ret = bkeep_mmap(alloc_addr, alloc_size, PROT_READ | PROT_WRITE,
                             MAP_ANONYMOUS | MAP_PRIVATE | VMA_UNMAPPED, NULL, 0, "brk");
        if (ret < 0)
            return ret;

        void* ptr = DkVirtualMemoryAlloc(alloc_addr, alloc_size, 0, PAL_PROT_READ | PAL_PROT_WRITE);
        __UNUSED(ptr);
        assert(ptr == alloc_addr);
        ADD_PROFILE_OCCURENCE(brk, alloc_size);
        INC_PROFILE_OCCURENCE(brk_migrate_count);

        debug("brk reserved area: %p - %p\n", alloc_addr, alloc_addr + alloc_size);
    }

    DEBUG_RS("current=%p,region=%p-%p", region.brk_current, region.brk_start, region.brk_end);
}
END_RS_FUNC(brk)
