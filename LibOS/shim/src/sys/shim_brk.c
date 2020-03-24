/* Copyright (C) 2014 Stony Brook University
   Copyright (C) 2020 Invisible Things Lab
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
#include <shim_table.h>
#include <shim_utils.h>
#include <shim_vma.h>

static struct {
    size_t data_segment_size;
    void* brk_start;
    void* brk_end;
} brk_region = { .data_segment_size = -1ul };

static struct shim_lock brk_lock;

int init_brk_region(void* brk_start, size_t data_segment_size) {
    size_t brk_max_size = DEFAULT_BRK_MAX_SIZE;
    data_segment_size = ALLOC_ALIGN_UP(data_segment_size);

    if (root_config) {
        char brk_cfg[CONFIG_MAX];
        if (get_config(root_config, "sys.brk.max_size", brk_cfg, sizeof(brk_cfg)) > 0)
            brk_max_size = parse_int(brk_cfg);
    }

    if ((uintptr_t)PAL_CB(user_address.end) < brk_max_size
            || (uintptr_t)PAL_CB(user_address.end) - brk_max_size <= (uintptr_t)brk_start) {
        debug("There is not enough space for brk. Consider reducing sys.brk.max_size.\n");
        /* Not reporting an error here - we just do not have brk. Let the app live without it. */
        return 0;
    }

    if (!create_lock(&brk_lock)) {
        debug("Creating brk_lock failed!\n");
        return -ENOMEM;
    }

    size_t offset = 0;
#if ENABLE_ASLR == 1
    int ret = DkRandomBitsRead(&offset, sizeof(offset));
    if (ret < 0) {
        return -convert_pal_errno(-ret);
    }
    /* Linux randomizes brk at offset from 0 to 0x2000000 from main executable data section
     * https://elixir.bootlin.com/linux/v5.6.3/source/arch/x86/kernel/process.c#L914 */
    offset %= MIN((size_t)0x2000000,
                  (size_t)((char*)PAL_CB(user_address.end) - brk_max_size - (char*)brk_start));
    offset = ALLOC_ALIGN_DOWN(offset);
#endif

    brk_region.brk_start = (char*)brk_start + offset;
    brk_region.brk_end = brk_region.brk_start;
    brk_region.data_segment_size = data_segment_size;

    set_rlimit_cur(RLIMIT_DATA, brk_max_size + data_segment_size);


    return 0;
}

void* shim_do_brk(void* brk) {
    size_t size = 0;
    void* brk_aligned = ALLOC_ALIGN_UP_PTR(brk);

    if (__atomic_load_n(&brk_region.data_segment_size, __ATOMIC_RELAXED) == -1ul) {
        /* We do not have brk. */
        return NULL;
    }

    lock(&brk_lock);

    void* end_aligned = ALLOC_ALIGN_UP_PTR(brk_region.brk_end);

    if (brk < brk_region.brk_start) {
        goto out;
    } else if (brk <= end_aligned) {
        size = (char*)end_aligned - (char*)brk_aligned;

        if (size) {
            void* tmp_vma = NULL;
            if (bkeep_munmap(brk_aligned, size, /*is_internal=*/false, &tmp_vma) < 0) {
                goto out;
            }

            DkVirtualMemoryFree(brk_aligned, size);

            bkeep_remove_tmp_vma(tmp_vma);
        }

        brk_region.brk_end = brk;
        goto out;
    }

    uint64_t rlim_data = get_rlimit_cur(RLIMIT_DATA);
    size = (char*)brk_aligned - (char*)brk_region.brk_start;

    if (rlim_data < brk_region.data_segment_size
            || rlim_data - brk_region.data_segment_size < size) {
        goto out;
    }

    size = (char*)brk_aligned - (char*)end_aligned;
    if (size) {
        if (bkeep_mmap_fixed(end_aligned, size, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                             NULL, 0, "heap") < 0) {
            goto out;
        }

        if (!DkVirtualMemoryAlloc(end_aligned, size, 0, PAL_PROT_READ | PAL_PROT_WRITE)) {
            void* tmp_vma = NULL;
            if (bkeep_munmap(end_aligned, size, /*is_internal=*/false, &tmp_vma) < 0) {
                debug("[brk] Failed to remove bookkeeped memory that was not allocated at %p-%p!\n",
                      end_aligned, (char*)end_aligned + size);
                BUG();
            }
            bkeep_remove_tmp_vma(tmp_vma);
            goto out;
        }
    }

    brk_region.brk_end = brk;

out:
    brk = brk_region.brk_end;
    unlock(&brk_lock);
    return brk;
}

BEGIN_CP_FUNC(brk) {
    __UNUSED(obj);
    __UNUSED(size);
    __UNUSED(objp);
    ADD_CP_FUNC_ENTRY((ptr_t)brk_region.brk_start);
    ADD_CP_ENTRY(SIZE, (char*)brk_region.brk_end - (char*)brk_region.brk_start);
    ADD_CP_ENTRY(SIZE, brk_region.data_segment_size);
}
END_CP_FUNC(brk)

BEGIN_RS_FUNC(brk) {
    __UNUSED(rebase);
    brk_region.brk_start         = (void*)GET_CP_FUNC_ENTRY();
    brk_region.brk_end           = (char*)brk_region.brk_start + GET_CP_ENTRY(SIZE);
    brk_region.data_segment_size = GET_CP_ENTRY(SIZE);

    debug("migrated brk area: %p - %p\n", brk_region.brk_start, brk_region.brk_end);

}
END_RS_FUNC(brk)
