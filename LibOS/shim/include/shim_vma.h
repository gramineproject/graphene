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
 * shim_vma.h
 *
 * Definitions of types and functions for VMA bookkeeping.
 */

#ifndef _SHIM_VMA_H_
#define _SHIM_VMA_H_

#include <linux/mman.h>

#include "api.h"
#include "pal.h"
#include "shim_defs.h"
#include "shim_handle.h"
#include "shim_types.h"

#define VMA_COMMENT_LEN 16

struct shim_vma_info {
    void* addr;
    size_t length;
    int prot;
    int flags;
    off_t offset;
    struct shim_handle* file;
    char comment[VMA_COMMENT_LEN];
};

/* MAP_FIXED_NOREPLACE and MAP_SHARED_VALIDATE are fairly new and might not be defined. */
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif // MAP_FIXED_NOREPLACE
#ifndef MAP_SHARED_VALIDATE
#define MAP_SHARED_VALIDATE 0x03
#endif // MAP_SHARED_VALIDATE


/* vma is kept for bookkeeping, but the memory is not actually allocated */
#define VMA_UNMAPPED 0x10000000
/* vma is used internally */
#define VMA_INTERNAL 0x20000000
/* vma is backed by a file and has been protected as writable, so it has to be checkpointed during
 * migration */
#define VMA_TAINTED 0x40000000

static inline PAL_FLG PAL_PROT(int prot, int flags) {
    PAL_FLG pal_prot = 0;

    if (prot & PROT_READ)
        pal_prot |= PAL_PROT_READ;
    if (prot & PROT_WRITE)
        pal_prot |= PAL_PROT_WRITE;
    if (prot & PROT_EXEC)
        pal_prot |= PAL_PROT_EXEC;

    if (flags & MAP_PRIVATE)
        pal_prot |= PAL_PROT_WRITECOPY;

    return pal_prot;
}

int init_vma(void);

/*
 * Bookkeeping a removal of mapped memory. On success returns a temporary VMA pointer in
 * `tmp_vma_ptr`, which must be subsequently freed by calling `bkeep_remove_tmp_vma` - but this
 * should be done only *AFTER* the memory deallocation itself. For example:
 *
 * void* tmp_vma = NULL;
 * if (bkeep_munmap(ptr, len, false, &tmp_vma) < 0) handle_errors();
 * DkVirtualMemoryFree(ptr, len);
 * bkeep_remove_tmp_vma((tmp_vma);
 *
 * Such a way of freeing is needed, so that no other thread will map the same memory in the window
 * between `bkeep_munmap` and `DkVirtualMemoryFree`.
 */
int bkeep_munmap(void* addr, size_t length, bool is_internal, void** tmp_vma_ptr);
void bkeep_remove_tmp_vma(void* vma);

/* Bookkeeping a change to memory protections. */
int bkeep_mprotect(void* addr, size_t length, int prot, bool is_internal);

/*
 * Bookkeeping an allocation of memory at a fixed address. `flags` must contain either MAP_FIXED or
 * MAP_FIXED_NOREPLACE - the former forces bookkeeping and removes any overlapping VMAs, the latter
 * atomically checks for overlaps and fails if one is found.
 */
int bkeep_mmap_fixed(void* addr, size_t length, int prot, int flags, struct shim_handle* file,
                     off_t offset, const char* comment);

/*
 * Bookkeeping an allocation of memory at any address in the range [`bottom_addr`, `top_addr`).
 * The search is top-down, starting from `top_addr` - `length` and returning the first unoccupied
 * area capable of fitting the requested size.
 * Start of bookkept range is returned in `*ret_val_ptr`.
 */
int bkeep_mmap_any_in_range(void* bottom_addr, void* top_addr, size_t length, int prot, int flags,
                            struct shim_handle* file, off_t offset, const char* comment,
                            void** ret_val_ptr);

/* Shorthand for `bkeep_mmap_any_in_range` with the range
 * [`PAL_CB(user_address.start)`, `PAL_CB(user_address.end)`). */
int bkeep_mmap_any(size_t length, int prot, int flags, struct shim_handle* file, off_t offset,
                   const char* comment, void** ret_val_ptr);

/* First tries to bookkeep in the range [`PAL_CB(user_address.start)`, `aslr_addr_top`) and if it
 * fails calls `bkeep_mmap_any`. `aslr_addr_top` is a value randomized on each program run. */
int bkeep_mmap_any_aslr(size_t length, int prot, int flags, struct shim_handle* file, off_t offset,
                        const char* comment, void** ret_val_ptr);

/* Looking up VMA that contains `addr`. If one is found, returns its description in `vma_info`.
 * This function increases ref-count of `vma_info->file` by one (if it is not NULL). */
int lookup_vma(void* addr, struct shim_vma_info* vma_info);

/* Returns true if the whole range [`addr`, `addr` + `length`) is mapped as user memory. */
bool is_in_adjacent_user_vmas(void* addr, size_t length);

/*
 * Dumps all non-internal and mapped VMAs.
 * On success returns 0 and puts the pointer to result array into `*vma_infos` and its length into
 * `*count`. On error returns negated error code.
 * The returned array can be subsequently freed by `free_vma_info_array`.
 */
int dump_all_vmas(struct shim_vma_info** vma_infos, size_t* count);
void free_vma_info_array(struct shim_vma_info* vma_infos, size_t count);

void debug_print_all_vmas(void);

#endif /* _SHIM_VMA_H_ */
