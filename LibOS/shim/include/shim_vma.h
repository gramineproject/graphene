/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Invisible Things Lab
 */

/*
 * Definitions of types and functions for VMA bookkeeping.
 */

#ifndef _SHIM_VMA_H_
#define _SHIM_VMA_H_

#include <linux/mman.h>

#include "api.h"
#include "avl_tree.h"
#include "pal.h"
#include "shim_defs.h"
#include "shim_handle.h"
#include "shim_types.h"

#define VMA_COMMENT_LEN 16

/* TODO: split flags into internal (Graphene) and Linux; also to consider: completely remove Linux
 * flags - we only need MAP_SHARED/MAP_PRIVATE and possibly MAP_STACK/MAP_GROWSDOWN */
struct shim_vma {
    uintptr_t begin;
    uintptr_t end;
    int prot;
    int flags;
    struct shim_handle* file;
    off_t offset; // offset inside `file`, where `begin` starts
    union {
        /* If this `vma` is used, it is included in `vma_tree` using this node. */
        struct avl_tree_node tree_node;
        /* Otherwise it might be cached in per thread vma cache, or might be on a temporary list
         * of to-be-freed vmas (used by _vma_bkeep_remove). Such lists use the field below. */
        struct shim_vma* next_free;
    };
    char comment[VMA_COMMENT_LEN];
};

/* Public version of shim_vma, used when we want to copy out the vma and use it without holding
 * the VMA list lock. */
struct shim_vma_info {
    void* addr;
    size_t length;
    int prot;  // memory protection flags: PROT_*
    int flags; // MAP_* and VMA_*
    struct shim_handle* file;
    off_t file_offset;
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

int init_vma(void);

typedef void (*traverse_visitor)(struct shim_vma* vma, void* visitor_arg);

/*
 * Walks through all VMAs which contain at least one byte from the [begin, end) range.
 *
 * Returns whether the traversed range was continuously covered by VMAs. This is useful for
 * emulating errors in memory management syscalls.
 *
 * `visitor` must be as simple as possible, because it's called with the VMA lock held.
 */
bool traverse_vmas_in_range(uintptr_t begin, uintptr_t end, traverse_visitor visitor,
                            void* visitor_arg);

/*
 * Bookkeeping a removal of mapped memory. On success returns a temporary VMA pointer in
 * `tmp_vma_ptr`, which must be subsequently freed by calling `bkeep_remove_tmp_vma` - but this
 * should be done only *AFTER* the memory deallocation itself. For example:
 *
 * void* tmp_vma = NULL;
 * if (bkeep_munmap(ptr, len, is_internal, &tmp_vma) < 0) {
 *     handle_errors();
 * }
 * DkVirtualMemoryFree(ptr, len);
 * bkeep_remove_tmp_vma(tmp_vma);
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
int dump_all_vmas(struct shim_vma_info** vma_infos, size_t* count, bool include_unmapped);
void free_vma_info_array(struct shim_vma_info* vma_infos, size_t count);

void debug_print_all_vmas(void);

#endif /* _SHIM_VMA_H_ */
