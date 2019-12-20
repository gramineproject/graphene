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
 * shim_vma.h
 *
 * Definitions of types and functions for VMA bookkeeping.
 */

#ifndef _SHIM_VMA_H_
#define _SHIM_VMA_H_

#include <api.h>
#include <linux/mman.h>
#include <list.h>
#include <pal.h>
#include <shim_defs.h>
#include <shim_handle.h>
#include <shim_types.h>

struct shim_handle;

#define VMA_COMMENT_LEN 16

/*
 * struct shim_vma_val is the published version of struct shim_vma
 * (struct shim_vma is defined in bookkeep/shim_vma.c).
 */
struct shim_vma_val {
    void* addr;
    size_t length;
    int prot;
    int flags;
    off_t offset;
    struct shim_handle* file;
    char comment[VMA_COMMENT_LEN];
};

static inline void free_vma_val_array(struct shim_vma_val* vmas, size_t count) {
    for (size_t i = 0; i < count; i++) {
        /* need to release the file handle */
        if (vmas[i].file)
            put_handle(vmas[i].file);
    }

    free(vmas);
}

/* an additional flag */
#define VMA_UNMAPPED 0x10000000 /* vma is kept for bookkeeping, but the memory is not actually
                                   allocated */
#define VMA_INTERNAL 0x20000000 /* vma is used internally */

#define VMA_TAINTED 0x40000000 /* vma has been protected as writable, so it has to be checkpointed
                                  during migration */

#define VMA_CP 0x80000000 /* vma is used for dumping checkpoint data */

#define VMA_TYPE(flags) ((flags) & (VMA_INTERNAL | VMA_CP))

/*
 * We distinguish checkpoint VMAs from user VMAs and other internal VMAs,
 * to prevent corrupting internal data when creating processes.
 */
#define CP_VMA_FLAGS (MAP_PRIVATE | MAP_ANONYMOUS | VMA_INTERNAL | VMA_CP)

#define NEED_MIGRATE_MEMORY(vma) \
    (((vma)->flags & VMA_TAINTED || !(vma)->file) && !((vma)->flags & VMA_UNMAPPED))

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

/* Bookkeeping mmap() system call */
int bkeep_mmap(void* addr, size_t length, int prot, int flags, struct shim_handle* file,
               off_t offset, const char* comment);

/* Bookkeeping munmap() system call */
int bkeep_munmap(void* addr, size_t length, int flags);

/* Bookkeeping mprotect() system call */
int bkeep_mprotect(void* addr, size_t length, int prot, int flags);

/* Looking up VMA that contains [addr, length) */
int lookup_vma(void* addr, struct shim_vma_val* vma);

/* Looking up VMA that overlaps with [addr, length) */
int lookup_overlap_vma(void* addr, size_t length, struct shim_vma_val* vma);

/* True if [addr, addr+length) is found in one VMA (valid memory region) */
bool is_in_adjacent_vmas(void* addr, size_t length);

/*
 * Looking for an unmapped space and then adding the corresponding bookkeeping
 * (more info in bookkeep/shim_vma.c).
 *
 * Note: the first argument is "top_addr" because the search is top-down.
 */
void* bkeep_unmapped(void* top_addr, void* bottom_addr, size_t length, int prot, int flags,
                     off_t offset, const char* comment);

static inline void* bkeep_unmapped_any(size_t length, int prot, int flags,
                                       off_t offset, const char* comment) {
    return bkeep_unmapped(PAL_CB(user_address.end), PAL_CB(user_address.start), length, prot, flags,
                          offset, comment);
}

void* bkeep_unmapped_heap(size_t length, int prot, int flags, struct shim_handle* file,
                          off_t offset, const char* comment);

/*
 * Dumping all *non-internal* VMAs into a user-allocated buffer ("max_count" is
 * the maximal number of entries in the buffer). Return number of filled entries
 * if succeeded, or -EOVERFLOW if the buffer is too small.
 */
int dump_all_vmas(struct shim_vma_val* vmas, size_t max_count);

/* Debugging */
void debug_print_vma_list(void);

#endif /* _SHIM_VMA_H_ */
