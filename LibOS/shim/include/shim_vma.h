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
 * shim_vma.h
 *
 * Definitions of types and functions for VMA bookkeeping.
 */

#ifndef _SHIM_VMA_H_
#define _SHIM_VMA_H_

#include <shim_types.h>
#include <shim_defs.h>
#include <shim_handle.h>

#include <pal.h>
#include <linux_list.h>

#include <asm/mman.h>

struct shim_handle;

#define VMA_COMMENT_LEN     16

struct shim_vma {
    REFTYPE                 ref_count;
    void *                  addr;
    int                     length;
    int                     prot;
    int                     flags;
    int                     offset;
    struct shim_handle *    file;
    struct list_head        list;
    char                    comment[VMA_COMMENT_LEN];
};

/* an additional flag */
#define VMA_UNMAPPED 0x10000000   /* vma is kept for bookkeeping, but the
                                     memory is not actually allocated */
#define VMA_INTERNAL 0x20000000

#define VMA_TAINTED  0x40000000   /* vma has been protected as writeable,
                                     so it has to be checkpointed during
                                     migration */

#define NEED_MIGRATE_MEMORY(vma)                                \
        (((vma)->flags & VMA_TAINTED || !(vma)->file) &&        \
        !((vma)->flags & VMA_UNMAPPED))

#define NEED_MIGRATE_MEMORY_IF_GIPC(vma)                        \
        (!((vma)->flags & VMA_UNMAPPED) &&                      \
         !(!(vma)->prot && !((vma)->flags & VMA_TAINTED)) &&    \
         !((vma)->file && ((vma)->flags & MAP_SHARED)))

static inline PAL_FLG PAL_PROT (int prot, int flags)
{
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

int init_vma (void);

/* Bookkeeping mmap() system call */
int bkeep_mmap (void * addr, int length, int prot, int flags,
                struct shim_handle * file, int offset, const char * comment);

/* Bookkeeping munmap() system call */
int bkeep_munmap (void * addr, int length, const int * flags);

/* Bookkeeping mprotect() system call */
int bkeep_mprotect (void * addr, int length, int prot, const int * flags);

/* Get vma bookkeeping handle */
void get_vma (struct shim_vma * vma);
void put_vma (struct shim_vma * vma);

int lookup_supervma (const void * addr, int len, struct shim_vma ** vma);
int lookup_overlap_vma (const void * addr, int len, struct shim_vma ** vma);

struct shim_vma * next_vma (struct shim_vma * vma);

void * get_unmapped_vma (int len, int flags);
void * get_unmapped_vma_for_cp (int len);

int dump_all_vmas (struct shim_thread * thread, char * buf, int size);

void unmap_all_vmas (void);

/* Debugging */
void debug_print_vma_list (void);

void print_vma_hash (struct shim_vma * vma, void * addr, int len,
                     bool force_protect);

/* Constants */
extern unsigned long mem_max_npages;
extern unsigned long brk_max_size;
extern unsigned long sys_stack_size;

#endif /* _SHIM_VMA_H_ */
