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
 * slab.c
 *
 * This file contains implementation of PAL's internal memory allocator.
 */

#include "pal_defs.h"
#include "pal_internal.h"
#include "pal_debug.h"
#include "linux_list.h"
#include "api.h"

static struct mutex_handle slab_mgr_lock = MUTEX_HANDLE_INIT;

#define system_lock()   _DkMutexLock(&slab_mgr_lock)
#define system_unlock() _DkMutexUnlock(&slab_mgr_lock)

#if STATIC_SLAB == 1
# define POOL_SIZE 4096 * 20480
static char mem_pool[POOL_SIZE];
static char *bump = mem_pool;
static char *mem_pool_end = &mem_pool[POOL_SIZE];
#else
# define PAGE_SIZE 4096
#endif

static inline void * __malloc (size_t size)
{
#if STATIC_SLAB == 1
    void * addr = (void *) bump;

    bump += size;
    if (bump >= mem_pool_end) {
        printf("Pal out of internal memory!\n");
        DkProcessExit(-1);
        return NULL;
    }
#else
    void * addr = NULL;
    _DkVirtualMemory(&addr, size, 0, PAL_PROT_READ|PAL_PROT_WRITE);
#endif /* STATIC_SLAB != 1 */

    return addr;
}

#define system_malloc(size) __malloc(size)

static inline void __free (void * addr, size_t size)
{
    _DkVirtualMemoryFree(addr, size);
}

#define system_free(addr, size) __free(addr, size)

#include "slabmgr.h"

static SLAB_MGR slab_mgr = NULL;

void init_slab_mgr (void)
{
    if (!slab_mgr) {
        slab_mgr = create_slab_mgr();
    }
}

void * malloc (int size)
{
    void * ptr = slab_alloc(slab_mgr, size);

    /* the slab manger will always remain at least one byte of padding,
       so we can feel free to assign an offset at the byte prior to
       the pointer */
    if (ptr)
        *(((unsigned char *) ptr) - 1) = 0;

    return ptr;
}

void * remalloc (const void * mem, int size)
{
    void * nmem = malloc(size);

    if (nmem)
        memcpy(nmem, mem, size);

    return nmem;
}

void * calloc (int nmem, int size)
{
    void * ptr = malloc(nmem * size + size);
    void * old_ptr = ptr;

    if (ptr) {
        // align ptr to size
        ptr += size - 1 - ((uintptr_t) ptr + size - 1) % size;
        *(((unsigned char *) ptr) - 1) = ptr - old_ptr;
    }

    return ptr;
}

void free (void * ptr)
{
    ptr -= *(((unsigned char *) ptr) - 1);
    slab_free(slab_mgr, ptr);
}
