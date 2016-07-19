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

#include "pal_internal.h"
#include "api.h"

#ifndef NO_INTERNAL_ALLOC

#include "pal_defs.h"
#include "pal_error.h"
#include "pal_debug.h"
#include "linux_list.h"

static int slab_alignment;
static PAL_LOCK slab_mgr_lock = LOCK_INIT;

#define system_lock()   _DkInternalLock(&slab_mgr_lock)
#define system_unlock() _DkInternalUnlock(&slab_mgr_lock)

#if STATIC_SLAB == 1
# define POOL_SIZE 64 * 1024 * 1024 /* 64MB by default */
static char mem_pool[POOL_SIZE];
static char *bump = mem_pool;
static char *mem_pool_end = &mem_pool[POOL_SIZE];
#else
# define PAGE_SIZE (slab_alignment)
#endif

#define STARTUP_SIZE    2

static inline void * __malloc (int size)
{
    void * addr = NULL;

#if STATIC_SLAB == 1
    if (bump + size <= mem_pool_end) {
        addr = bump;
        bump += size;
        return addr;
    }
#endif

    _DkVirtualMemoryAlloc(&addr, size, PAL_ALLOC_INTERNAL,
                          PAL_PROT_READ|PAL_PROT_WRITE);
    return addr;
}

#define system_malloc(size) __malloc(size)

static inline void __free (void * addr, int size)
{
#if STATIC_SLAB == 1
    if ((char *) addr >= (char *) mem_pool && (char *) addr + size <= (char *) mem_pool_end)
        return;
#endif

    _DkVirtualMemoryFree(addr, size);
}

#define system_free(addr, size) __free(addr, size)

#include "slabmgr.h"

static SLAB_MGR slab_mgr = NULL;

void init_slab_mgr (int alignment)
{
    if (slab_mgr)
        return;

#if PROFILING == 1
    unsigned long before_slab = _DkSystemTimeQuery();
#endif

    slab_alignment = alignment;
    slab_mgr = create_slab_mgr();
    if (!slab_mgr)
        init_fail(PAL_ERROR_NOMEM, "cannot initialize slab manager");

#if PROFILING == 1
    pal_state.slab_time += _DkSystemTimeQuery() - before_slab;
#endif
}

void * malloc (int size)
{
#if PROFILING == 1
    unsigned long before_slab = _DkSystemTimeQuery();
#endif
    void * ptr = slab_alloc(slab_mgr, size);

    /* the slab manger will always remain at least one byte of padding,
       so we can feel free to assign an offset at the byte prior to
       the pointer */
    if (ptr)
        *(((unsigned char *) ptr) - 1) = 0;

#if PROFILING == 1
    pal_state.slab_time += _DkSystemTimeQuery() - before_slab;
#endif
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
        ptr = (char *) ptr + size - 1 - ((uintptr_t) ptr + size - 1) % size;
        *(((char *) ptr) - 1) = (char *) ptr - (char *) old_ptr;
    }

    return ptr;
}

void free (void * ptr)
{
#if PROFILING == 1
    unsigned long before_slab = _DkSystemTimeQuery();
#endif

    ptr = (char *) ptr - *(((unsigned char *) ptr) - 1);
    slab_free(slab_mgr, ptr);

#if PROFILING == 1
    pal_state.slab_time += _DkSystemTimeQuery() - before_slab;
#endif
}

#endif /* !NO_INTERNAL_ALLOC */
