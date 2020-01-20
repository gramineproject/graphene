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
 * slab.c
 *
 * This file contains implementation of PAL's internal memory allocator.
 */

#include "api.h"
#include "pal_internal.h"

#ifndef NO_INTERNAL_ALLOC

#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"

static int slab_alignment;
static PAL_LOCK slab_mgr_lock = LOCK_INIT;

#define SYSTEM_LOCK()   _DkInternalLock(&slab_mgr_lock)
#define SYSTEM_UNLOCK() _DkInternalUnlock(&slab_mgr_lock)
#define SYSTEM_LOCKED() _DkInternalIsLocked(&slab_mgr_lock)

#if STATIC_SLAB == 1
#define POOL_SIZE 64 * 1024 * 1024 /* 64MB by default */
static char mem_pool[POOL_SIZE];
static void* bump         = mem_pool;
static void* mem_pool_end = &mem_pool[POOL_SIZE];
#else
#define ALLOC_ALIGNMENT slab_alignment
#endif

#define STARTUP_SIZE 2

/* This function is protected by slab_mgr_lock. */
static inline void* __malloc(int size) {
    void* addr = NULL;

#if STATIC_SLAB == 1
    if (bump + size <= mem_pool_end) {
        addr = bump;
        bump += size;
        return addr;
    }
#endif

    _DkVirtualMemoryAlloc(&addr, size, PAL_ALLOC_INTERNAL, PAL_PROT_READ | PAL_PROT_WRITE);
    return addr;
}

#define system_malloc(size) __malloc(size)

static inline void __free(void* addr, int size) {
    if (!addr)
        return;
#if STATIC_SLAB == 1
    if (addr >= (void*)mem_pool && addr < mem_pool_end)
        return;
#endif

    _DkVirtualMemoryFree(addr, size);
}

#define system_free(addr, size) __free(addr, size)

#include "slabmgr.h"

static SLAB_MGR slab_mgr = NULL;

void init_slab_mgr(int alignment) {
    if (slab_mgr)
        return;

#if PROFILING == 1
    unsigned long before_slab = _DkSystemTimeQuery();
#endif

    slab_alignment = alignment;
    slab_mgr       = create_slab_mgr();
    if (!slab_mgr)
        INIT_FAIL(PAL_ERROR_NOMEM, "cannot initialize slab manager");

#if PROFILING == 1
    pal_state.slab_time += _DkSystemTimeQuery() - before_slab;
#endif
}

void* malloc(size_t size) {
#if PROFILING == 1
    unsigned long before_slab = _DkSystemTimeQuery();
#endif
    void* ptr = slab_alloc(slab_mgr, size);

#ifdef DEBUG
    /* In debug builds, try to break code that uses uninitialized heap
     * memory by explicitly initializing to a non-zero value. */
    if (ptr)
        memset(ptr, 0xa5, size);
#endif

    if (!ptr) {
        /*
         * Normally, the PAL should not run out of memory.
         * If malloc() failed internally, we cannot handle the
         * condition and must terminate the current process.
         */
        printf("******** Out-of-memory in PAL ********\n");
        _DkProcessExit(-ENOMEM);
    }

#if PROFILING == 1
    pal_state.slab_time += _DkSystemTimeQuery() - before_slab;
#endif
    return ptr;
}

// Copies data from `mem` to a newly allocated buffer of a specified size.
void* malloc_copy(const void* mem, size_t size) {
    void* nmem = malloc(size);

    if (nmem)
        memcpy(nmem, mem, size);

    return nmem;
}

char* strdup(const char* s) {
    size_t len = strlen(s) + 1;
    char* new  = malloc(len);

    if (new)
        memcpy(new, s, len);

    return new;
}

void* calloc(size_t nmem, size_t size) {
    void* ptr = malloc(nmem * size);

    if (ptr)
        memset(ptr, 0, nmem * size);

    return ptr;
}

void free(void* ptr) {
    if (!ptr)
        return;
#if PROFILING == 1
    unsigned long before_slab = _DkSystemTimeQuery();
#endif
    slab_free(slab_mgr, ptr);

#if PROFILING == 1
    pal_state.slab_time += _DkSystemTimeQuery() - before_slab;
#endif
}

#endif /* !NO_INTERNAL_ALLOC */
