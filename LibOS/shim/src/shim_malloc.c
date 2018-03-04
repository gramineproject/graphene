/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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
 * shim_malloc.c
 *
 * This file implements page allocation for the library OS-internal SLAB
 * memory allocator.  The slab allocator is in Pal/lib/slabmgr.h.  
 * 
 * When existing slabs are not sufficient, or a large (4k or greater) 
 * allocation is requested, it ends up here (__system_alloc and __system_free).
 * 
 * There are two modes this file executes in: early initialization (before
 * VMAs are available), and post-initialization.  
 * 
 * Before VMAs are available, allocations are tracked in the shim_heap_areas
 * array.  
 *
 * Once VMAs initialized, the contents of shim_heap_areas are added to the VMA
 * list.  In order to reduce the risk of virtual address collisions, the VMA 
 * for the shim_heap_area is never removed, but the pages themselves are
 * freed.   This approach effectively reserves part of the address space for
 * initialization-time bookkeeping.
 * 
 * After initialization, all allocations and frees just call
 * DkVirtualMemoryAlloc and DkVirtualMemory Free, and add/remove VMAs for the
 * results.
 */

#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_profile.h>
#include <shim_checkpoint.h>
#include <shim_vma.h>

#include <pal.h>
#include <pal_debug.h>

#include <asm/mman.h>

static LOCKTYPE slab_mgr_lock;

#define system_lock()       lock(slab_mgr_lock)
#define system_unlock()     unlock(slab_mgr_lock)
#define PAGE_SIZE           allocsize

#ifdef SLAB_DEBUG_TRACE
# define SLAB_DEBUG
#endif

#define SLAB_CANARY
#define STARTUP_SIZE    4

#include <slabmgr.h>

static SLAB_MGR slab_mgr = NULL;

#define MIN_SHIM_HEAP_PAGES      64
#define MAX_SHIM_HEAP_AREAS      32

#define INIT_SHIM_HEAP     256 * allocsize

static int vmas_initialized = 0;

static struct shim_heap {
    void * start;
    void * current;
    void * end;
} shim_heap_areas[MAX_SHIM_HEAP_AREAS];

static LOCKTYPE shim_heap_lock;

DEFINE_PROFILE_CATAGORY(memory, );

static struct shim_heap * __alloc_enough_heap (size_t size)
{
    struct shim_heap * heap = NULL, * first_empty = NULL, * smallest = NULL;
    size_t smallest_size = 0;

    for (int i = 0 ; i < MAX_SHIM_HEAP_AREAS ; i++)
        if (shim_heap_areas[i].start) {
            if (shim_heap_areas[i].end >= shim_heap_areas[i].current + size)
                return &shim_heap_areas[i];

            if (!smallest ||
                shim_heap_areas[i].end <=
                shim_heap_areas[i].current + smallest_size) {
                smallest = &shim_heap_areas[i];
                smallest_size = shim_heap_areas[i].end -
                                shim_heap_areas[i].current;
            }
        } else {
            if (!first_empty)
                first_empty = &shim_heap_areas[i];
        }

    if (!heap) {
        size_t heap_size = MIN_SHIM_HEAP_PAGES * allocsize;
        void * start = NULL;
        heap = first_empty ? : smallest;
        assert(heap);

        while (size > heap_size)
            heap_size *= 2;

        if (!(start = (void *) DkVirtualMemoryAlloc(NULL, heap_size, 0,
                                    PAL_PROT_WRITE|PAL_PROT_READ)))
            return NULL;

        debug("allocate internal heap at %p - %p\n", start, start + heap_size);

        if (heap == smallest && heap->current != heap->end) {
            DkVirtualMemoryFree(heap->current, heap->end - heap->current);
            int flags = VMA_INTERNAL;
            unlock(shim_heap_lock);
            bkeep_munmap(heap->current, heap->end - heap->current, flags);
            lock(shim_heap_lock);
        }

        heap->start = heap->current = start;
        heap->end = start + heap_size;

        unlock(shim_heap_lock);
        bkeep_mmap(start, heap_size, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS|VMA_INTERNAL, NULL, 0, NULL);
        lock(shim_heap_lock);
    }

    return heap;
}

/* Returns NULL on failure */
void * __system_malloc (size_t size)
{
    size_t alloc_size = ALIGN_UP(size);
    void * addr;

    lock(shim_heap_lock);

    if (vmas_initialized) {
        int flags = MAP_PRIVATE|MAP_ANONYMOUS|VMA_INTERNAL;

        /*
         * If vmas are initialized, we need to request a free address range
         * using bkeep_unmapped_any().  The current mmap code uses this function
         * to synchronize all address allocation, via a "publication"
         * pattern.  It is not safe to just call DkVirtualMemoryAlloc directly
         * without reserving the vma region first.
         */
        addr = bkeep_unmapped_any(alloc_size, PROT_READ|PROT_WRITE, flags,
                                  NULL, 0, "heap");

        if (!addr) {
            unlock(shim_heap_lock);
            return NULL;
        }

        addr = (void *) DkVirtualMemoryAlloc(addr, alloc_size, 0,
                                             PAL_PROT_WRITE|PAL_PROT_READ);
        if (!addr) {
            bkeep_munmap(addr, alloc_size, flags);
            unlock(shim_heap_lock);
            return NULL;
        }
    } else {

        struct shim_heap * heap = __alloc_enough_heap(alloc_size);

        if (!heap) {
            unlock(shim_heap_lock);
            return NULL;
        }

        addr = heap->current;
        heap->current += alloc_size;
    }

    unlock(shim_heap_lock);

    return addr;
}

void __system_free (void * addr, size_t size)
{
    int in_reserved_area = 0;
    DkVirtualMemoryFree(addr, ALIGN_UP(size));
    int flags = VMA_INTERNAL;
    for (int i = 0 ; i < MAX_SHIM_HEAP_AREAS ; i++)
        if (shim_heap_areas[i].start) {
            /* Here we assume that any allocation from the 
             * shim_heap_area is a strict inclusion.  Allocations
             * cannot partially overlap.
             */
            if (addr >= shim_heap_areas[i].start
                && addr <= shim_heap_areas[i].end)
                in_reserved_area = 1;
        }

    if (!in_reserved_area)
        bkeep_munmap(addr, ALIGN_UP(size), flags);
}

int init_heap (void)
{
    create_lock(shim_heap_lock);

    void * start = (void *) DkVirtualMemoryAlloc(NULL, INIT_SHIM_HEAP, 0,
                                    PAL_PROT_WRITE|PAL_PROT_READ);
    if (!start)
        return -ENOMEM;

    debug("allocate internal heap at %p - %p\n", start,
          start + INIT_SHIM_HEAP);

    shim_heap_areas[0].start = shim_heap_areas[0].current = start;
    shim_heap_areas[0].end = start + INIT_SHIM_HEAP;

    return 0;
}

int bkeep_shim_heap (void)
{
    lock(shim_heap_lock);
    
    for (int i = 0 ; i < MAX_SHIM_HEAP_AREAS ; i++)
        if (shim_heap_areas[i].start) {
            /* Add a VMA for the active region */
            bkeep_mmap(shim_heap_areas[i].start,
                       shim_heap_areas[i].current - shim_heap_areas[i].start,
                       PROT_READ|PROT_WRITE,
                       MAP_PRIVATE|MAP_ANONYMOUS|VMA_INTERNAL, NULL, 0, NULL);
            /* Go ahead and free the reserved region */
            if (shim_heap_areas[i].current < shim_heap_areas[i].end) {
                DkVirtualMemoryFree(shim_heap_areas[i].current,
                                    ALIGN_UP(((long unsigned int) shim_heap_areas[i].end) - ((long unsigned int) shim_heap_areas[i].current)));
                shim_heap_areas[i].end = shim_heap_areas[i].current;
            }
        }
    vmas_initialized = 1;
    
    unlock(shim_heap_lock);
    return 0;
}

int init_slab (void)
{
    create_lock(slab_mgr_lock);
    slab_mgr = create_slab_mgr();
    return 0;
}

extern_alias(init_slab);

int reinit_slab (void)
{
    if (slab_mgr) {
        destroy_slab_mgr(slab_mgr);
        slab_mgr = NULL;
    }
    return 0;
}

DEFINE_PROFILE_OCCURENCE(malloc_0, memory);
DEFINE_PROFILE_OCCURENCE(malloc_1, memory);
DEFINE_PROFILE_OCCURENCE(malloc_2, memory);
DEFINE_PROFILE_OCCURENCE(malloc_3, memory);
DEFINE_PROFILE_OCCURENCE(malloc_4, memory);
DEFINE_PROFILE_OCCURENCE(malloc_5, memory);
DEFINE_PROFILE_OCCURENCE(malloc_6, memory);
DEFINE_PROFILE_OCCURENCE(malloc_7, memory);
DEFINE_PROFILE_OCCURENCE(malloc_big, memory);

#if defined(SLAB_DEBUG_PRINT) || defined(SLABD_DEBUG_TRACE)
void * __malloc_debug (size_t size, const char * file, int line)
#else
void * malloc (size_t size)
#endif
{
#ifdef PROFILE
    int i;
    int level = -1;

    for (i = 0 ; i < SLAB_LEVEL ; i++)
        if (size < slab_levels[i]) {
            level = i;
            break;
        }
    switch(level) {
    case 0:
        INC_PROFILE_OCCURENCE(malloc_0);
        break;
    case 1:
        INC_PROFILE_OCCURENCE(malloc_1);
        break;
    case 2:
        INC_PROFILE_OCCURENCE(malloc_2);
        break;
    case 3:
        INC_PROFILE_OCCURENCE(malloc_3);
        break;
    case 4:
        INC_PROFILE_OCCURENCE(malloc_4);
        break;
    case 5:
        INC_PROFILE_OCCURENCE(malloc_5);
        break;
    case 6:
        INC_PROFILE_OCCURENCE(malloc_6);
        break;
    case 7:
        INC_PROFILE_OCCURENCE(malloc_7);
        break;
    case -1:
        INC_PROFILE_OCCURENCE(malloc_big);
        break;
    }
#endif

#ifdef SLAB_DEBUG_TRACE
    void * mem = slab_alloc_debug(slab_mgr, size, file, line);
#else
    void * mem = slab_alloc(slab_mgr, size);
#endif

#ifdef SLAB_DEBUG_PRINT
    debug("malloc(%d) = %p (%s:%d)\n", size, mem, file, line);
#endif
    return mem;
}
#if !defined(SLAB_DEBUG_PRINT) && !defined(SLAB_DEBUG_TRACE)
extern_alias(malloc);
#endif

void * calloc (size_t nmemb, size_t size)
{
    // This overflow checking is not a UB, because the operands are unsigned.
    size_t total = nmemb * size;
    if (total / size != nmemb)
        return NULL;
    void *ptr = malloc(total);
    if (ptr)
        memset(ptr, 0, total);
    return ptr;
}
extern_alias(calloc);

void* realloc(void* ptr, size_t new_size)
{
    // TODO: This function should be optimized to avoid memcpy when buffer
    // expansion is possible.
    size_t old_size = slab_get_buf_size(slab_mgr, ptr);
    void* new_buf = malloc(new_size);
    if (!new_buf)
        return NULL;
    memcpy(new_buf, ptr, new_size < old_size ? new_size : old_size);
    free(ptr);
    return new_buf;
}
extern_alias(realloc);


// Copies data from `mem` to a newly allocated buffer of a specified size.
#if defined(SLAB_DEBUG_PRINT) || defined(SLABD_DEBUG_TRACE)
void * __malloc_copy_debug (const void * mem, size_t size,
                         const char * file, int line)
#else
void * malloc_copy (const void * mem, size_t size)
#endif
{
#if defined(SLAB_DEBUG_PRINT) || defined(SLABD_DEBUG_TRACE)
    void * buff = __malloc_debug(size, file, line);
#else
    void * buff = malloc(size);
#endif
    if (buff)
        memcpy(buff, mem, size);
    return buff;
}
#if !defined(SLAB_DEBUG_PRINT) && !defined(SLABD_DEBUG_TRACE)
extern_alias(malloc_copy);
#endif

DEFINE_PROFILE_OCCURENCE(free_0, memory);
DEFINE_PROFILE_OCCURENCE(free_1, memory);
DEFINE_PROFILE_OCCURENCE(free_2, memory);
DEFINE_PROFILE_OCCURENCE(free_3, memory);
DEFINE_PROFILE_OCCURENCE(free_4, memory);
DEFINE_PROFILE_OCCURENCE(free_5, memory);
DEFINE_PROFILE_OCCURENCE(free_6, memory);
DEFINE_PROFILE_OCCURENCE(free_7, memory);
DEFINE_PROFILE_OCCURENCE(free_big, memory);
DEFINE_PROFILE_OCCURENCE(free_migrated, memory);

#if defined(SLAB_DEBUG_PRINT) || defined(SLABD_DEBUG_TRACE)
void __free_debug (void * mem, const char * file, int line)
#else
void free (void * mem)
#endif
{
    if (MEMORY_MIGRATED(mem)) {
        INC_PROFILE_OCCURENCE(free_migrated);
        return;
    }

#ifdef PROFILE
    int level = RAW_TO_LEVEL(mem);
    switch(level) {
    case 0:
        INC_PROFILE_OCCURENCE(free_0);
        break;
    case 1:
        INC_PROFILE_OCCURENCE(free_1);
        break;
    case 2:
        INC_PROFILE_OCCURENCE(free_2);
        break;
    case 3:
        INC_PROFILE_OCCURENCE(free_3);
        break;
    case 4:
        INC_PROFILE_OCCURENCE(free_4);
        break;
    case 5:
        INC_PROFILE_OCCURENCE(free_5);
        break;
    case 6:
        INC_PROFILE_OCCURENCE(free_6);
        break;
    case 7:
        INC_PROFILE_OCCURENCE(free_7);
        break;
    case -1:
    case 255:
        INC_PROFILE_OCCURENCE(free_big);
        break;
    }
#endif

#ifdef SLAB_DEBUG_PRINT
    debug("free(%p) (%s:%d)\n", mem, file, line);
#endif

#ifdef SLAB_DEBUG_TRACE
    slab_free_debug(slab_mgr, mem, file, line);
#else
    slab_free(slab_mgr, mem);
#endif
}
#if !defined(SLAB_DEBUG_PRINT) && !defined(SLABD_DEBUG_TRACE)
extern_alias(free);
#endif
