/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains implementation of PAL's internal memory allocator.
 */

#include "api.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

static int g_slab_alignment;
static PAL_LOCK g_slab_mgr_lock = LOCK_INIT;

#define SYSTEM_LOCK()   _DkInternalLock(&g_slab_mgr_lock)
#define SYSTEM_UNLOCK() _DkInternalUnlock(&g_slab_mgr_lock)
#define SYSTEM_LOCKED() _DkInternalIsLocked(&g_slab_mgr_lock)

#if STATIC_SLAB == 1
#define POOL_SIZE 64 * 1024 * 1024
static char g_mem_pool[POOL_SIZE];
static bool g_alloc_from_bottom = true; /* allocate from bottom if true, from top if false */
static void* g_mem_pool_end = &g_mem_pool[POOL_SIZE];
static void* g_bottom = g_mem_pool;
static void* g_top    = &g_mem_pool[POOL_SIZE];
#else
#define ALLOC_ALIGNMENT g_slab_alignment
#endif

#define STARTUP_SIZE 2

static inline void* __malloc(int size);
static inline void __free(void* addr, int size);
#define system_malloc(size) __malloc(size)
#define system_free(addr, size) __free(addr, size)

#include "slabmgr.h"

/* caller (slabmgr.h) releases g_slab_mgr_lock before calling this function (this must be reworked
 * in the future), so grab the lock again to protect g_bottom/g_top */
static inline void* __malloc(int size) {
    void* addr = NULL;

#if STATIC_SLAB == 1
    SYSTEM_LOCK();
    if (g_bottom + size <= g_top) {
        /* alternate allocating objects from top and bottom of available memory pool; this allows
         * to free memory for patterns like "malloc1 - malloc2 - free1" (seen in e.g. realloc) */
        if (g_alloc_from_bottom) {
            addr = g_bottom;
            g_bottom += size;
        } else {
            addr = g_top - size;
            g_top -= size;
        }
        g_alloc_from_bottom = !g_alloc_from_bottom; /* switch alloc direction for next malloc */
    }
    SYSTEM_UNLOCK();
    if (addr)
        return addr;
#endif

    /* At this point, we depleted the pre-allocated memory pool of POOL_SIZE. Let's fall back to
     * PAL-internal allocations. PAL allocator must be careful though because LibOS doesn't know
     * about PAL-internal memory, limited via manifest option `loader.pal_internal_mem_size` and
     * thus this malloc may return -ENOMEM. */
    int ret = _DkVirtualMemoryAlloc(&addr, ALLOC_ALIGN_UP(size), PAL_ALLOC_INTERNAL,
              PAL_PROT_READ | PAL_PROT_WRITE);
    if (ret < 0) {
        printf("*** Out-of-memory in PAL (try increasing `loader.pal_internal_mem_size`) ***\n");
        _DkProcessExit(-ENOMEM);
    }
    return addr;
}

/* caller (slabmgr.h) releases g_slab_mgr_lock before calling this function (this must be reworked
 * in the future), so grab the lock again to protect g_bottom/g_top */
static inline void __free(void* addr, int size) {
    if (!addr)
        return;
#if STATIC_SLAB == 1
    if (addr >= (void*)g_mem_pool && addr < g_mem_pool_end) {
        SYSTEM_LOCK();
        if (addr == g_top) {
            /* reclaim space of last object allocated at top */
            g_top = addr + size;
        } else if (addr + size == g_bottom) {
            /* reclaim space of last object allocated at bottom */
            g_bottom = addr;
        }
        /* not a last object from top/bottom, can't do anything about this case */
        SYSTEM_UNLOCK();
        return;
    }
#endif

    _DkVirtualMemoryFree(addr, ALLOC_ALIGN_UP(size));
}

static SLAB_MGR g_slab_mgr = NULL;

void init_slab_mgr(int alignment) {
    if (g_slab_mgr)
        return;

    g_slab_alignment = alignment;
    g_slab_mgr       = create_slab_mgr();
    if (!g_slab_mgr)
        INIT_FAIL(PAL_ERROR_NOMEM, "cannot initialize slab manager");
}

void* malloc(size_t size) {
    void* ptr = slab_alloc(g_slab_mgr, size);

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
    return ptr;
}

// Copies data from `mem` to a newly allocated buffer of a specified size.
void* malloc_copy(const void* mem, size_t size) {
    void* nmem = malloc(size);

    if (nmem)
        memcpy(nmem, mem, size);

    return nmem;
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
    slab_free(g_slab_mgr, ptr);
}
