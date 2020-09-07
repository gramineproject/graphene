/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * slab.c
 *
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
static void* g_bump = g_mem_pool;
static void* g_mem_pool_end = &g_mem_pool[POOL_SIZE];
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
 * in the future), so grab the lock again to protect g_bump */
static inline void* __malloc(int size) {
    void* addr = NULL;

#if STATIC_SLAB == 1
    SYSTEM_LOCK();
    if (g_bump + size <= g_mem_pool_end) {
        addr = g_bump;
        g_bump += size;
        SYSTEM_UNLOCK();
        return addr;
    }
    SYSTEM_UNLOCK();
#endif

#if 1
    /* FIXME: At this point, we depleted the pre-allocated memory pool of POOL_SIZE. Previously,
     *        PAL would allocate more pages (for its internal purposes e.g. for event objects),
     *        but LibOS had no idea about it. This led to LibOS allocating pages at same addresses
     *        and ultimately to subtle memory corruptions. Fixing it requires complete re-write of
     *        PAL memory allocation; loudly terminate for now. For more details, see issue
     *        https://github.com/oscarlab/graphene/issues/1072. */
    printf("*** Out-of-memory in PAL (try increasing POOL_SIZE and rebuilding Graphene) ***\n");
    _DkProcessExit(-ENOMEM);
#else
    size = ALLOC_ALIGN_UP(size);
    _DkVirtualMemoryAlloc(&addr, size, PAL_ALLOC_INTERNAL, PAL_PROT_READ | PAL_PROT_WRITE);
#endif
    return addr;
}

static inline void __free(void* addr, int size) {
    if (!addr)
        return;
#if STATIC_SLAB == 1
    if (addr >= (void*)g_mem_pool && addr < g_mem_pool_end)
        return;
#endif

    size = ALLOC_ALIGN_UP(size);
    _DkVirtualMemoryFree(addr, size);
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
    slab_free(g_slab_mgr, ptr);
}
