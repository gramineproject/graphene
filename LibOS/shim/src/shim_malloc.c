/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * shim_malloc.c
 *
 * This file implements page allocation for the library OS-internal SLAB
 * memory allocator.  The slab allocator is in Pal/lib/slabmgr.h.
 *
 * When existing slabs are not sufficient, or a large (4k or greater)
 * allocation is requested, it ends up here (__system_alloc and __system_free).
 */

#include <asm/mman.h>
#include <pal.h>
#include <pal_debug.h>
#include <shim_checkpoint.h>
#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_vma.h>

static struct shim_lock slab_mgr_lock;

#define SYSTEM_LOCK()   lock(&slab_mgr_lock)
#define SYSTEM_UNLOCK() unlock(&slab_mgr_lock)
#define SYSTEM_LOCKED() locked(&slab_mgr_lock)

#ifdef SLAB_DEBUG_TRACE
#define SLAB_DEBUG
#endif

#define SLAB_CANARY
#define STARTUP_SIZE 16

#include <slabmgr.h>

static SLAB_MGR slab_mgr = NULL;

/* Returns NULL on failure */
void* __system_malloc(size_t size) {
    size_t alloc_size = ALLOC_ALIGN_UP(size);
    void* addr;
    void* ret_addr;

    int ret = bkeep_mmap_any(alloc_size, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | VMA_INTERNAL, NULL, 0, "slab", &addr);
    if (ret < 0) {
        return NULL;
    }

    do {
        ret_addr = DkVirtualMemoryAlloc(addr, alloc_size, 0, PAL_PROT_WRITE | PAL_PROT_READ);

        if (!ret_addr) {
            /* If the allocation is interrupted by signal, try to handle the
             * signal and then retry the allocation. */
            if (PAL_NATIVE_ERRNO() == PAL_ERROR_INTERRUPTED) {
                handle_signals();
                continue;
            }

            debug("failed to allocate memory (%ld)\n", -PAL_ERRNO());
            void* tmp_vma = NULL;
            if (bkeep_munmap(addr, alloc_size, /*is_internal=*/true, &tmp_vma) < 0) {
                BUG();
            }
            bkeep_remove_tmp_vma(tmp_vma);
            return NULL;
        }
    } while (!ret_addr);
    assert(addr == ret_addr);
    return addr;
}

void __system_free(void* addr, size_t size) {
    void* tmp_vma = NULL;
    if (bkeep_munmap(addr, ALLOC_ALIGN_UP(size), /*is_internal=*/true, &tmp_vma) < 0) {
        BUG();
    }
    DkVirtualMemoryFree(addr, ALLOC_ALIGN_UP(size));
    bkeep_remove_tmp_vma(tmp_vma);
}

int init_slab(void) {
    if (!create_lock(&slab_mgr_lock)) {
        return -ENOMEM;
    }
    slab_mgr = create_slab_mgr();
    if (!slab_mgr) {
        return -ENOMEM;
    }
    return 0;
}

EXTERN_ALIAS(init_slab);

#if defined(SLAB_DEBUG_PRINT) || defined(SLABD_DEBUG_TRACE)
void* __malloc_debug(size_t size, const char* file, int line)
#else
void* malloc(size_t size)
#endif
{
#ifdef SLAB_DEBUG_TRACE
    void* mem = slab_alloc_debug(slab_mgr, size, file, line);
#else
    void* mem = slab_alloc(slab_mgr, size);
#endif

    if (!mem) {
        /*
         * Normally, the library OS should not run out of memory.
         * If malloc() failed internally, we cannot handle the
         * condition and must terminate the current process.
         */
        SYS_PRINTF("******** Out-of-memory in library OS ********\n");
        __abort();
    }

#ifdef SLAB_DEBUG_PRINT
    debug("malloc(%d) = %p (%s:%d)\n", size, mem, file, line);
#endif
    return mem;
}
#if !defined(SLAB_DEBUG_PRINT) && !defined(SLAB_DEBUG_TRACE)
EXTERN_ALIAS(malloc);
#endif

void* calloc(size_t nmemb, size_t size) {
    // This overflow checking is not a UB, because the operands are unsigned.
    size_t total = nmemb * size;
    if (total / size != nmemb)
        return NULL;
    void* ptr = malloc(total);
    if (ptr)
        memset(ptr, 0, total);
    return ptr;
}
EXTERN_ALIAS(calloc);

#if 0 /* Temporarily disabling this code */
void * realloc(void * ptr, size_t new_size)
{
    /* TODO: We can't deal with this case right now */
    assert(!memory_migrated(ptr));

    size_t old_size = slab_get_buf_size(slab_mgr, ptr);

    /*
     * TODO: this realloc() implementation follows the GLIBC design, which
     * will avoid reallocation when the buffer is large enough. Potentially
     * this design can cause memory draining if user resizes an extremely
     * large object to much smaller.
     */
    if (old_size >= new_size)
        return ptr;

    void * new_buf = malloc(new_size);
    if (!new_buf)
        return NULL;

    memcpy(new_buf, ptr, old_size);
    /* realloc() does not zero the rest of the object */
    free(ptr);
    return new_buf;
}
EXTERN_ALIAS(realloc);
#endif

// Copies data from `mem` to a newly allocated buffer of a specified size.
#if defined(SLAB_DEBUG_PRINT) || defined(SLABD_DEBUG_TRACE)
void* __malloc_copy_debug(const void* mem, size_t size, const char* file, int line)
#else
void* malloc_copy(const void* mem, size_t size)
#endif
{
#if defined(SLAB_DEBUG_PRINT) || defined(SLABD_DEBUG_TRACE)
    void* buff = __malloc_debug(size, file, line);
#else
    void* buff = malloc(size);
#endif
    if (buff)
        memcpy(buff, mem, size);
    return buff;
}
#if !defined(SLAB_DEBUG_PRINT) && !defined(SLABD_DEBUG_TRACE)
EXTERN_ALIAS(malloc_copy);
#endif

#if defined(SLAB_DEBUG_PRINT) || defined(SLABD_DEBUG_TRACE)
void __free_debug(void* mem, const char* file, int line)
#else
void free(void* mem)
#endif
{
    if (!mem)
        return;
    if (memory_migrated(mem)) {
        return;
    }

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
EXTERN_ALIAS(free);
#endif
