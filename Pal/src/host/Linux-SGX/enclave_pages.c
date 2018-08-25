/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <pal_linux.h>
#include <pal_internal.h>
#include <pal_security.h>
#include <api.h>
#include "enclave_pages.h"

#include <list.h>

#include <stdint.h>

static unsigned long pgsz = PRESET_PAGESIZE;
void * heap_base;
static uint64_t heap_size;

/* This list keeps heap_vma structures of free regions
 * organized in DESCENDING order.*/
DEFINE_LIST(heap_vma);
struct heap_vma {
    LIST_TYPE(heap_vma) list;
    void * top;
    void * bottom;
};

DEFINE_LISTP(heap_vma);
static LISTP_TYPE(heap_vma) heap_vma_list = LISTP_INIT;
PAL_LOCK heap_vma_lock = LOCK_INIT;

struct atomic_int alloced_pages, max_alloced_pages;

void init_pages (void)
{
    heap_base = pal_sec.heap_min;
    heap_size = pal_sec.heap_max - pal_sec.heap_min;

    SGX_DBG(DBG_M, "available heap size: %llu M\n",
           (heap_size - pal_sec.exec_size) / 1024 / 1024);

    if (pal_sec.exec_size) {
        struct heap_vma * vma = malloc(sizeof(struct heap_vma));
        vma->top = pal_sec.exec_addr + pal_sec.exec_size;
        vma->bottom = pal_sec.exec_addr;
        INIT_LIST_HEAD(vma, list);
        listp_add(vma, &heap_vma_list, list);
    }
}

#define ASSERT_VMA          0

static void assert_vma_list (void)
{
#if ASSERT_VMA == 1
    void * last_addr = heap_base + heap_size;
    struct heap_vma * vma;

    listp_for_each_entry(vma, &heap_vma_list, list) {
        SGX_DBG(DBG_M, "[%d] %p - %p\n", pal_sec.pid, vma->bottom, vma->top);
        if (last_addr < vma->top || vma->top <= vma->bottom) {
            SGX_DBG(DBG_E, "*** [%d] corrupted heap vma: %p - %p (last = %p) ***\n", pal_sec.pid, vma->bottom, vma->top, last_addr);
#ifdef DEBUG
            if (pal_sec.in_gdb)
                asm volatile ("int $3" ::: "memory");
#endif
            ocall_exit();
        }
        last_addr = vma->bottom;
    }
#endif
}

// TODO: This function should be fixed to always either return exactly `addr` or
// fail.
void * get_reserved_pages(void * addr, uint64_t size)
{
    if (!size)
        return NULL;

    SGX_DBG(DBG_M, "*** get_reserved_pages: heap_base %p, heap_size %llu, limit %p ***\n", heap_base, heap_size, heap_base + heap_size);
    if (addr >= heap_base + heap_size) {
        SGX_DBG(DBG_E, "*** allocating out of heap: %p ***\n", addr);
        return NULL;
    }

    if (size & (pgsz - 1))
        size = ((size + pgsz - 1) & ~(pgsz - 1));

    if ((uintptr_t) addr & (pgsz - 1))
        addr = (void *) ((uintptr_t) addr & ~(pgsz - 1));

    SGX_DBG(DBG_M, "allocate %d bytes at %p\n", size, addr);

    _DkInternalLock(&heap_vma_lock);

    struct heap_vma * prev = NULL, * next;
    struct heap_vma * vma;

    /* Allocating in the heap region.  This loop searches the vma list to
     * find the first vma with a starting address lower than the requested
     * address.  Recall that vmas are in descending order.  
     * 
     * If the very first vma matches, prev will be null.  
     */
    if (addr && addr >= heap_base &&
        addr + size <= heap_base + heap_size) {
        listp_for_each_entry(vma, &heap_vma_list, list) {
            if (vma->bottom < addr)
                break;
            prev = vma;
        }
        goto allocated;
    }

    if (addr) {
        _DkInternalUnlock(&heap_vma_lock);
        return NULL;
    }

    void * avail_top = heap_base + heap_size;

    listp_for_each_entry(vma, &heap_vma_list, list) {
        if (avail_top - vma->top > size) {
            addr = avail_top - size;
            goto allocated;
        }
        prev = vma;
        avail_top = prev->bottom;
    }

    if (avail_top >= heap_base + size) {
        addr = avail_top - size;
        goto allocated;
    }

    _DkInternalUnlock(&heap_vma_lock);

    SGX_DBG(DBG_E, "*** Not enough space on the heap (requested = %llu) ***\n", size);
    asm volatile("int $3");
    return NULL;

allocated:
    if (prev) {
        // If this is the last entry, don't wrap around
        if (prev->list.next == listp_first_entry(&heap_vma_list, struct heap_vma, list))
            next = NULL;
        else 
            next = prev->list.next;
    } else {
        /* In this case, the list is empty, or 
         * first vma starts at or below the allocation site.
         * 
         * The next field will be used to merge vmas with the allocation, if 
         * they overlap, until the vmas drop below the requested addr
         * (traversing in decreasing virtual address order)
         */
        next = listp_empty(&heap_vma_list) ? NULL :
            listp_first_entry(&heap_vma_list, struct heap_vma, list);
    }

    if (prev && next)
        SGX_DBG(DBG_M, "insert vma between %p-%p and %p-%p\n",
                next->bottom, next->top, prev->bottom, prev->top);
    else if (prev)
        SGX_DBG(DBG_M, "insert vma below %p-%p\n", prev->bottom, prev->top);
    else if (next)
        SGX_DBG(DBG_M, "insert vma above %p-%p\n", next->bottom, next->top);

    vma = NULL;
    while (prev) {
        struct heap_vma * prev_prev = NULL;

        if (prev->bottom > addr + size)
            break;

        /* This appears to be doing a reverse search; we should stop before we
         * wrap back to the last entry */
        if (prev->list.prev != listp_last_entry(&heap_vma_list, struct heap_vma, list))
            prev_prev = list_entry(prev->list.prev, struct heap_vma, list);

        if (!vma) {
            SGX_DBG(DBG_M, "merge %p-%p and %p-%p\n", addr, addr + size,
                    prev->bottom, prev->top);

            vma = prev;
            vma->top = (addr + size > vma->top) ? addr + size : vma->top;
            vma->bottom = addr;
        } else {
            SGX_DBG(DBG_M, "merge %p-%p and %p-%p\n", vma->bottom, vma->top,
                    prev->bottom, prev->top);

            vma->top = (prev->top > vma->top) ? prev->top : vma->top;
            listp_del(prev, &heap_vma_list,list);
            free(prev);
        }

        prev = prev_prev;
    }

    while (next) {
        struct heap_vma * next_next = NULL;

        if (next->top < addr)
            break;

        if (next->list.next != listp_first_entry(&heap_vma_list, struct heap_vma, list))
            next_next = list_entry(next->list.next, struct heap_vma, list);

        if (!vma) {
            SGX_DBG(DBG_M, "merge %p-%p and %p-%p\n", addr, addr + size,
                    next->bottom, next->top);

            vma = next;
            vma->top = (addr + size > vma->top) ? addr + size : vma->top;
        } else {
            SGX_DBG(DBG_M, "merge %p-%p and %p-%p\n", vma->bottom, vma->top,
                    next->bottom, next->top);

            vma->bottom = next->bottom;
            listp_del(next, &heap_vma_list, list);
            free(next);
        }

        next = next_next;
    }

    if (!vma) {
        vma = malloc(sizeof(struct heap_vma));
        if (!vma) {
            _DkInternalUnlock(&heap_vma_lock);
            return NULL;
        }
        vma->top = addr + size;
        vma->bottom = addr;
        INIT_LIST_HEAD(vma, list);
        listp_add_after(vma, prev, &heap_vma_list, list);
    }

    if (vma->bottom >= vma->top) {
        SGX_DBG(DBG_E, "*** Bad memory bookkeeping: %p - %p ***\n",
                vma->bottom, vma->top);
#ifdef DEBUG
        if (pal_sec.in_gdb)
            asm volatile ("int $3" ::: "memory");
#endif
    }
    assert_vma_list();

    _DkInternalUnlock(&heap_vma_lock);

    atomic_add(size / pgsz, &alloced_pages);
    return addr;
}

void free_pages(void * addr, uint64_t size)
{
    void * addr_top = addr + size;

    SGX_DBG(DBG_M, "free_pages: trying to free %p %llu\n", addr, size);
    
    if (!addr || !size)
        return;

    if ((uintptr_t) addr_top & (pgsz - 1))
        addr = (void *) (((uintptr_t) addr_top + pgsz + 1) & ~(pgsz - 1));

    if ((uintptr_t) addr & (pgsz - 1))
        addr = (void *) ((uintptr_t) addr & ~(pgsz - 1));

    if (addr >= heap_base + heap_size)
        return;
    if (addr_top <= heap_base)
        return;
    if (addr_top > heap_base + heap_size)
        addr_top = heap_base + heap_size;
    if (addr < heap_base)
        addr = heap_base;

    SGX_DBG(DBG_M, "free %d bytes at %p\n", size, addr);

    _DkInternalLock(&heap_vma_lock);

    struct heap_vma * vma, * p;

    listp_for_each_entry_safe(vma, p, &heap_vma_list, list) {
        if (vma->bottom >= addr_top)
            continue;
        if (vma->top <= addr)
            break;
        if (vma->bottom < addr) {
            struct heap_vma * new = malloc(sizeof(struct heap_vma));
            new->top = addr;
            new->bottom = vma->bottom;
            INIT_LIST_HEAD(new, list);
            list_add(new, vma, list);
        }

        vma->bottom = addr_top;
        if (vma->top <= vma->bottom) {
            listp_del(vma, &heap_vma_list, list); free(vma);
        }
    }

    assert_vma_list();

    _DkInternalUnlock(&heap_vma_lock);

    unsigned int val = atomic_read(&alloced_pages);
    atomic_sub(size / pgsz, &alloced_pages);
    if (val > atomic_read(&max_alloced_pages))
        atomic_set(&max_alloced_pages, val);
}

void print_alloced_pages (void)
{
    unsigned int val = atomic_read(&alloced_pages);
    unsigned int max = atomic_read(&max_alloced_pages);

    printf("                >>>>>>>> "
           "Enclave heap size =         %10ld pages / %10ld pages\n",
           val > max ? val : max, heap_size / pgsz);
}
