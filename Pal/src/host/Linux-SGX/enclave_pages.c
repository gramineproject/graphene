#include <pal_linux.h>
#include <pal_internal.h>
#include <pal_security.h>
#include <api.h>
#include "enclave_pages.h"

#include <list.h>

#include <stdint.h>

static size_t g_page_size = PRESET_PAGESIZE;
void * heap_base;
static uint64_t heap_size;

/* TODO: If this list can be very long, consider to introduce rb tree instead of simple doubly
 * linked list
 */
/* This list keeps heap_vma structures of used/reserved regions organized in DESCENDING order.*/
DEFINE_LIST(heap_vma);
struct heap_vma {
    LIST_TYPE(heap_vma) list;
    /* [bottom, top) */
    void* top;
    void* bottom;
    bool internal;  /* PAL_ALLOC_INTERNAL */
};

DEFINE_LISTP(heap_vma);
static LISTP_TYPE(heap_vma) heap_vma_list = LISTP_INIT;
PAL_LOCK heap_vma_lock = LOCK_INIT;

struct atomic_int alloced_pages, max_alloced_pages;

void init_pages (void)
{
    uint64_t reserved_for_exec = 0;

    heap_base = pal_sec.heap_min;
    heap_size = pal_sec.heap_max - pal_sec.heap_min;

    if (pal_sec.exec_size) {
        struct heap_vma * vma = malloc(sizeof(struct heap_vma));
        vma->bottom = SATURATED_P_SUB(pal_sec.exec_addr, MEMORY_GAP, pal_sec.heap_min);
        vma->top = SATURATED_P_ADD(pal_sec.exec_addr + pal_sec.exec_size, MEMORY_GAP, pal_sec.heap_max);
        vma->internal = false;  /* migration does copy it */
        reserved_for_exec = vma->top - vma->bottom;
        INIT_LIST_HEAD(vma, list);
        LISTP_ADD(vma, &heap_vma_list, list);
    }

    SGX_DBG(DBG_M, "available heap size: %lu M\n",
           (heap_size - reserved_for_exec) / 1024 / 1024);
}

#define ASSERT_VMA          0

static void assert_vma_list (void)
{
#if ASSERT_VMA == 1
    void * last_addr = heap_base + heap_size;
    struct heap_vma * vma;

    LISTP_FOR_EACH_ENTRY(vma, &heap_vma_list, list) {
        SGX_DBG(DBG_M, "[%d] %p - %p\n", pal_sec.pid, vma->bottom, vma->top);
        if (last_addr < vma->top || vma->top <= vma->bottom) {
            SGX_DBG(DBG_E, "*** [%d] corrupted heap vma: %p - %p (last = %p) ***\n", pal_sec.pid, vma->bottom, vma->top, last_addr);
#ifdef DEBUG
            if (pal_sec.in_gdb)
                __asm__ volatile ("int $3" ::: "memory");
#endif
            ocall_exit(1, /*is_exitgroup=*/true);
        }
        last_addr = vma->bottom;
    }
#endif
}

static bool vma_overlap(const struct heap_vma* vma, const void* start, size_t size) {
    return !(start + size <= vma->bottom || vma->top <= start);
}

static bool vma_mergable(const struct heap_vma* vma, const void* start, size_t size) {
    return !(start + size < vma->bottom || vma->top < start);
}

static int reserve_area(void* addr, size_t size, struct heap_vma* prev, bool internal) {
    struct heap_vma* next;

    if (prev) {
        next = LISTP_NEXT_ENTRY(prev, &heap_vma_list, list);
    } else {
        /* In this case, the list is empty, or
         * first vma starts at or below the allocation site.
         *
         * The next field will be used to merge vmas with the allocation, if
         * they overlap, until the vmas drop below the requested addr
         * (traversing in decreasing virtual address order)
         */
        next = LISTP_FIRST_ENTRY(&heap_vma_list, struct heap_vma, list);
    }

    if (prev && next)
        SGX_DBG(DBG_M, "insert vma between %p-%p and %p-%p\n",
                next->bottom, next->top, prev->bottom, prev->top);
    else if (prev)
        SGX_DBG(DBG_M, "insert vma below %p-%p\n", prev->bottom, prev->top);
    else if (next)
        SGX_DBG(DBG_M, "insert vma above %p-%p\n", next->bottom, next->top);

    if (!internal) {
        /* The region must not overlap with internal use area */
        if (prev && vma_overlap(prev, addr, size) && prev->internal)
            return -PAL_ERROR_DENIED;

        struct heap_vma* tmp = next;
        while (tmp) {
            assert(tmp->top <= addr + size);
            if (tmp->top <= addr)
                break;

            struct heap_vma* next_next = LISTP_NEXT_ENTRY(tmp, &heap_vma_list, list);

            assert(vma_overlap(tmp, addr, size));
            if (tmp->internal)
                return -PAL_ERROR_DENIED;

            tmp = next_next;
        }
    }

    struct heap_vma* vma = malloc(sizeof(*vma));
    if (!vma)
        return -PAL_ERROR_NOMEM;
    vma->top = addr + size;
    vma->bottom = addr;
    vma->internal = internal;

    /* merge with previous(higher address) vma */
    if (prev && vma_mergable(prev, addr, size) && prev->internal == internal) {
        SGX_DBG(DBG_M, "prev merge %p-%p and %p-%p %d\n", addr, addr + size, prev->bottom, prev->top, (int)internal);
        vma->top = MAX(vma->top, prev->top);
        vma->bottom = MIN(vma->bottom, prev->bottom);
        struct heap_vma* prev_prev = LISTP_PREV_ENTRY(prev, &heap_vma_list, list);
        LISTP_DEL(prev, &heap_vma_list, list);
        free(prev);
        prev = prev_prev;
    } else {
        assert(!prev || addr + size <= prev->bottom);
    }

    /* merge with next(lower address) vma */
    while (next) {
        assert(next->top <= addr + size);
        if (next->top < addr)
            break;

        struct heap_vma* next_next = LISTP_NEXT_ENTRY(next, &heap_vma_list, list);

        if (vma->internal == internal) {
            assert(vma_mergable(vma, addr, size));
            vma->bottom = MIN(vma->bottom, next->bottom);
            LISTP_DEL(next, &heap_vma_list, list);
            free(next);
        } else {
            assert(!vma_overlap(vma, addr, size));
        }

        next = next_next;
    }

    INIT_LIST_HEAD(vma, list);
    LISTP_ADD_AFTER(vma, prev, &heap_vma_list, list);

    if (vma->bottom >= vma->top) {
        SGX_DBG(DBG_E, "*** Bad memory bookkeeping: %p - %p ***\n",
                vma->bottom, vma->top);
#ifdef DEBUG
        if (pal_sec.in_gdb)
            __asm__ volatile ("int $3" ::: "memory");
#endif
    }
    assert_vma_list();

    /* FIXME: size isn't correct as there can be overlaps with existing areas. */
    atomic_add(size / g_page_size, &alloced_pages);
    SGX_DBG(DBG_M, "allocated [%p, %p)@%ld bytes %d\n", addr, addr + size, size, (int)internal);

    return 0;
}

static int get_reserved_pages_fixed(void* addr, size_t size) {
    if (!(addr >= heap_base && addr + size <= heap_base + heap_size))
        return -PAL_ERROR_INVAL;

    _DkInternalLock(&heap_vma_lock);
    struct heap_vma* prev = NULL;
    struct heap_vma* vma;
    LISTP_FOR_EACH_ENTRY(vma, &heap_vma_list, list) {
        if (vma_mergable(vma, addr, size)) {
            prev = vma;
            break;
        }
        /* non-overlap case */
        if (vma->bottom <= addr + size)
            break;
        prev = vma;
    }
    int ret = reserve_area(addr, size, prev, false);
    _DkInternalUnlock(&heap_vma_lock);
    return ret;
}

static int get_reserved_pages_alloc(void** addr, size_t size, bool internal) {
    /* Allocating in the heap region.  This loop searches the vma list to
     * find the first vma with a starting address lower than the requested
     * address.  Recall that vmas are in descending order.
     *
     * If the very first vma matches, prev will be null.
     */
    *addr = NULL;
    int ret = -PAL_ERROR_NOMEM;
    struct heap_vma* prev = NULL;
    void* avail_top = heap_base + heap_size;

    _DkInternalLock(&heap_vma_lock);
    struct heap_vma* vma;
    LISTP_FOR_EACH_ENTRY(vma, &heap_vma_list, list) {
        if ((size_t)(avail_top - vma->top) > size) {
            *addr = avail_top - size;
            break;
        }
        prev = vma;
        avail_top = prev->bottom;
    }
    if (!*addr && avail_top >= heap_base + size) {
        *addr = avail_top - size;
    }

    if (*addr)
        ret = reserve_area(*addr, size, prev, internal);

    _DkInternalUnlock(&heap_vma_lock);
    if (ret < 0) {
        SGX_DBG(DBG_E, "*** Not enough space on the heap (requested = %lu) ***\n", size);
#ifdef DEBUG
        if (pal_sec.in_gdb)
            __asm__ volatile ("int $3" ::: "memory");
#endif
        *addr = NULL;
    }
    return ret;
}

/*
 * FIXME: recursive deadlock
 * get_reserved_pages() => malloc(sizeof(*vma)) => slab_alloc() => __system_malloc() @ slab.c =>
 * get_reserved_pages()
 * Normally slab_alloc() hits cached item so that __system_malloc() isn't invoked.
 */
// TODO: This function should be fixed to always either return exactly `addr` or
// fail.
int get_reserved_pages(void** addr, size_t size, bool internal) {
    if (!size)
        return -PAL_ERROR_INVAL;

    SGX_DBG(DBG_M, "*** get_reserved_pages: heap_base %p, heap_size %lu, limit %p ***\n", heap_base, heap_size, heap_base + heap_size);
    if (*addr >= heap_base + heap_size) {
        SGX_DBG(DBG_E, "*** allocating out of heap: %p ***\n", addr);
        return -PAL_ERROR_INVAL;
    }

    size = ALIGN_UP(size, g_page_size);
    *addr = ALIGN_DOWN_PTR(*addr, g_page_size);

    SGX_DBG(DBG_M, "allocate %ld bytes at %p\n", size, *addr);

    if (*addr) {
        if (internal)
            /* fixed addr allocation isn't needed for internal use for now */
            return -PAL_ERROR_INVAL;
        return get_reserved_pages_fixed(*addr, size);
    }
    return get_reserved_pages_alloc(addr, size, internal);
}

int free_pages(void* addr, size_t size) {
    void* addr_top = addr + size;

    SGX_DBG(DBG_M, "free_pages: trying to free %p %lu\n", addr, size);

    if (!addr || !size)
        return 0;

    addr = ALIGN_DOWN_PTR(addr, g_page_size);
    addr_top = ALIGN_UP_PTR(addr_top, g_page_size);

    if (addr >= heap_base + heap_size)
        return 0;
    if (addr_top <= heap_base)
        return 0;
    if (addr_top > heap_base + heap_size)
        addr_top = heap_base + heap_size;
    if (addr < heap_base)
        addr = heap_base;

    SGX_DBG(DBG_M, "free %ld bytes at %p\n", size, addr);

    _DkInternalLock(&heap_vma_lock);

    struct heap_vma * vma, * p;
    bool checked = false;
    LISTP_FOR_EACH_ENTRY_SAFE(vma, p, &heap_vma_list, list) {
        if (vma->bottom >= addr_top)
            continue;
        if (vma->top <= addr)
            break;

        assert(vma_overlap(vma, addr, size));
        /* Check needs to be done before modifying the list */
        if (vma->internal) {
            /* TODO: currently assume that internal PAL memory is freed at same granularity as
             *       was allocated in _DkVirtualMemoryAlloc(); may be false in general case */
            if (!(vma->bottom <= addr && addr + size <= vma->top))
                return -PAL_ERROR_DENIED;
        } else if (!checked) {
            struct heap_vma* tmp;
            struct heap_vma* next = vma;
            LISTP_FOR_EACH_ENTRY_SAFE_CONTINUE(next, tmp, &heap_vma_list, list) {
                if (next->top <= addr)
                    break;
                if (next->internal)
                    return -PAL_ERROR_DENIED;
            }
            checked = true;
        }

        if (vma->bottom < addr) {
            struct heap_vma * new = malloc(sizeof(struct heap_vma));
            new->top = addr;
            new->bottom = vma->bottom;
            INIT_LIST_HEAD(new, list);
            LIST_ADD(new, vma, list);
        }

        vma->bottom = addr_top;
        if (vma->top <= vma->bottom) {
            LISTP_DEL(vma, &heap_vma_list, list);
            free(vma);
        }
    }

    assert_vma_list();

    _DkInternalUnlock(&heap_vma_lock);

    /* FIXME: size isn't correct as unreserved area can be freed as nop */
    unsigned int val = atomic_read(&alloced_pages);
    atomic_sub(size / g_page_size, &alloced_pages);
    if (val > atomic_read(&max_alloced_pages))
        atomic_set(&max_alloced_pages, val);

    return 0;
}

/* Only for file_map(): once file_map unuse this function, eliminate this */
bool _DkCheckMemoryMappable(const void* addr, size_t size) {
    if (addr < DATA_END && addr + size > TEXT_START) {
        printf("address %p-%p is not mappable\n", addr, addr + size);
        return false;
    }

    if (!addr || !size)
        return true;

    bool ret = true;
    addr = ALIGN_DOWN_PTR(addr, g_page_size);
    const void* addr_top = addr + size;
    addr_top = ALIGN_UP_PTR(addr_top, g_page_size);

    _DkInternalLock(&heap_vma_lock);
    struct heap_vma* vma;
    LISTP_FOR_EACH_ENTRY(vma, &heap_vma_list, list) {
        if (vma->bottom >= addr_top)
            continue;
        if (vma->top <= addr)
            break;

        assert(vma_overlap(vma, addr, size));
        if (vma->internal) {
            ret = false;
            break;
        }
    }
    _DkInternalUnlock(&heap_vma_lock);
    return ret;
}

void print_alloced_pages (void)
{
    unsigned int val = atomic_read(&alloced_pages);
    unsigned int max = atomic_read(&max_alloced_pages);

    printf("                >>>>>>>> "
           "Enclave heap size =         %10d pages / %10ld pages\n",
           val > max ? val : max, heap_size / g_page_size);
}
