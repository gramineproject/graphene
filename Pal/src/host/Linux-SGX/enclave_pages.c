#include "api.h"
#include "enclave_pages.h"
#include "list.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_security.h"

struct atomic_int g_alloced_pages;

static size_t g_page_size = PRESET_PAGESIZE;
static void* g_heap_bottom;
static void* g_heap_top;

/* list of VMAs of used memory areas kept in DESCENDING order */
/* TODO: rewrite the logic so that this list keeps VMAs in ascending order */
DEFINE_LIST(heap_vma);
struct heap_vma {
    LIST_TYPE(heap_vma) list;
    void* bottom;
    void* top;
    bool is_pal_internal;
};
DEFINE_LISTP(heap_vma);

static LISTP_TYPE(heap_vma) g_heap_vma_list = LISTP_INIT;
static PAL_LOCK g_heap_vma_lock = LOCK_INIT;

/* heap_vma objects are taken from pre-allocated pool to avoid recursive mallocs */
#define MAX_HEAP_VMAS 100000
static struct heap_vma g_heap_vma_pool[MAX_HEAP_VMAS];
static size_t g_heap_vma_num = 0;
static struct heap_vma* g_free_vma = NULL;

/* returns uninitialized heap_vma, the caller is responsible for setting at least bottom/top */
static struct heap_vma* __alloc_vma(void) {
    assert(_DkInternalIsLocked(&g_heap_vma_lock));

    if (g_free_vma) {
        /* simple optimization: if there is a cached free vma object, use it */
        assert((uintptr_t)g_free_vma >= (uintptr_t)&g_heap_vma_pool[0]);
        assert((uintptr_t)g_free_vma <= (uintptr_t)&g_heap_vma_pool[MAX_HEAP_VMAS - 1]);

        struct heap_vma* ret = g_free_vma;
        g_free_vma = NULL;
        g_heap_vma_num++;
        return ret;
    }

    /* FIXME: this loop may become perf bottleneck on large number of vma objects; however,
     * experiments show that this number typically does not exceed 20 (thanks to VMA merging) */
    for (size_t i = 0; i < MAX_HEAP_VMAS; i++) {
        if (!g_heap_vma_pool[i].bottom && !g_heap_vma_pool[i].top) {
            /* found empty slot in the pool, use it */
            g_heap_vma_num++;
            return &g_heap_vma_pool[i];
        }
    }

    return NULL;
}

static void __free_vma(struct heap_vma* vma) {
    assert(_DkInternalIsLocked(&g_heap_vma_lock));
    assert((uintptr_t)vma >= (uintptr_t)&g_heap_vma_pool[0]);
    assert((uintptr_t)vma <= (uintptr_t)&g_heap_vma_pool[MAX_HEAP_VMAS - 1]);

    g_free_vma  = vma;
    vma->top    = 0;
    vma->bottom = 0;
    g_heap_vma_num--;
}

int init_enclave_pages(void) {
    int ret;

    g_heap_bottom = pal_sec.heap_min;
    g_heap_top    = pal_sec.heap_max;

    size_t reserved_size = 0;
    struct heap_vma* exec_vma = NULL;

    _DkInternalLock(&g_heap_vma_lock);

    if (pal_sec.exec_addr < g_heap_top && pal_sec.exec_addr + pal_sec.exec_size > g_heap_bottom) {
        /* there is an executable mapped inside the heap, carve a VMA for its area; this can happen
         * in case of non-PIE executables that start at a predefined address (typically 0x400000) */
        exec_vma = __alloc_vma();
        if (!exec_vma) {
            SGX_DBG(DBG_E, "*** Cannot initialize VMA for executable ***\n");
            ret = -PAL_ERROR_NOMEM;
            goto out;
        }

        exec_vma->bottom = SATURATED_P_SUB(pal_sec.exec_addr, MEMORY_GAP, g_heap_bottom);
        exec_vma->top = SATURATED_P_ADD(pal_sec.exec_addr + pal_sec.exec_size, MEMORY_GAP, g_heap_top);
        exec_vma->is_pal_internal = false;
        INIT_LIST_HEAD(exec_vma, list);
        LISTP_ADD(exec_vma, &g_heap_vma_list, list);

        reserved_size += exec_vma->top - exec_vma->bottom;
    }

    atomic_add(reserved_size / g_page_size, &g_alloced_pages);

    SGX_DBG(DBG_M, "Heap size: %luM\n", (g_heap_top - g_heap_bottom - reserved_size) / 1024 / 1024);
    ret = 0;

out:
    _DkInternalUnlock(&g_heap_vma_lock);
    return ret;
}

static void* __create_vma_and_merge(void* addr, size_t size, bool is_pal_internal,
                                    struct heap_vma* vma_above) {
    assert(_DkInternalIsLocked(&g_heap_vma_lock));
    assert(addr && size);

    if (addr < g_heap_bottom)
        return NULL;

    /* find enclosing VMAs and check that pal-internal VMAs do not overlap with normal VMAs */
    struct heap_vma* vma_below;
    if (vma_above) {
        vma_below = LISTP_NEXT_ENTRY(vma_above, &g_heap_vma_list, list);
    } else {
        /* no VMA above `addr`; VMA right below `addr` must be the first (highest-address) in list */
        vma_below = LISTP_FIRST_ENTRY(&g_heap_vma_list, struct heap_vma, list);
    }

    /* check whether [addr, addr + size) overlaps with above VMAs of different type */
    struct heap_vma* check_vma_above = vma_above;
    while (check_vma_above && addr + size > check_vma_above->bottom) {
        if (check_vma_above->is_pal_internal != is_pal_internal) {
            SGX_DBG(DBG_M, "VMA %p-%p (internal=%d) overlaps with %p-%p (internal=%d)\n",
                    addr, addr + size, is_pal_internal, check_vma_above->bottom,
                    check_vma_above->top, check_vma_above->is_pal_internal);
            return NULL;
        }
        check_vma_above = LISTP_PREV_ENTRY(check_vma_above, &g_heap_vma_list, list);
    }

    /* check whether [addr, addr + size) overlaps with below VMAs of different type */
    struct heap_vma* check_vma_below = vma_below;
    while (check_vma_below && addr < check_vma_below->top) {
        if (check_vma_below->is_pal_internal != is_pal_internal) {
            SGX_DBG(DBG_M, "VMA %p-%p (internal=%d) overlaps with %p-%p (internal=%d)\n",
                    addr, addr + size, is_pal_internal, check_vma_below->bottom,
                    check_vma_below->top, check_vma_below->is_pal_internal);
            return NULL;
        }
        check_vma_below = LISTP_NEXT_ENTRY(check_vma_below, &g_heap_vma_list, list);
    }

    /* create VMA with [addr, addr+size); in case of existing overlapping VMAs, the created VMA is
     * merged with them and the old VMAs are discarded, similar to mmap(MAX_FIXED) */
    struct heap_vma* vma = __alloc_vma();
    if (!vma)
        return NULL;
    vma->bottom          = addr;
    vma->top             = addr + size;
    vma->is_pal_internal = is_pal_internal;

    /* how much memory was freed because [addr, addr + size) overlapped with VMAs */
    size_t freed = 0;

    /* Try to merge VMAs as an optimization:
     *   (1) start from `vma_above` and iterate through VMAs with higher-addresses for merges
     *   (2) start from `vma_below` and iterate through VMAs with lower-addresses for merges.
     * Note that we never merge normal VMAs with pal-internal VMAs. */
    while (vma_above && vma_above->bottom <= vma->top &&
           vma_above->is_pal_internal == vma->is_pal_internal) {
        /* newly created VMA grows into above VMA; expand newly created VMA and free above-VMA */
        SGX_DBG(DBG_M, "Merge %p-%p and %p-%p\n", vma->bottom, vma->top,
                vma_above->bottom, vma_above->top);

        freed += vma_above->top - vma_above->bottom;
        struct heap_vma* vma_above_above = LISTP_PREV_ENTRY(vma_above, &g_heap_vma_list, list);

        vma->bottom = MIN(vma_above->bottom, vma->bottom);
        vma->top    = MAX(vma_above->top, vma->top);
        LISTP_DEL(vma_above, &g_heap_vma_list, list);

        __free_vma(vma_above);
        vma_above = vma_above_above;
    }

    while (vma_below && vma_below->top >= vma->bottom &&
           vma_below->is_pal_internal == vma->is_pal_internal) {
        /* newly created VMA grows into below VMA; expand newly create VMA and free below-VMA */
        SGX_DBG(DBG_M, "Merge %p-%p and %p-%p\n", vma->bottom, vma->top,
                vma_below->bottom, vma_below->top);

        freed += vma_below->top - vma_below->bottom;
        struct heap_vma* vma_below_below = LISTP_NEXT_ENTRY(vma_below, &g_heap_vma_list, list);

        vma->bottom = MIN(vma_below->bottom, vma->bottom);
        vma->top    = MAX(vma_below->top, vma->top);
        LISTP_DEL(vma_below, &g_heap_vma_list, list);

        __free_vma(vma_below);
        vma_below = vma_below_below;
    }

    INIT_LIST_HEAD(vma, list);
    LISTP_ADD_AFTER(vma, vma_above, &g_heap_vma_list, list);
    SGX_DBG(DBG_M, "Created vma %p-%p\n", vma->bottom, vma->top);

    if (vma->bottom >= vma->top) {
        SGX_DBG(DBG_E, "*** Bad memory bookkeeping: %p - %p ***\n", vma->bottom, vma->top);
        ocall_exit(/*exitcode=*/1, /*is_exitgroup=*/true);
    }

    assert(vma->top - vma->bottom >= (ptrdiff_t)freed);
    size_t allocated = vma->top - vma->bottom - freed;
    atomic_add(allocated / g_page_size, &g_alloced_pages);
    return addr;
}

void* get_enclave_pages(void* addr, size_t size, bool is_pal_internal) {
    void* ret = NULL;

    if (!size)
        return NULL;

    size = ALIGN_UP(size, g_page_size);
    addr = ALIGN_DOWN_PTR(addr, g_page_size);

    assert(access_ok(addr, size));

    SGX_DBG(DBG_M, "Allocating %lu bytes in enclave memory at %p (%s)\n", size, addr,
            is_pal_internal ? "PAL internal" : "normal");

    struct heap_vma* vma_above = NULL;
    struct heap_vma* vma;

    _DkInternalLock(&g_heap_vma_lock);

    if (addr) {
        /* caller specified concrete address; find VMA right-above this address */
        if (addr < g_heap_bottom || addr + size > g_heap_top)
            goto out;

        LISTP_FOR_EACH_ENTRY(vma, &g_heap_vma_list, list) {
            if (vma->bottom < addr) {
                /* current VMA is not above `addr`, thus vma_above is VMA right-above `addr` */
                break;
            }
            vma_above = vma;
        }
        ret = __create_vma_and_merge(addr, size, is_pal_internal, vma_above);
    } else {
        /* caller did not specify address; find first (highest-address) empty slot that fits */
        void* vma_above_bottom = g_heap_top;

        LISTP_FOR_EACH_ENTRY(vma, &g_heap_vma_list, list) {
            if (vma->top < vma_above_bottom - size) {
                ret = __create_vma_and_merge(vma_above_bottom - size, size, is_pal_internal, vma_above);
                goto out;
            }
            vma_above = vma;
            vma_above_bottom = vma_above->bottom;
        }

        /* corner case: there may be enough space between heap bottom and the lowest-address VMA */
        if (g_heap_bottom < vma_above_bottom - size)
            ret = __create_vma_and_merge(vma_above_bottom - size, size, is_pal_internal, vma_above);
    }

out:
    _DkInternalUnlock(&g_heap_vma_lock);
    return ret;
}

int free_enclave_pages(void* addr, size_t size) {
    int ret = 0;

    if (!size)
        return -PAL_ERROR_NOMEM;

    size = ALIGN_UP(size, g_page_size);

    if (!access_ok(addr, size) || !IS_ALIGNED_PTR(addr, g_page_size) ||
        addr < g_heap_bottom || addr + size > g_heap_top) {
        return -PAL_ERROR_INVAL;
    }

    SGX_DBG(DBG_M, "Freeing %lu bytes in enclave memory at %p\n", size, addr);

    _DkInternalLock(&g_heap_vma_lock);

    /* VMA list contains both normal and pal-internal VMAs; it is impossible to free an area
     * that overlaps with VMAs of two types at the same time, so we fail in such cases */
    bool is_pal_internal_set = false;
    bool is_pal_internal;

    /* how much memory was actually freed, since [addr, addr + size) can overlap with VMAs */
    size_t freed = 0;

    struct heap_vma* vma;
    struct heap_vma* p;
    LISTP_FOR_EACH_ENTRY_SAFE(vma, p, &g_heap_vma_list, list) {
        if (vma->bottom >= addr + size)
            continue;
        if (vma->top <= addr)
            break;

        /* found VMA overlapping with area to free; check it is either normal or pal-internal */
        if (!is_pal_internal_set) {
            is_pal_internal = vma->is_pal_internal;
            is_pal_internal_set = true;
        }

        if (is_pal_internal != vma->is_pal_internal) {
            SGX_DBG(DBG_E, "*** Area to free (address %p, size %lu) overlaps with both normal and "
                    "pal-internal VMAs ***\n", addr, size);
            ret = -PAL_ERROR_INVAL;
            goto out;
        }

        freed += MIN(vma->top, addr + size) - MAX(vma->bottom, addr);

        if (vma->bottom < addr) {
            /* create VMA [vma->bottom, addr); this may leave VMA [addr + size, vma->top), see below */
            struct heap_vma* new = __alloc_vma();
            if (!new) {
                SGX_DBG(DBG_E, "*** Cannot create split VMA during free of address %p ***\n", addr);
                ret = -PAL_ERROR_NOMEM;
                goto out;
            }
            new->top             = addr;
            new->bottom          = vma->bottom;
            new->is_pal_internal = vma->is_pal_internal;
            INIT_LIST_HEAD(new, list);
            LIST_ADD(new, vma, list);
        }

        /* compress overlapping VMA to [addr + size, vma->top) */
        vma->bottom = addr + size;
        if (vma->top <= addr + size) {
            /* memory area to free completely covers/extends above the rest of the VMA */
            LISTP_DEL(vma, &g_heap_vma_list, list);
            __free_vma(vma);
        }
    }

    atomic_sub(freed / g_page_size, &g_alloced_pages);

out:
    _DkInternalUnlock(&g_heap_vma_lock);
    return ret;
}

/* returns current highest available address on the enclave heap */
void* get_enclave_heap_top(void) {
    _DkInternalLock(&g_heap_vma_lock);

    void* addr = g_heap_top;
    struct heap_vma* vma;
    LISTP_FOR_EACH_ENTRY(vma, &g_heap_vma_list, list) {
        if (vma->top < addr) {
            goto out;
        }
        addr = vma->bottom;
    }

out:
    _DkInternalUnlock(&g_heap_vma_lock);
    return addr;
}
