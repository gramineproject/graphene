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
};
DEFINE_LISTP(heap_vma);

static LISTP_TYPE(heap_vma) g_heap_vma_list = LISTP_INIT;
static PAL_LOCK g_heap_vma_lock = LOCK_INIT;

int init_enclave_pages(void) {
    g_heap_bottom = pal_sec.heap_min;
    g_heap_top    = pal_sec.heap_max;

    size_t reserved_size = 0;
    struct heap_vma* exec_vma = NULL;

    if (pal_sec.exec_addr < g_heap_top && pal_sec.exec_addr + pal_sec.exec_size > g_heap_bottom) {
        /* there is an executable mapped inside the heap, carve a VMA for its area; this can happen
         * in case of non-PIE executables that start at a predefined address (typically 0x400000) */
        exec_vma = malloc(sizeof(*exec_vma));
        if (!exec_vma) {
            SGX_DBG(DBG_E, "*** Cannot initialize VMA for executable ***\n");
            return -PAL_ERROR_NOMEM;
        }
        exec_vma->bottom = SATURATED_P_SUB(pal_sec.exec_addr, MEMORY_GAP, g_heap_bottom);
        exec_vma->top = SATURATED_P_ADD(pal_sec.exec_addr + pal_sec.exec_size, MEMORY_GAP, g_heap_top);
        INIT_LIST_HEAD(exec_vma, list);
        LISTP_ADD(exec_vma, &g_heap_vma_list, list);

        reserved_size += exec_vma->top - exec_vma->bottom;
    }

    atomic_add(reserved_size / g_page_size, &g_alloced_pages);

    SGX_DBG(DBG_M, "Heap size: %luM\n", (g_heap_top - g_heap_bottom - reserved_size) / 1024 / 1024);
    return 0;
}

static void* __create_vma_and_merge(void* addr, size_t size, struct heap_vma* vma_above) {
    assert(_DkInternalIsLocked(&g_heap_vma_lock));
    assert(addr && size);

    if (addr < g_heap_bottom)
        return NULL;

    /* create VMA with [addr, addr+size); in case of existing overlapping VMAs, the created VMA is
     * merged with them and the old VMAs are discarded, similar to mmap(MAX_FIXED) */
    struct heap_vma* vma = malloc(sizeof(*vma));
    if (!vma)
        return NULL;

    vma->bottom = addr;
    vma->top    = addr + size;

    /* find VMAs to merge:
     *   (1) start from `vma_above` and iterate through VMAs with higher-addresses for merges
     *   (2) start from `vma_below` and iterate through VMAs with lower-addresses for merges */
    struct heap_vma* vma_below;
    if (vma_above) {
        vma_below = LISTP_NEXT_ENTRY(vma_above, &g_heap_vma_list, list);
    } else {
        /* no VMA above `addr`; VMA right below `addr` must be the first (highest-address) in list */
        vma_below = LISTP_FIRST_ENTRY(&g_heap_vma_list, struct heap_vma, list);
    }

    while (vma_above && vma_above->bottom <= vma->top) {
        /* newly created VMA grows into above VMA; expand newly created VMA and free above-VMA */
        SGX_DBG(DBG_M, "Merge %p-%p and %p-%p\n", vma->bottom, vma->top,
                vma_above->bottom, vma_above->top);

        struct heap_vma* vma_above_above = LISTP_PREV_ENTRY(vma_above, &g_heap_vma_list, list);

        vma->bottom = MIN(vma_above->bottom, vma->bottom);
        vma->top    = MAX(vma_above->top, vma->top);
        LISTP_DEL(vma_above, &g_heap_vma_list, list);

        free(vma_above);
        vma_above = vma_above_above;
    }

    while (vma_below && vma_below->top >= vma->bottom) {
        /* newly created VMA grows into below VMA; expand newly create VMA and free below-VMA */
        SGX_DBG(DBG_M, "Merge %p-%p and %p-%p\n", vma->bottom, vma->top,
                vma_below->bottom, vma_below->top);

        struct heap_vma* vma_below_below = LISTP_NEXT_ENTRY(vma_below, &g_heap_vma_list, list);

        vma->bottom = MIN(vma_below->bottom, vma->bottom);
        vma->top    = MAX(vma_below->top, vma->top);
        LISTP_DEL(vma_below, &g_heap_vma_list, list);

        free(vma_below);
        vma_below = vma_below_below;
    }

    INIT_LIST_HEAD(vma, list);
    LISTP_ADD_AFTER(vma, vma_above, &g_heap_vma_list, list);
    SGX_DBG(DBG_M, "Created vma %p-%p\n", vma->bottom, vma->top);

    if (vma->bottom >= vma->top) {
        SGX_DBG(DBG_E, "*** Bad memory bookkeeping: %p - %p ***\n", vma->bottom, vma->top);
        ocall_exit(/*exitcode=*/1, /*is_exitgroup=*/true);
    }

    atomic_add(size / g_page_size, &g_alloced_pages);
    return addr;
}

void* get_enclave_pages(void* addr, size_t size) {
    void* ret = NULL;

    if (!size)
        return NULL;

    size = ALIGN_UP(size, g_page_size);
    addr = ALIGN_DOWN_PTR(addr, g_page_size);

    assert(access_ok(addr, size));

    SGX_DBG(DBG_M, "Allocating %ld bytes at %p\n", size, addr);

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
        ret = __create_vma_and_merge(addr, size, vma_above);
    } else {
        /* caller did not specify address; find first (highest-address) empty slot that fits */
        void* vma_above_bottom = g_heap_top;

        LISTP_FOR_EACH_ENTRY(vma, &g_heap_vma_list, list) {
            if (vma->top < vma_above_bottom - size) {
                ret = __create_vma_and_merge(vma_above_bottom - size, size, vma_above);
                goto out;
            }
            vma_above = vma;
            vma_above_bottom = vma_above->bottom;
        }

        /* corner case: there may be enough space between heap bottom and the lowest-address VMA */
        if (g_heap_bottom < vma_above_bottom - size)
            ret = __create_vma_and_merge(vma_above_bottom - size, size, vma_above);
    }

out:
    _DkInternalUnlock(&g_heap_vma_lock);

    if (!ret) {
        SGX_DBG(DBG_E, "*** Cannot allocate %lu bytes on the heap (at address %p) ***\n", size, addr);
    }
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

    SGX_DBG(DBG_M, "Freeing %ld bytes at %p\n", size, addr);

    _DkInternalLock(&g_heap_vma_lock);

    struct heap_vma* vma;
    struct heap_vma* p;
    LISTP_FOR_EACH_ENTRY_SAFE(vma, p, &g_heap_vma_list, list) {
        if (vma->bottom >= addr + size)
            continue;
        if (vma->top <= addr)
            break;

        /* found VMA overlapping with memory area to free */
        if (vma->bottom < addr) {
            /* create VMA [vma->bottom, addr); this may leave VMA [addr + size, vma->top), see below */
            struct heap_vma* new = malloc(sizeof(*new));
            if (!new) {
                SGX_DBG(DBG_E, "*** Cannot create split VMA during free of address %p ***\n", addr);
                ret = -PAL_ERROR_NOMEM;
                goto out;
            }
            new->top    = addr;
            new->bottom = vma->bottom;
            INIT_LIST_HEAD(new, list);
            LIST_ADD(new, vma, list);
        }

        /* compress overlapping VMA to [addr + size, vma->top) */
        vma->bottom = addr + size;
        if (vma->top <= addr + size) {
            /* memory area to free completely covers/extends above the rest of the VMA */
            LISTP_DEL(vma, &g_heap_vma_list, list);
            free(vma);
        }
    }

    atomic_sub(size / g_page_size, &g_alloced_pages);

out:
    _DkInternalUnlock(&g_heap_vma_lock);
    return ret;
}
