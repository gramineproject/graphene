#include "enclave_pages.h"

#include <asm/errno.h>
#include <stdalign.h>

#include "api.h"
#include "list.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_security.h"
#include "spinlock.h"

struct atomic_int g_allocated_pages;

static void* g_heap_bottom;
static void* g_heap_top;

static size_t g_pal_internal_mem_used = 0;

/* list of VMAs of used memory areas kept in DESCENDING order; note that preallocated PAL internal
 * memory relies on this descending order of allocations (from high addresses to low), see
 * _DkGetAvailableUserAddressRange() for more details */
DEFINE_LIST(heap_vma);
struct heap_vma {
    LIST_TYPE(heap_vma) list;
    void* bottom;
    void* top;
    bool is_pal_internal;
};
DEFINE_LISTP(heap_vma);

struct edmm_heap_range {
    void* addr;
    size_t size;
};

static LISTP_TYPE(heap_vma) g_heap_vma_list = LISTP_INIT;
static spinlock_t g_heap_vma_lock = INIT_SPINLOCK_UNLOCKED;

/* heap_vma objects are taken from pre-allocated pool to avoid recursive mallocs */
#define MAX_HEAP_VMAS 100000
/* TODO: Setting this as 64 to start with, but will need to revisit */
#define EDMM_HEAP_RANGE_CNT 64
static struct heap_vma g_heap_vma_pool[MAX_HEAP_VMAS];
static size_t g_heap_vma_num = 0;
static struct heap_vma* g_free_vma = NULL;

/* returns uninitialized heap_vma, the caller is responsible for setting at least bottom/top */
static struct heap_vma* __alloc_vma(void) {
    assert(spinlock_is_locked(&g_heap_vma_lock));

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
    assert(spinlock_is_locked(&g_heap_vma_lock));
    assert((uintptr_t)vma >= (uintptr_t)&g_heap_vma_pool[0]);
    assert((uintptr_t)vma <= (uintptr_t)&g_heap_vma_pool[MAX_HEAP_VMAS - 1]);

    g_free_vma  = vma;
    vma->top    = 0;
    vma->bottom = 0;
    g_heap_vma_num--;
}

int init_enclave_pages(void) {
    g_heap_bottom = g_pal_sec.heap_min;
    g_heap_top    = g_pal_sec.heap_max;
    log_debug("%s: g_heap_bottom: %p, g_heap_top: %p\n", __func__, g_heap_bottom, g_heap_top);
    return 0;
}

/* Returns size that is non overlapping with the pre-allocated heap when preheat option is turned on.
 * 0 means entire request overlaps with the pre-allocated region. */
static size_t find_preallocated_heap_nonoverlap(void* addr, size_t size) {
    size_t non_overlapping_sz = size;

    if (g_pal_sec.preheat_enclave_sz > 0) {
        if ((char*)addr >= (char*)g_heap_top - g_pal_sec.preheat_enclave_sz)
            /* Full overlap: Entire request lies in the pre-allocated region */
            non_overlapping_sz = 0;
        else if ((char*)addr + size > (char*)g_heap_top - g_pal_sec.preheat_enclave_sz)
            /* Partial overlap: Update size to skip the overlapped region. */
            non_overlapping_sz = (char*)g_heap_top - g_pal_sec.preheat_enclave_sz - (char*)addr;
        else
            /* No overlap */
            non_overlapping_sz = size;
    }

    return non_overlapping_sz;
}

/* This function trims EPC pages on enclave's request. The sequence is as below:
 * 1. Enclave calls SGX driver IOCTL to change the page's type to PT_TRIM.
 * 2. Driver invokes ETRACK to track page's address on all CPUs and issues IPI to flush stale TLB
 * entries.
 * 3. Enclave issues an EACCEPT to accept changes to each EPC page.
 * 4. Enclave notifies the driver to remove EPC pages (using an IOCTL).
 * 5. Driver issues EREMOVE to complete the request. */
static int free_edmm_page_range(void* start, size_t size) {
    void* addr = ALLOC_ALIGN_DOWN_PTR(start);
    size_t non_overlapping_sz = find_preallocated_heap_nonoverlap(addr, size);
    log_debug("%s: preallocated heap addr = %p, org_size = %lx, updated_size=%lx\n", __func__, addr,
              size, non_overlapping_sz);

    /* Entire request overlaps with preallocated heap, so simply return. */
    if (non_overlapping_sz == 0)
        return 0;
    else
        size = non_overlapping_sz;

    void* end = (void*)((char*)addr + size);
    int ret = 0;

    alignas(64) sgx_arch_sec_info_t secinfo;
    secinfo.flags = SGX_SECINFO_FLAGS_TRIM | SGX_SECINFO_FLAGS_MODIFIED;
    memset(&secinfo.reserved, 0, sizeof(secinfo.reserved));

    size_t nr_pages = size / g_pal_state.alloc_align;
    ret = ocall_trim_epc_pages(addr, nr_pages);
    if (ret < 0) {
        log_debug("EPC trim page on [%p, %p) failed (%d)\n", addr, end, ret);
        return ret;
    }

    for (void* page_addr = addr; page_addr < end;
        page_addr = (void*)((char*)page_addr + g_pal_state.alloc_align)) {
        ret = sgx_accept(&secinfo, page_addr);
        if (ret) {
            log_debug("EDMM accept page failed while trimming: %p %d\n", page_addr, ret);
            return -EFAULT;
        }
    }

    ret = ocall_notify_accept(addr, nr_pages);
    if (ret < 0) {
        log_debug("EPC notify_accept on [%p, %p), %ld pages failed (%d)\n", addr, end, nr_pages, ret);
        return ret;
    }

    return 0;
}

/* This function allocates EPC pages within ELRANGE of an enclave. If EPC pages contain
 * executable code, page permissions are extended once the page is in a valid state. The
 * allocation sequence is described below:
 * 1. Enclave invokes EACCEPT on a new page request which triggers a page fault (#PF) as the page
 * is not available yet.
 * 2. Driver catches this #PF and issues EAUG for the page (at this point the page becomes VALID and
 * may be used by the enclave). The control returns back to enclave.
 * 3. Enclave continues the same EACCEPT and the instruction succeeds this time. */
static int get_edmm_page_range(void* start, size_t size, bool executable) {
    size_t non_overlapping_sz = find_preallocated_heap_nonoverlap(start, size);
    log_debug("%s: preallocated heap addr = %p, org_size = %lx, updated_size=%lx\n", __func__,
              start, size, non_overlapping_sz);

    /* Entire request overlaps with preallocated heap, so simply return. */
    if (non_overlapping_sz == 0)
        return 0;
    else
        size = non_overlapping_sz;

    void* lo = start;
    void* addr = (void*)((char*)lo + size);

    alignas(64) sgx_arch_sec_info_t secinfo;
    secinfo.flags = SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W | SGX_SECINFO_FLAGS_REG |
                    SGX_SECINFO_FLAGS_PENDING;
    memset(&secinfo.reserved, 0, sizeof(secinfo.reserved));

    while (lo < addr) {
        int ret;
        addr = (void*)((char*)addr - g_pal_state.alloc_align);

        ret = sgx_accept(&secinfo, addr);
        if (ret) {
            log_debug("EDMM accept page failed: %p %d\n", addr, ret);
            return -EFAULT;
        }

        /* All new pages will have RW permissions initially, so after EAUG/EACCEPT, extend
         * permission of a VALID enclave page (if needed). */
        if (executable) {
            alignas(64) sgx_arch_sec_info_t secinfo_extend = secinfo;

            secinfo_extend.flags |= SGX_SECINFO_FLAGS_X;
            sgx_modpe(&secinfo_extend, addr);
        }
    }

    return 0;
}

static void* __create_vma_and_merge(void* addr, size_t size, bool is_pal_internal,
                                    struct heap_vma* vma_above,
                                    struct edmm_heap_range* heap_ranges_to_alloc) {
    assert(spinlock_is_locked(&g_heap_vma_lock));
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
            return NULL;
        }
        check_vma_above = LISTP_PREV_ENTRY(check_vma_above, &g_heap_vma_list, list);
    }

    /* check whether [addr, addr + size) overlaps with below VMAs of different type */
    struct heap_vma* check_vma_below = vma_below;
    while (check_vma_below && addr < check_vma_below->top) {
        if (check_vma_below->is_pal_internal != is_pal_internal) {
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
    int unallocated_cnt = 0;
    void* unallocated_start_addr = (vma_below) ? MAX(vma_below->top, vma->bottom) : vma->bottom;
    while (vma_above && vma_above->bottom <= vma->top &&
           vma_above->is_pal_internal == vma->is_pal_internal) {
        /* newly created VMA grows into above VMA; expand newly created VMA and free above-VMA */
        freed += vma_above->top - vma_above->bottom;
        struct heap_vma* vma_above_above = LISTP_PREV_ENTRY(vma_above, &g_heap_vma_list, list);

        /* Track unallocated memory regions between VMAs while merging `vma_above`. */
        if (g_pal_sec.edmm_enable_heap && vma_above->bottom > unallocated_start_addr) {
            assert(unallocated_cnt < EDMM_HEAP_RANGE_CNT);
            heap_ranges_to_alloc[unallocated_cnt].size = vma_above->bottom - unallocated_start_addr;
            heap_ranges_to_alloc[unallocated_cnt].addr = unallocated_start_addr;
            unallocated_cnt++;
        }

        vma->bottom = MIN(vma_above->bottom, vma->bottom);
        vma->top    = MAX(vma_above->top, vma->top);
        LISTP_DEL(vma_above, &g_heap_vma_list, list);

        /* Store vma_above->top to check for any free region between vma_above->top and
         * vma_above_above->bottom. */
        if (g_pal_sec.edmm_enable_heap)
            unallocated_start_addr = vma_above->top;

        __free_vma(vma_above);
        vma_above = vma_above_above;
    }

    while (vma_below && vma_below->top >= vma->bottom &&
           vma_below->is_pal_internal == vma->is_pal_internal) {
        /* newly created VMA grows into below VMA; expand newly create VMA and free below-VMA */
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

    if (vma->bottom >= vma->top) {
        log_error("Bad memory bookkeeping: %p - %p", vma->bottom, vma->top);
        ocall_exit(/*exitcode=*/1, /*is_exitgroup=*/true);
    }

    assert(vma->top - vma->bottom >= (ptrdiff_t)freed);
    size_t allocated = vma->top - vma->bottom - freed;

    /* No unallocated memory regions between VMAs found */
    if (g_pal_sec.edmm_enable_heap && unallocated_cnt == 0 && allocated > 0) {
        heap_ranges_to_alloc[0].size = allocated;
        heap_ranges_to_alloc[0].addr = unallocated_start_addr;
    }

    __atomic_add_fetch(&g_allocated_pages.counter, allocated / g_page_size, __ATOMIC_SEQ_CST);

    if (is_pal_internal) {
        assert(allocated <= g_pal_internal_mem_size - g_pal_internal_mem_used);
        g_pal_internal_mem_used += allocated;
    }

    return addr;
}

void* get_enclave_pages(void* addr, size_t size, bool is_pal_internal) {
    void* ret = NULL;
    /* TODO: Should we introduce a compiler switch for EDMM? */
    struct edmm_heap_range heap_ranges_to_alloc[EDMM_HEAP_RANGE_CNT] = {0};

    log_debug("%s: edmm alloc start_addr = %p, size = %lx\n", __func__, addr, size);
    if (!size)
        return NULL;

    size = ALIGN_UP(size, g_page_size);
    addr = ALIGN_DOWN_PTR(addr, g_page_size);

    assert(access_ok(addr, size));

    struct heap_vma* vma_above = NULL;
    struct heap_vma* vma;

    spinlock_lock(&g_heap_vma_lock);

    if (is_pal_internal && size > g_pal_internal_mem_size - g_pal_internal_mem_used) {
        /* requested PAL-internal allocation would exceed the limit, fail */
        goto out;
    }

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
        ret = __create_vma_and_merge(addr, size, is_pal_internal, vma_above, heap_ranges_to_alloc);
    } else {
        /* caller did not specify address; find first (highest-address) empty slot that fits */
        void* vma_above_bottom = g_heap_top;

        LISTP_FOR_EACH_ENTRY(vma, &g_heap_vma_list, list) {
            if (vma->top < vma_above_bottom - size) {
                ret = __create_vma_and_merge(vma_above_bottom - size, size, is_pal_internal,
                                             vma_above, heap_ranges_to_alloc);
                goto out;
            }
            vma_above = vma;
            vma_above_bottom = vma_above->bottom;
        }

        /* corner case: there may be enough space between heap bottom and the lowest-address VMA */
        if (g_heap_bottom < vma_above_bottom - size)
            ret = __create_vma_and_merge(vma_above_bottom - size, size, is_pal_internal, vma_above,
                                         heap_ranges_to_alloc);
    }

out:
    /* In order to prevent already accepted pages from being accepted again, we track EPC pages that
     * aren't accepted yet (unallocated heap) and call EACCEPT only on those EPC pages. */
    if (g_pal_sec.edmm_enable_heap && ret != NULL) {
        for (int i = 0; i < EDMM_HEAP_RANGE_CNT; i++) {
            if (!heap_ranges_to_alloc[i].size)
                break;
            int retval = get_edmm_page_range(heap_ranges_to_alloc[i].addr,
                                             heap_ranges_to_alloc[i].size, /*executable=*/true);
            if (retval < 0) {
                ret = NULL;
                break;
            }
        }
    }
    spinlock_unlock(&g_heap_vma_lock);
    return ret;
}

int free_enclave_pages(void* addr, size_t size) {
    int ret = 0;
    /* TODO: Should we introduce a compiler switch for EDMM? */
    struct edmm_heap_range heap_ranges_to_free[EDMM_HEAP_RANGE_CNT] = {0};
    int free_cnt = 0;

    log_debug("%s: edmm free start_addr = %p, size = %lx\n", __func__, addr, size);
    if (!size)
        return -PAL_ERROR_NOMEM;

    size = ALIGN_UP(size, g_page_size);

    if (!access_ok(addr, size) || !IS_ALIGNED_PTR(addr, g_page_size) || addr < g_heap_bottom ||
            addr + size > g_heap_top) {
        return -PAL_ERROR_INVAL;
    }

    spinlock_lock(&g_heap_vma_lock);

    /* VMA list contains both normal and pal-internal VMAs; it is impossible to free an area
     * that overlaps with VMAs of two types at the same time, so we fail in such cases */
    bool is_pal_internal_set = false;
    bool is_pal_internal = false;

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
            log_error("Area to free (address %p, size %lu) overlaps with both normal and "
                      "pal-internal VMAs",
                      addr, size);
            ret = -PAL_ERROR_INVAL;
            goto out;
        }

        void* free_heap_top = MIN(vma->top, addr + size);
        void* free_heap_bottom = MAX(vma->bottom, addr);
        size_t range = free_heap_top - free_heap_bottom;
        freed += range;
        if (g_pal_sec.edmm_enable_heap) {
            /* if range is contiguous with previous entry, update addr and size accordingly;
             * this case may be rare but the below optimization still saves us 2 OCALLs and 2
             * IOCTLs, so should be worth it */
            if (free_cnt > 0 &&
                free_heap_top == heap_ranges_to_free[free_cnt-1].addr) {
                heap_ranges_to_free[free_cnt-1].addr = free_heap_bottom;
                heap_ranges_to_free[free_cnt-1].size += range;
                assert(0);
            } else {
                assert(free_cnt < EDMM_HEAP_RANGE_CNT);
                /* found a new non-contiguous range */
                heap_ranges_to_free[free_cnt].addr = free_heap_bottom;
                heap_ranges_to_free[free_cnt].size = range;
                free_cnt++;
            }
        }

        if (vma->bottom < addr) {
            /* create VMA [vma->bottom, addr); this may leave VMA [addr + size, vma->top), see below */
            struct heap_vma* new = __alloc_vma();
            if (!new) {
                log_error("Cannot create split VMA during freeing of address %p", addr);
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

    __atomic_sub_fetch(&g_allocated_pages.counter, freed / g_page_size, __ATOMIC_SEQ_CST);

    if (is_pal_internal_set && is_pal_internal) {
        assert(g_pal_internal_mem_used >= freed);
        g_pal_internal_mem_used -= freed;
    }

out:
    if (ret >=0 && g_pal_sec.edmm_enable_heap) {
        for (int i = 0; i < free_cnt; i++) {
            ret = free_edmm_page_range(heap_ranges_to_free[i].addr, heap_ranges_to_free[i].size);
            if (ret < 0) {
                ret = -PAL_ERROR_INVAL;
                break;
            }
        }
    }
    spinlock_unlock(&g_heap_vma_lock);
    return ret;
}

/* returns current highest available address on the enclave heap */
void* get_enclave_heap_top(void) {
    spinlock_lock(&g_heap_vma_lock);

    void* addr = g_heap_top;
    struct heap_vma* vma;
    LISTP_FOR_EACH_ENTRY(vma, &g_heap_vma_list, list) {
        if (vma->top < addr) {
            goto out;
        }
        addr = vma->bottom;
    }

out:
    spinlock_unlock(&g_heap_vma_lock);
    return addr;
}
