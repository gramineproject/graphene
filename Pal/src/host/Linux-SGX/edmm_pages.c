#include "edmm_pages.h"

#include <asm/errno.h>
#include <stdalign.h>

#include "api.h"
#include "list.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_security.h"

extern void* g_heap_top;
extern spinlock_t g_heap_vma_lock;
static uint64_t g_pending_free_size;
uint64_t g_edmm_lazyfree_th_bytes;

static LISTP_TYPE(edmm_heap_pool) g_edmm_heap_pool_list = LISTP_INIT;

static struct edmm_heap_pool g_edmm_heap_pool[MAX_EDMM_HEAP_RANGE];
static size_t g_edmm_heap_rg_cnt;
static struct edmm_heap_pool* g_edmm_heap_rg = NULL;

/* returns uninitialized edmm heap range */
static struct edmm_heap_pool* __alloc_heap(void) {
    assert(spinlock_is_locked(&g_heap_vma_lock));

    if (g_edmm_heap_rg) {
        /* simple optimization: if there is a cached free vma object, use it */
        assert((uintptr_t)g_edmm_heap_rg >= (uintptr_t)&g_edmm_heap_pool[0]);
        assert((uintptr_t)g_edmm_heap_rg <= (uintptr_t)&g_edmm_heap_pool[MAX_EDMM_HEAP_RANGE - 1]);

        struct edmm_heap_pool* ret = g_edmm_heap_rg;
        g_edmm_heap_rg = NULL;
        g_edmm_heap_rg_cnt++;
        return ret;
    }

    for (size_t i = 0; i < MAX_EDMM_HEAP_RANGE; i++) {
        if (!g_edmm_heap_pool[i].addr && !g_edmm_heap_pool[i].size) {
            /* found empty slot in the pool, use it */
            g_edmm_heap_rg_cnt++;
            return &g_edmm_heap_pool[i];
        }
    }

    return NULL;
}

static void __free_heap(struct edmm_heap_pool* heap_rg) {
    assert(spinlock_is_locked(&g_heap_vma_lock));
    assert((uintptr_t)heap_rg >= (uintptr_t)&g_edmm_heap_pool[0]);
    assert((uintptr_t)heap_rg <= (uintptr_t)&g_edmm_heap_pool[MAX_EDMM_HEAP_RANGE - 1]);

    heap_rg->addr = NULL;
    heap_rg->size = 0;
    g_edmm_heap_rg = heap_rg;
    g_edmm_heap_rg_cnt--;
}

/* Returns size that is non overlapping with the pre-allocated heap when preheat option is true.
 * 0 means entire request overlaps with the pre-allocated region. */
size_t find_preallocated_heap_nonoverlap(void* addr, size_t size) {
    if (!g_pal_sec.preheat_enclave_sz) {
        return size;
    }

    size_t non_overlapping_sz;
    if ((char*)addr >= (char*)g_heap_top - g_pal_sec.preheat_enclave_sz)
        /* Full overlap: Entire request lies in the pre-allocated region */
        non_overlapping_sz = 0;
    else if ((char*)addr + size > (char*)g_heap_top - g_pal_sec.preheat_enclave_sz)
        /* Partial overlap: Update size to skip the overlapped region. */
        non_overlapping_sz = (char*)g_heap_top - g_pal_sec.preheat_enclave_sz - (char*)addr;
    else
        /* No overlap */
        non_overlapping_sz = size;


    return non_overlapping_sz;
}

/* This function adds free EPC page requests to a global list and frees the EPC pages in a lazy
 * manner once the amount of free EPC pages exceeds a certain threshold. Returns 0 on success and
 * negative unix error code on failure. */
int add_to_pending_free_epc(void* addr, size_t size) {
    assert(spinlock_is_locked(&g_heap_vma_lock));

    /* Allocate new entry for pending_free_epc range */
    struct edmm_heap_pool* new_pending_free = __alloc_heap();
    if (!new_pending_free) {
        log_error("Adding to pending free EPC pages failed %p\n", addr);
        return -PAL_ERROR_NOMEM;
    }
    new_pending_free->addr = addr;
    new_pending_free->size = size;

    struct edmm_heap_pool* pending_free_epc;
    struct edmm_heap_pool* pending_above = NULL;
    LISTP_FOR_EACH_ENTRY(pending_free_epc, &g_edmm_heap_pool_list, list) {
        if (pending_free_epc->addr < addr)
            break;
        pending_above = pending_free_epc;
    }

    struct edmm_heap_pool* pending_below = NULL;
    if (pending_above) {
        pending_below = LISTP_NEXT_ENTRY(pending_above, &g_edmm_heap_pool_list, list);
    } else {
        /* no previous entry found. This is the first entry which is below [addr, addr+size) */
        pending_below = LISTP_FIRST_ENTRY(&g_edmm_heap_pool_list, struct edmm_heap_pool, list);
    }

    if (pending_above && pending_above->addr == addr + size) {
        new_pending_free->size += pending_above->size;
        struct edmm_heap_pool* pending_above_above = LISTP_PREV_ENTRY(pending_above,
                                                                      &g_edmm_heap_pool_list, list);
        LISTP_DEL(pending_above, &g_edmm_heap_pool_list, list);
         __free_heap(pending_above);

        pending_above = pending_above_above;
    }

    if (pending_below && pending_below->addr + pending_below->size == addr) {
        new_pending_free->addr = pending_below->addr;
        new_pending_free->size += pending_below->size;

        LISTP_DEL(pending_below, &g_edmm_heap_pool_list, list);
        __free_heap(pending_below);
    }

    INIT_LIST_HEAD(new_pending_free, list);
    LISTP_ADD_AFTER(new_pending_free, pending_above, &g_edmm_heap_pool_list, list);

    /* update the pending free size */
    g_pending_free_size += size;

    /* Keep freeing last entry from the pending_free_epc list until the pending free falls
     * below the threshold */
    while (g_pending_free_size > g_edmm_lazyfree_th_bytes) {
        struct edmm_heap_pool* last_pending_free = LISTP_LAST_ENTRY(&g_edmm_heap_pool_list,
                                                                    struct edmm_heap_pool, list);

        int ret = free_edmm_page_range(last_pending_free->addr, last_pending_free->size);
        if (ret < 0) {
            log_error("%s:Free failed! g_edmm_lazyfree_th_bytes = 0x%lx, g_pending_free_size = 0x%lx,"
                      " last_addr = %p, last_size = 0x%lx, req_addr = %p, req_size = 0x%lx\n",
                      __func__, g_edmm_lazyfree_th_bytes, g_pending_free_size,
                      last_pending_free->addr, last_pending_free->size, addr, size);
            return ret;
        }

        if (g_pending_free_size >= last_pending_free->size) {
            g_pending_free_size -= last_pending_free->size;
        } else {
            g_pending_free_size = 0;
        }

        LISTP_DEL(last_pending_free, &g_edmm_heap_pool_list, list);
        __free_heap(last_pending_free);
    }

    return 0;
}

/* This function checks if the requested EPC range overlaps with range in pending free EPC list.
 * If so, removes overlapping requested range from the EPC list. This can cause the requested range
 * be fragmented into smaller requests. On success, returns number of fragmented requests and
 * negative unix error code on failure. */
int remove_from_pending_free_epc(void* addr, size_t size,
                                 struct edmm_heap_pool* updated_heap_alloc) {
    assert(spinlock_is_locked(&g_heap_vma_lock));
    size_t allocated = 0;
    int alloc_cnt = 0;

    if (!g_pal_sec.edmm_lazyfree_th || !g_pending_free_size)
        goto out;

    struct edmm_heap_pool* pending_free_epc;
    struct edmm_heap_pool* temp;
    LISTP_FOR_EACH_ENTRY_SAFE(pending_free_epc, temp, &g_edmm_heap_pool_list, list) {
        void* pendingfree_top = (char*)pending_free_epc->addr + pending_free_epc->size;
        void* pendingfree_bottom = pending_free_epc->addr;

        if (pendingfree_bottom >= (void*)((char*)addr + size))
            continue;
        if (pendingfree_top <= addr)
            break;

        if (pendingfree_bottom < addr) {
            /* create a new entry for [pendingfree_bottom, addr) */
            struct edmm_heap_pool* new_pending_free = __alloc_heap();
            if (!new_pending_free) {
                log_error("Updating pending free EPC pages failed during allocation %p\n", addr);
                return -ENOMEM;
            }
            new_pending_free->addr = pendingfree_bottom;
            new_pending_free->size = (char*)addr - (char*)pendingfree_bottom;

            /* update size of the current pending_free entry after inserting new entry */
            pending_free_epc->addr = addr;
            pending_free_epc->size -= new_pending_free->size;

            /* Adjust helper variable */
            pendingfree_bottom = pending_free_epc->addr;

            INIT_LIST_HEAD(new_pending_free, list);
            LIST_ADD(new_pending_free, pending_free_epc, list);
        }

        if (pendingfree_top <= (void*)((char*)addr + size)) {
            /* Special case when [addr, addr + size) exceeds a pending free region.
             * So split into [addr, pendingfree_bottom) and [pendingfree_top, addr + size) */
            if (pendingfree_bottom > addr && pendingfree_top < (void*)((char*)addr + size)) {
                updated_heap_alloc[alloc_cnt].addr = pendingfree_top;
                updated_heap_alloc[alloc_cnt].size = (char*)addr + size - (char*)pendingfree_top;
                alloc_cnt++;
                allocated += pending_free_epc->size;
                size = (char*)pendingfree_bottom - (char*)addr;
                goto release_entry;
            }

            /* Requested region either fully/partially overlaps with pending free epc range. So we
             * can remove it from pending_free_epc list and update addr and size accordingly.
             * Note: Here pendingfree_bottom >= addr condition will always be true even for
             * pendingfree_bottom < *addr case due to earlier adjustment. */
            if (pendingfree_top < (void*)((char*)addr + size)) {
                addr = pendingfree_top;
            }

            allocated += pending_free_epc->size;
            size = size - pending_free_epc->size;

release_entry:
            LISTP_DEL(pending_free_epc, &g_edmm_heap_pool_list, list);
            __free_heap(pending_free_epc);
        } else {
            /* Adjust pending_free_epc [addr + size, pendingfree_top) to remove allocated region */
            pending_free_epc->addr = (void*)((char*)addr + size);
            pending_free_epc->size = (char*)pendingfree_top - ((char*)addr + size);

            if (pendingfree_bottom >= addr) {
                allocated += (char*)addr + size - (char*)pendingfree_bottom;
                size = (char*)pendingfree_bottom - (char*)addr;
            } else {
                allocated = size;
                size = 0;
            }
        }
    }

out:
    if (size) {
        updated_heap_alloc[alloc_cnt].addr = addr;
        updated_heap_alloc[alloc_cnt].size =  size;
        alloc_cnt++;
    }

    /* update the pending free size amount allocated*/
    if (allocated)
        g_pending_free_size -= allocated;

    return alloc_cnt;
}

/* This function trims EPC pages on enclave's request. The sequence is as below:
 * 1. Enclave calls SGX driver IOCTL to change the page's type to PT_TRIM.
 * 2. Driver invokes ETRACK to track page's address on all CPUs and issues IPI to flush stale TLB
 * entries.
 * 3. Enclave issues an EACCEPT to accept changes to each EPC page.
 * 4. Enclave notifies the driver to remove EPC pages (using an IOCTL).
 * 5. Driver issues EREMOVE to complete the request. */
int free_edmm_page_range(void* start, size_t size) {
    void* end = (void*)((char*)start + size);
    int ret = 0;

    alignas(64) sgx_arch_sec_info_t secinfo;
    secinfo.flags = SGX_SECINFO_FLAGS_TRIM | SGX_SECINFO_FLAGS_MODIFIED;
    memset(&secinfo.reserved, 0, sizeof(secinfo.reserved));

    size_t nr_pages = size / g_pal_state.alloc_align;
    ret = ocall_trim_epc_pages(start, nr_pages);
    if (ret < 0) {
        log_error("EPC trim page on [%p, %p) failed (errno = %d)\n", start, end, ret);
        return ret;
    }

    for (void* page_addr = start; page_addr < end;
        page_addr = (void*)((char*)page_addr + g_pal_state.alloc_align)) {
        ret = sgx_accept(&secinfo, page_addr);
        if (ret) {
            log_error("EDMM accept page failed with %d while trimming %p\n", ret, page_addr);
            return -EFAULT;
        }
    }

    ret = ocall_notify_accept(start, nr_pages);
    if (ret < 0) {
        log_error("EPC notify_accept failed for range [%p, %p), %ld pages (errno = %d)\n", start,
                   end, nr_pages, ret);
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
int get_edmm_page_range(void* start, size_t size, bool executable) {
    if (g_pal_sec.edmm_batch_alloc) {
        /* Pass faulting address to the driver for EAUGing the range */
        int tid = pal_get_cur_tid();
        assert(tid);

        struct sgx_eaug_range_param *eaug_range = (struct sgx_eaug_range_param*)g_pal_sec.eaug_base;
        eaug_range[tid-1].fault_addr = (unsigned long)((char*)start + size -
                                                       g_pal_state.alloc_align);
        eaug_range[tid-1].mem_seg = HEAP;
        eaug_range[tid-1].num_pages = size / g_pal_state.alloc_align;

        log_debug("TID= %d, fault_addr = 0x%lx, mem_seg = %d, num_pages = %d\n",
                  tid-1, eaug_range[tid-1].fault_addr, eaug_range[tid-1].mem_seg,
                  eaug_range[tid-1].num_pages);
    }

    void* lo = start;
    void* addr = (void*)((char*)lo + size);

    alignas(64) sgx_arch_sec_info_t secinfo;
    secinfo.flags = SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W | SGX_SECINFO_FLAGS_REG |
                    SGX_SECINFO_FLAGS_PENDING;
    memset(&secinfo.reserved, 0, sizeof(secinfo.reserved));

    while (lo < addr) {
        addr = (void*)((char*)addr - g_pal_state.alloc_align);

        int ret = sgx_accept(&secinfo, addr);
        if (ret) {
            log_error("EDMM accept page failed: %p org_start = %p, org_size=0x%lx ret=%d\n", addr,
                       start, size, ret);
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