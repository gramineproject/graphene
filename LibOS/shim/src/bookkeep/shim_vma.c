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
 * shim_vma.c
 *
 * This file contains code to maintain bookkeeping of VMAs in library OS.
 */

#include <shim_internal.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_vma.h>
#include <shim_checkpoint.h>
#include <shim_fs.h>

#include <pal.h>
#include <list.h>

#include <asm/mman.h>
#include <errno.h>
#include <stdbool.h>

/*
 * Internal bookkeeping for VMAs (virtual memory areas). This data
 * structure can only be accessed in this source file, with g_vma_list_lock
 * held. No reference counting needed in this data structure.
 */
DEFINE_LIST(shim_vma);
/* struct shim_vma tracks the area of [start, end) */
struct shim_vma {
    LIST_TYPE(shim_vma)     list;
    void *                  start;
    void *                  end;
    int                     prot;
    int                     flags;
    off_t                   offset;
    struct shim_handle *    file;
    char                    comment[VMA_COMMENT_LEN];
};

#define VMA_MGR_ALLOC   DEFAULT_VMA_COUNT
#define RESERVED_VMAS   6

static int g_num_reserved_vmas;
static struct shim_vma* g_reserved_vmas[RESERVED_VMAS];

static void * __bkeep_unmapped (void * top_addr, void * bottom_addr,
                                size_t length, int prot, int flags,
                                struct shim_handle * file,
                                off_t offset, const char * comment);

/*
 * Because the default system_malloc() must create VMA(s), we need
 * a new system_malloc() to avoid cicular dependency. This __malloc()
 * stores the VMA address and size in the current thread to delay the
 * bookkeeping until the allocator finishes extension.
 */
static inline void * __malloc (size_t size)
{
    void * addr;
    size = ALLOC_ALIGN_UP(size);

    /*
     * Chia-Che 3/3/18: We must enforce the policy that all VMAs have to
     * be created before issuing the PAL calls.
     */
    addr = __bkeep_unmapped(PAL_CB(user_address.end),
                            PAL_CB(user_address.start), size,
                            PROT_READ|PROT_WRITE,
                            MAP_PRIVATE|MAP_ANONYMOUS|VMA_INTERNAL,
                            NULL, 0, "vma");

    debug("allocate %p-%p for vmas\n", addr, addr + size);

    return (void *) DkVirtualMemoryAlloc(addr, size, 0,
                                         PAL_PROT_WRITE|PAL_PROT_READ);
}

void __free(void* addr, size_t size) {
    __UNUSED(addr);
    __UNUSED(size);

    /* g_vma_mgr is never destroyed. */
    __abort();
}

#undef system_malloc
#define system_malloc __malloc
#undef system_free
#define system_free __free

#define OBJ_TYPE struct shim_vma
#include <memmgr.h>

/*
 * "g_vma_mgr" has no specific lock. "g_vma_list_lock" must be held when
 * allocating or freeing any VMAs.
 */
static MEM_MGR g_vma_mgr = NULL;
/*
 * If assert(!__mem_mgr_enlarged(vma_mgr)) fails, increase the size of g_vma_mgr_area for the
 * needed vmas for initialization.
 */
static uint8_t g_vma_mgr_area[__MAX_MEM_SIZE(VMA_MGR_ALLOC)];

/*
 * "g_vma_list" contains a sorted list of non-overlapping VMAs.
 * "g_vma_list_lock" must be held when accessing either the g_vma_list or any
 * field of a VMA.
 */
DEFINE_LISTP(shim_vma);
static LISTP_TYPE(shim_vma) g_vma_list = LISTP_INIT;
static struct shim_lock g_vma_list_lock;

/*
 * Return true if [s, e) is exactly the area represented by vma.
 */
static inline bool test_vma_equal (struct shim_vma * vma,
                                   void * s, void * e)
{
    assert(s < e);
    return vma->start == s && vma->end == e;
}

/*
 * Return true if [s, e) is part of the area represented by vma.
 */
static inline bool test_vma_contain (struct shim_vma * vma,
                                     void * s, void * e)
{
    assert(s < e);
    return vma->start <= s && vma->end >= e;
}

/*
 * Return true if [s, e) contains the starting address of vma.
 */
static inline bool test_vma_startin (struct shim_vma * vma,
                                     void * s, void * e)
{
    assert(s < e);
    return vma->start >= s && vma->start < e;
}

/*
 * Return true if [s, e) contains the ending address of vma.
 */
static inline bool test_vma_endin (struct shim_vma * vma,
                                   void * s, void * e)
{
    assert(s < e);
    return vma->end > s && vma->end <= e;
}

/*
 * Return true if [s, e) overlaps with the area represented by vma.
 */
static inline bool test_vma_overlap (struct shim_vma * vma,
                                     void * s, void * e)
{
    assert(s < e);
    return test_vma_contain(vma, s, s + 1) ||
           test_vma_contain(vma, e - 1, e) ||
           test_vma_startin(vma, s, e);
}

static inline void __assert_vma_list (void)
{
    assert(locked(&g_vma_list_lock));

    struct shim_vma * tmp;
    struct shim_vma * prev __attribute__((unused)) = NULL;

    LISTP_FOR_EACH_ENTRY(tmp, &g_vma_list, list) {
        /* Assert we are really sorted */
        assert(tmp->end > tmp->start);
        assert(!prev || prev->end <= tmp->start);
        prev = tmp;
    }
}

// In a debug build only, assert that the VMA list is
// sorted.  This should be called with the g_vma_list_lock held.
static inline void assert_vma_list (void)
{
#ifdef DEBUG
    __assert_vma_list();
#endif
}

static struct shim_vma* g_lookup_cache = NULL;

static bool check_addr_vma(void* addr, struct shim_vma* vma,
                           struct shim_vma** pprev, struct shim_vma** found) {
    if (addr < vma->start)
        return true;
    if (test_vma_contain(vma, addr, addr + 1)) {
        *found = vma;
        return true;
    }

    assert(vma->end > vma->start);
    assert(!*pprev || (*pprev)->end <= vma->start);
    *pprev = vma;
    return false;
}

/*
 * __lookup_vma() returns the VMA that contains the address; otherwise,
 * returns NULL. "pprev" returns the highest VMA below the address.
 * __lookup_vma() fills "pprev" even when the function cannot find a
 * matching vma for "addr".
 */
static inline struct shim_vma* __lookup_vma(void* addr, struct shim_vma** pprev) {
    assert(locked(&g_vma_list_lock));

    struct shim_vma* vma;
    struct shim_vma* prev = NULL;
    struct shim_vma* found = NULL;

    /*
     * This speeds only the case when continuously increasing addresses are looked up.
     * This is easy optimization with the hope that it won't harm in cache miss case.
     *
     * TODO: observe memory allocation behavior and optimize for it; in particular, look at:
     *       - bkeep_unmapped_heap()
     *       - bkeep_unmapped_any() = bkeep_unmapped() used by shim_malloc.c
     *       - user app malloc (e.g. malloc() in glibc)
     *
     * Another options is to introduce rb-tree. (or other tree, e.g. splay tree)
     */
    if (g_lookup_cache && g_lookup_cache->end < addr) {
        /* addr is after the cached address, skip to cached VMA. */
        struct shim_vma* tmp;
        prev = g_lookup_cache;
        vma = prev;
        LISTP_FOR_EACH_ENTRY_SAFE_CONTINUE(vma, tmp, &g_vma_list, list) {
            if (check_addr_vma(addr, vma, &prev, &found))
                break;
        }
    } else {
        /* addr is before the cached address, search from the beginning */
        LISTP_FOR_EACH_ENTRY(vma, &g_vma_list, list) {
            if (check_addr_vma(addr, vma, &prev, &found))
                break;
        }
    }

    if (pprev) {
        *pprev = prev;
        if (prev) {
            /* The callers with pprev = NULL are lookup_vma() and lookup_overlap_vma()
             * which seems useless to update g_lookup_cache.
             */
            g_lookup_cache = prev;
        }
    }
    return found;
}

/*
 * __insert_vma() places "vma" after "prev", or at the beginning of
 * g_vma_list if "prev" is NULL. g_vma_list_lock must be held when calling
 * this function.
 */
static inline void
__insert_vma (struct shim_vma * vma, struct shim_vma * prev)
{
    assert(locked(&g_vma_list_lock));
    assert(!prev || prev->end <= vma->start);
    assert(vma != prev);

    /* check the next entry */
    struct shim_vma * next = prev ?
            LISTP_NEXT_ENTRY(prev, &g_vma_list, list) :
            LISTP_FIRST_ENTRY(&g_vma_list, struct shim_vma, list);

    __UNUSED(next);
    assert(!next || vma->end <= next->start);

    if (prev)
        LISTP_ADD_AFTER(vma, prev, &g_vma_list, list);
    else
        LISTP_ADD(vma, &g_vma_list, list);
}

/*
 * __remove_vma() removes "vma" after "prev", or at the beginnning of
 * g_vma_list if "prev" is NULL. g_vma_list_lock must be held when calling
 * this function.
 */
static inline void
__remove_vma (struct shim_vma * vma, struct shim_vma * prev)
{
    assert(locked(&g_vma_list_lock));
    assert(vma != prev);
    if (g_lookup_cache == vma)
        g_lookup_cache = prev;
    LISTP_DEL(vma, &g_vma_list, list);
}

/*
 * Storing a cursor pointing to the current heap top. With ASLR, the cursor
 * is randomized at initialization. The cursor is monotonically decremented
 * when allocating user VMAs. Updating this cursor needs holding g_vma_list_lock.
 */
static void * current_heap_top;

static int __bkeep_mmap (struct shim_vma * prev,
                         void * start, void * end, int prot, int flags,
                         struct shim_handle * file, off_t offset,
                         const char * comment);

static int __bkeep_munmap (struct shim_vma ** prev,
                           void * start, void * end, int flags);

static int __bkeep_mprotect (struct shim_vma * prev,
                             void * start, void * end, int prot, int flags);

static inline void __restore_reserved_vmas(void);

static int
__bkeep_preloaded (void * start, void * end, int prot, int flags,
                   const char * comment)
{
    assert(locked(&g_vma_list_lock));

    if (!start || !end || start == end)
        return 0;

    struct shim_vma * prev = NULL;
    __lookup_vma(start, &prev);
    int ret = __bkeep_mmap(prev, start, end, prot, flags, NULL, 0, comment);
    assert(!mem_mgr_enlarged(g_vma_mgr));
    __restore_reserved_vmas();
    assert(!mem_mgr_enlarged(g_vma_mgr));
    return ret;
}

int init_vma(void) {
    int ret = 0;

    if (!create_lock(&g_vma_list_lock)) {
        return -ENOMEM;
    }

    lock(&g_vma_list_lock);

    /* Initialize the allocator */
    g_vma_mgr = create_mem_mgr_in_place(g_vma_mgr_area, sizeof(g_vma_mgr_area));
    assert(g_vma_mgr);
    for (int i = 0; i < RESERVED_VMAS; i++) {
        g_reserved_vmas[i] = get_mem_obj_from_mgr(g_vma_mgr);
        assert(g_reserved_vmas[i]);
        assert(!mem_mgr_enlarged(g_vma_mgr));
    }
    g_num_reserved_vmas = RESERVED_VMAS;

    /* Bookkeeping for preloaded areas */

    if (PAL_CB(user_address_hole.end) - PAL_CB(user_address_hole.start) > 0) {
        ret = __bkeep_preloaded(PAL_CB(user_address_hole.start),
                                PAL_CB(user_address_hole.end),
                                PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|VMA_UNMAPPED,
                                "reserved");
        if (ret < 0)
            goto out;
    }

    ret = __bkeep_preloaded(PAL_CB(executable_range.start),
                            PAL_CB(executable_range.end),
                            PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|VMA_UNMAPPED,
                            "exec");
    if (ret < 0)
        goto out;

    ret = __bkeep_preloaded(PAL_CB(manifest_preload.start),
                            PAL_CB(manifest_preload.end),
                            PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS|VMA_INTERNAL,
                            "manifest");
    if (ret < 0)
        goto out;

    /* Keep track of LibOS code itself so nothing overwrites it */
    ret = __bkeep_preloaded(&__load_address,
                            ALLOC_ALIGN_UP_PTR(&__load_address_end),
                            PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS|VMA_INTERNAL,
                            "LibOS");
    if (ret < 0)
        goto out;

    current_heap_top = PAL_CB(user_address.end);

#if ENABLE_ASLR == 1
    /*
     * Randomize the heap top in top 5/6 of the user address space.
     * This is a simplified version of the mmap_base() logic in the Linux
     * kernel: https://elixir.bootlin.com/linux/v4.8/ident/mmap_base
     */
    size_t addr_rand_size =
        (PAL_CB(user_address.end) - PAL_CB(user_address.start)) * 5 / 6;
    size_t rand;
    ret = DkRandomBitsRead(&rand, sizeof(rand));
    if (ret < 0) {
        ret = -convert_pal_errno(-ret);
        goto out;
    }
    current_heap_top -= ALLOC_ALIGN_DOWN(rand % addr_rand_size);
#endif

    debug("heap top adjusted to %p\n", current_heap_top);

out:
    unlock(&g_vma_list_lock);
    return ret;
}

static inline struct shim_vma * __get_new_vma (void)
{
    assert(locked(&g_vma_list_lock));

    struct shim_vma* tmp = get_mem_obj_from_mgr(g_vma_mgr);
    if (tmp == NULL) {
        if (g_num_reserved_vmas) {
            tmp = g_reserved_vmas[--g_num_reserved_vmas];
        }
    }

    if (tmp == NULL) {
        /* Should never reach here; if this happens, increase RESERVED_VMAS */
        debug("failed to allocate new vma\n");
        BUG();
        return NULL;
    }
    memset(tmp, 0, sizeof(*tmp));
    INIT_LIST_HEAD(tmp, list);
    return tmp;
}

static inline void __restore_reserved_vmas(void) {
    assert(locked(&g_vma_list_lock));

    while (g_num_reserved_vmas < RESERVED_VMAS) {
        /* get_mem_obj_from_mgr_enlarge() may allocate vma for memory allocation. */
        assert(g_num_reserved_vmas >= 1);
        struct shim_vma * new = get_mem_obj_from_mgr_enlarge(g_vma_mgr,
                                                             size_align_up(VMA_MGR_ALLOC));

        /* this allocation must succeed */
        if (!new)
            __abort();
        g_reserved_vmas[g_num_reserved_vmas++] = new;
    }
}

static inline void __drop_vma (struct shim_vma * vma)
{
    assert(locked(&g_vma_list_lock));
    assert(g_vma_mgr);

    if (vma->file)
        put_handle(vma->file);

    assert(g_lookup_cache != vma);
    if (g_num_reserved_vmas < RESERVED_VMAS)
        g_reserved_vmas[g_num_reserved_vmas++] = vma;
    else
        free_mem_obj_to_mgr(g_vma_mgr, vma);
}

static inline void
__assert_vma_flags (const struct shim_vma * vma, int flags)
{
    if (!(vma->flags & VMA_UNMAPPED)
            && VMA_TYPE(vma->flags) != VMA_TYPE(flags)) {
        debug("Check vma flag failure: vma flags %x, checked flags %x\n",
              vma->flags, flags);
        BUG();
    }
}

static inline void
__set_vma_comment (struct shim_vma * vma, const char * comment)
{
    if (!comment) {
        vma->comment[0] = 0;
        return;
    }

    size_t len = strlen(comment);

    if (len > VMA_COMMENT_LEN - 1)
        len = VMA_COMMENT_LEN - 1;

    memcpy(vma->comment, comment, len);
    vma->comment[len] = 0;
}

/*
 * Add bookkeeping for mmap(). "prev" must point to the the immediately
 * precedent vma of the address to map, or be NULL if no vma is lower than
 * the address. If the bookkeeping area overlaps with some existing vmas,
 * we must check whether the caller (from user, internal code, or checkpointing
 * procedure) is allowed to overwrite the existing vmas.
 *
 * Bookkeeping convention (must follow):
 * Create the bookkeeping BEFORE any allocation PAL calls
 * (DkVirtualMemoryAlloc() or DkStreamMap()).
 */
static int __bkeep_mmap (struct shim_vma * prev,
                         void * start, void * end, int prot, int flags,
                         struct shim_handle * file, off_t offset,
                         const char * comment)
{
    assert(locked(&g_vma_list_lock));

    int ret = 0;
    struct shim_vma * new = __get_new_vma();

    /* First, remove any overlapping VMAs */
    ret = __bkeep_munmap(&prev, start, end, flags);
    if (ret < 0) {
        __drop_vma(new);
        return ret;
    }

    /* Inserting the new VMA */
    new->start  = start;
    new->end    = end;
    new->prot   = prot;
    new->flags  = flags|((file && (prot & PROT_WRITE)) ? VMA_TAINTED : 0);
    new->file   = file;
    if (new->file)
        get_handle(new->file);
    new->offset = offset;
    __set_vma_comment(new, comment);
    __insert_vma(new, prev);
    return 0;
}

int bkeep_mmap (void * addr, size_t length, int prot, int flags,
                struct shim_handle * file, off_t offset, const char * comment)
{
    if (!addr || !length)
        return -EINVAL;

    if (comment && !comment[0])
        comment = NULL;

    debug("bkeep_mmap: %p-%p\n", addr, addr + length);

    lock(&g_vma_list_lock);
    __restore_reserved_vmas();
    struct shim_vma * prev = NULL;
    __lookup_vma(addr, &prev);
    int ret = __bkeep_mmap(prev, addr, addr + length, prot, flags, file, offset,
                           comment);
    assert_vma_list();
    unlock(&g_vma_list_lock);
    return ret;
}

/*
 * __shrink_vma() removes the area in a VMA that overlaps with [start, end).
 * The function deals with three cases:
 * (1) [start, end) overlaps with the beginning of the VMA.
 * (2) [start, end) overlaps with the ending of the VMA.
 * (3) [start, end) overlaps with the middle of the VMA. In this case, the VMA
 *     is splitted into two. The new VMA is stored in 'tailptr'.
 * In either of these cases, "vma" is the only one changed among g_vma_list.
 */
static inline void __shrink_vma (struct shim_vma * vma, void * start, void * end,
                                 struct shim_vma ** tailptr)
{
    assert(locked(&g_vma_list_lock));

    if (test_vma_startin(vma, start, end)) {
        /*
         * Dealing with the head: if the starting address of "vma" is in
         * [start, end), move the starting address.
         */
        if (end < vma->end) {
            if (vma->file) /* must adjust offset */
                vma->offset += end - vma->start;
            vma->start = end;
        } else {
            if (vma->file) /* must adjust offset */
                vma->offset += vma->end - vma->start;
            vma->start = vma->end;
        }
    } else if (test_vma_endin(vma, start, end)) {
        /*
         * Dealing with the tail: if the ending address of "vma" is in
         * [start, end), move the ending address.
         */
        if (start > vma->start) {
            vma->end = start;
        } else {
            vma->end = vma->start;
        }
        /* offset is not affected */
    } else if (test_vma_contain(vma, start, end)) {
        /*
         * If [start, end) is inside the range of "vma", divide up
         * the VMA. A new VMA is created to represent the remaining tail.
         */
        void * old_end = vma->end;
        vma->end = start;

        /* Remaining space after [start, end), creating a new VMA */
        if (old_end > end) {
            struct shim_vma * tail = __get_new_vma();

            tail->start = end;
            tail->end   = old_end;
            tail->prot  = vma->prot;
            tail->flags = vma->flags;
            tail->file  = vma->file;
            if (tail->file) {
                get_handle(tail->file);
                tail->offset = vma->offset + (tail->start - vma->start);
            } else {
                tail->offset = 0;
            }
            memcpy(tail->comment, vma->comment, VMA_COMMENT_LEN);
            *tailptr = tail;
        }
    } else {
        /* Never reach here */
        BUG();
    }

    assert(!test_vma_overlap(vma, start, end));
    assert(vma->start < vma->end);
}

/*
 * Update bookkeeping for munmap(). "*pprev" must point to the immediately
 * precedent vma of the address to unmap, or be NULL if no vma is lower than
 * the address. If the bookkeeping area overlaps with some existing vmas,
 * we must check whether the caller (from user, internal code, or checkpointing
 * procedure) is allowed to overwrite the existing vmas. "pprev" can be
 * updated if a new vma lower than the unmapping address is added.
 *
 * Bookkeeping convention (must follow):
 * Make deallocation PAL calls (DkVirtualMemoryFree() or DkStreamUnmap())
 * BEFORE updating the bookkeeping.
 */
static int __bkeep_munmap (struct shim_vma ** pprev,
                           void * start, void * end, int flags)
{
    assert(locked(&g_vma_list_lock));

    struct shim_vma * prev = *pprev;
    struct shim_vma * cur, * next;

    if (!prev) {
        cur = LISTP_FIRST_ENTRY(&g_vma_list, struct shim_vma, list);
        if (!cur)
            return 0;
    } else {
        cur = LISTP_NEXT_ENTRY(prev, &g_vma_list, list);
    }

    next = cur ? LISTP_NEXT_ENTRY(cur, &g_vma_list, list) : NULL;

    while (cur) {
        struct shim_vma * tail = NULL;

        /* Stop unmapping if "cur" no longer overlaps with [start, end) */
        if (!test_vma_overlap(cur, start, end))
            break;

        if (VMA_TYPE(cur->flags) != VMA_TYPE(flags))
            return -EACCES;

        /* If [start, end) contains the VMA, just drop the VMA. */
        if (start <= cur->start && cur->end <= end) {
            __remove_vma(cur, prev);
            __drop_vma(cur);
        } else {
            __shrink_vma(cur, start, end, &tail);

            if (cur->end <= start) {
                prev = cur;
                if (tail) {
                    __insert_vma(tail, cur); /* insert "tail" after "cur" */
                    cur = tail; /* "tail" is the new "cur" */
                    break;
                }
            } else if (cur->start >= end) {
                /* __shrink_vma() only creates a new VMA when the beginning of the
                 * original VMA is preserved. */
                assert(!tail);
                break;
            } else {
                /* __shrink_vma() should never allow this case. */
                BUG();
            }
        }

        cur = next;
        next = cur ? LISTP_NEXT_ENTRY(cur, &g_vma_list, list) : NULL;
    }

    if (prev)
        assert(cur == LISTP_NEXT_ENTRY(prev, &g_vma_list, list));
    else
        assert(cur == LISTP_FIRST_ENTRY(&g_vma_list, struct shim_vma, list));

    assert(!prev || prev->end <= start);
    assert(!cur || end <= cur->start);
    *pprev = prev;
    return 0;
}

int bkeep_munmap (void * addr, size_t length, int flags)
{
    if (!length)
        return -EINVAL;

    debug("bkeep_munmap: %p-%p\n", addr, addr + length);

    lock(&g_vma_list_lock);
    __restore_reserved_vmas();
    struct shim_vma * prev = NULL;
    __lookup_vma(addr, &prev);
    int ret = __bkeep_munmap(&prev, addr, addr + length, flags);
    assert_vma_list();
    /* DEP 5/20/19: If this is a debugging region we are removing, take it out
     * of the checkpoint.  Otherwise, it will be restored erroneously after a fork. */
    remove_r_debug(addr);
    unlock(&g_vma_list_lock);
    return ret;
}

/*
 * Update bookkeeping for mprotect(). "prev" must point to the immediately
 * precedent vma of the address to protect, or be NULL if no vma is lower than
 * the address. If the bookkeeping area overlaps with some existing vmas,
 * we must check whether the caller (from user, internal code, or checkpointing
 * procedure) is allowed to overwrite the existing vmas.
 *
 * Bookkeeping convention (must follow):
 * Update the bookkeeping BEFORE calling DkVirtualMemoryProtect().
 */
static int __bkeep_mprotect (struct shim_vma * prev,
                             void * start, void * end, int prot, int flags)
{
    assert(locked(&g_vma_list_lock));

    struct shim_vma * cur, * next;

    if (!prev) {
        cur = LISTP_FIRST_ENTRY(&g_vma_list, struct shim_vma, list);
        if (!cur)
            return 0;
    } else {
        cur = LISTP_NEXT_ENTRY(prev, &g_vma_list, list);
    }

    next = cur ? LISTP_NEXT_ENTRY(cur, &g_vma_list, list) : NULL;

    while (cur) {
        struct shim_vma * new, * tail = NULL;

        /* Stop protecting if "cur" no longer overlaps with [start, end) */
        if (!test_vma_overlap(cur, start, end))
            break;

        if (VMA_TYPE(cur->flags) != VMA_TYPE(flags))
            /* For now, just shout loudly. */
            return -EACCES;

        /* If protection doesn't change anything, move on to the next */
        if (cur->prot != prot) {
            /* If [start, end) contains the VMA, just update its protection. */
            if (start <= cur->start && cur->end <= end) {
                cur->prot = prot;
                if (cur->file && (prot & PROT_WRITE)) {
                    cur->flags |= VMA_TAINTED;
                }
            } else {
                /* Create a new VMA for the protected area */
                new = __get_new_vma();
                new->start = cur->start > start ? cur->start : start;
                new->end   = cur->end < end ? cur->end : end;
                new->prot  = prot;
                new->flags = cur->flags | ((cur->file && (prot & PROT_WRITE)) ? VMA_TAINTED : 0);
                new->file  = cur->file;
                if (new->file) {
                    get_handle(new->file);
                    new->offset = cur->offset + (new->start - cur->start);
                } else {
                    new->offset = 0;
                }
                memcpy(new->comment, cur->comment, VMA_COMMENT_LEN);

                /* Like unmapping, shrink (and potentially split) the VMA first. */
                __shrink_vma(cur, start, end, &tail);

                if (cur->end <= start) {
                    prev = cur;
                    if (tail) {
                        __insert_vma(tail, cur); /* insert "tail" after "cur" */
                        cur = tail; /* "tail" is the new "cur" */
                        /* "next" is the same */
                    }
                } else if (cur->start >= end) {
                    /* __shrink_vma() only creates a new VMA when the beginning of the
                     * original VMA is preserved. */
                    assert(!tail);
                } else {
                    /* __shrink_vma() should never allow this case. */
                    BUG();
                }

                /* Now insert the new protected vma between prev and cur */
                __insert_vma(new, prev);
                assert(!prev || prev->end <= new->end);
                assert(new->start < new->end);
            }
        }

        prev = cur;
        cur = next;
        next = cur ? LISTP_NEXT_ENTRY(cur, &g_vma_list, list) : NULL;
    }

    return 0;
}

int bkeep_mprotect (void * addr, size_t length, int prot, int flags)
{
    if (!addr || !length)
        return -EINVAL;

    debug("bkeep_mprotect: %p-%p\n", addr, addr + length);

    lock(&g_vma_list_lock);
    __restore_reserved_vmas();
    struct shim_vma * prev = NULL;
    __lookup_vma(addr, &prev);
    int ret = __bkeep_mprotect(prev, addr, addr + length, prot, flags);
    assert_vma_list();
    unlock(&g_vma_list_lock);
    return ret;
}

/*
 * Search for an unmapped area within [bottom, top) that is big enough
 * to allocate "length" bytes. The search approach is top-down.
 * If this function returns a non-NULL address, the corresponding VMA is
 * added to the VMA list.
 */
static void * __bkeep_unmapped (void * top_addr, void * bottom_addr,
                                size_t length, int prot, int flags,
                                struct shim_handle * file,
                                off_t offset, const char * comment)
{
    assert(locked(&g_vma_list_lock));
    assert(top_addr > bottom_addr);

    if (!length || length > (uintptr_t) top_addr - (uintptr_t) bottom_addr)
        return NULL;

    struct shim_vma * prev = NULL;
    struct shim_vma * cur = __lookup_vma(top_addr, &prev);

    while (true) {
        /* Set the range for searching */
        void * end = cur ? cur->start : top_addr;
        void * start =
            (prev && prev->end > bottom_addr) ? prev->end : bottom_addr;

        assert(start <= end);

        /* Check if there is enough space between prev and cur */
        if (length <= (uintptr_t) end - (uintptr_t) start) {
            /* create a new VMA at the top of the range */
            __bkeep_mmap(prev, end - length, end, prot, flags,
                         file, offset, comment);
            assert_vma_list();

            debug("bkeep_unmapped: %p-%p%s%s\n", end - length, end,
                  comment ? " => " : "", comment ? : "");

            return end - length;
        }

        if (!prev || prev->start <= bottom_addr)
            break;

        cur = prev;
        prev = LISTP_PREV_ENTRY(cur, &g_vma_list, list);
    }

    return NULL;
}

void * bkeep_unmapped (void * top_addr, void * bottom_addr, size_t length,
                       int prot, int flags, off_t offset, const char * comment)
{
    lock(&g_vma_list_lock);
    __restore_reserved_vmas();
    void * addr = __bkeep_unmapped(top_addr, bottom_addr, length, prot, flags,
                                   NULL, offset, comment);
    assert_vma_list();
    unlock(&g_vma_list_lock);
    return addr;
}

void * bkeep_unmapped_heap (size_t length, int prot, int flags,
                            struct shim_handle * file,
                            off_t offset, const char * comment)
{
    lock(&g_vma_list_lock);
    __restore_reserved_vmas();

    void * bottom_addr = PAL_CB(user_address.start);
    void * top_addr = current_heap_top;
    void * heap_max = PAL_CB(user_address.end);
    void * addr = NULL;

#ifdef MAP_32BIT
    /*
     * If MAP_32BIT is given in the flags, force the searching range to
     * be lower than 1ULL << 32.
     */
#define ADDR_32BIT ((void*)(1ULL << 32))

    if (flags & MAP_32BIT) {
        /* Try the lower 4GB memory space */
        if (heap_max > ADDR_32BIT)
            heap_max = ADDR_32BIT;

        if (top_addr > heap_max)
            top_addr = heap_max;
    }
#endif

    if (top_addr > bottom_addr) {
        /* Try first time */
        addr = __bkeep_unmapped(top_addr, bottom_addr,
                                length, prot, flags,
                                file, offset, comment);
        assert_vma_list();
    }
    if (addr) {
        /*
         * we only update the current heap top when we get the
         * address from [bottom_addr, current_heap_top).
         */
        if (top_addr == current_heap_top) {
            debug("heap top adjusted to %p\n", addr);
            current_heap_top = addr;
        }
    } else if (top_addr < heap_max) {
        /* Try to allocate above the current heap top */
        addr = __bkeep_unmapped(heap_max, bottom_addr,
                                length, prot, flags,
                                file, offset, comment);
        assert_vma_list();
    }

    unlock(&g_vma_list_lock);
#ifdef MAP_32BIT
    assert(!(flags & MAP_32BIT) || !addr || addr + length <= ADDR_32BIT);
#endif
    return addr;
}

static inline void
__dump_vma (struct shim_vma_val * val, const struct shim_vma * vma)
{
    val->addr   = vma->start;
    val->length = vma->end - vma->start;
    val->prot   = vma->prot;
    val->flags  = vma->flags;
    val->file   = vma->file;
    if (val->file)
        get_handle(val->file);
    val->offset = vma->offset;
    memcpy(val->comment, vma->comment, VMA_COMMENT_LEN);
}

int lookup_vma (void * addr, struct shim_vma_val * res)
{
    lock(&g_vma_list_lock);

    struct shim_vma * vma = __lookup_vma(addr, NULL);
    if (!vma) {
        unlock(&g_vma_list_lock);
        return -ENOENT;
    }

    if (res)
        __dump_vma(res, vma);

    unlock(&g_vma_list_lock);
    return 0;
}

int lookup_overlap_vma (void * addr, size_t length, struct shim_vma_val * res)
{
    struct shim_vma * tmp, * vma = NULL;

    lock(&g_vma_list_lock);

    LISTP_FOR_EACH_ENTRY(tmp, &g_vma_list, list)
        if (test_vma_overlap (tmp, addr, addr + length)) {
            vma = tmp;
            break;
        }


    if (!vma) {
        unlock(&g_vma_list_lock);
        return -ENOENT;
    }

    if (res)
        __dump_vma(res, vma);

    unlock(&g_vma_list_lock);
    return 0;
}

bool is_in_adjacent_vmas (void * addr, size_t length)
{
    struct shim_vma* vma;
    struct shim_vma* prev = NULL;
    lock(&g_vma_list_lock);

    /* we rely on the fact that VMAs are sorted (for adjacent VMAs) */
    assert_vma_list();

    LISTP_FOR_EACH_ENTRY(vma, &g_vma_list, list) {
        if (addr >= vma->start && addr < vma->end) {
            assert(prev == NULL);
            prev = vma;
        }
        if (prev) {
            if (prev != vma && prev->end != vma->start) {
                /* prev and current VMAs are not adjacent */
                break;
            }
            if ((addr + length) > vma->start && (addr + length) <= vma->end) {
                unlock(&g_vma_list_lock);
                return true;
            }
            prev = vma;
        }
    }

    unlock(&g_vma_list_lock);
    return false;
}

int dump_all_vmas (struct shim_vma_val * vmas, size_t max_count)
{
    struct shim_vma_val * val = vmas;
    struct shim_vma * vma;
    size_t cnt = 0;
    lock(&g_vma_list_lock);

    LISTP_FOR_EACH_ENTRY(vma, &g_vma_list, list) {
        if (VMA_TYPE(vma->flags))
            continue;
        if (vma->flags & VMA_UNMAPPED)
            continue;

        if (cnt == max_count) {
            cnt = -EOVERFLOW;
            for (size_t i = 0 ; i < max_count ; i++)
                if (vmas[i].file)
                    put_handle(vmas[i].file);
            break;
        }

        __dump_vma(val, vma);
        cnt++;
        val++;
    }

    unlock(&g_vma_list_lock);
    return cnt;
}

BEGIN_CP_FUNC(vma)
{
    __UNUSED(size);
    assert(size == sizeof(struct shim_vma_val));

    struct shim_vma_val * vma = (struct shim_vma_val *) obj;
    struct shim_vma_val * new_vma = NULL;
    PAL_FLG pal_prot = PAL_PROT(vma->prot, 0);

    ptr_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(*vma));
        ADD_TO_CP_MAP(obj, off);

        new_vma = (struct shim_vma_val *) (base + off);
        memcpy(new_vma, vma, sizeof(*vma));

        if (vma->file)
            DO_CP(handle, vma->file, &new_vma->file);

        void * need_mapped = vma->addr;

        if (NEED_MIGRATE_MEMORY(vma)) {
            void* send_addr  = vma->addr;
            size_t send_size = vma->length;
            if (vma->file) {
                /*
                 * Chia-Che 8/13/2017:
                 * A fix for cloning a private VMA which maps a file to a process.
                 *
                 * (1) Application can access any page backed by the file, wholly
                 *     or partially.
                 *
                 * (2) Access beyond the last file-backed page will cause SIGBUS.
                 *     For reducing fork latency, the following code truncates the
                 *     memory size for migrating a process. The memory size is
                 *     truncated to the file size, round up to pages.
                 *
                 * (3) Data in the last file-backed page is valid before or after
                 *     forking. Has to be included in process migration.
                 */
                off_t file_len = get_file_size(vma->file);
                if (file_len >= 0 &&
                    (off_t)(vma->offset + vma->length) > file_len) {
                    send_size = file_len > vma->offset ?
                                file_len - vma->offset : 0;
                    send_size = ALLOC_ALIGN_UP(send_size);
                }
            }
            if (send_size > 0) {
                if (!(pal_prot & PAL_PROT_READ)) {
                    /* Make the area readable */
                    DkVirtualMemoryProtect(send_addr, send_size,
                                           pal_prot|PAL_PROT_READ);
                }

                struct shim_mem_entry * mem;
                DO_CP_SIZE(memory, send_addr, send_size, &mem);
                mem->prot = pal_prot;

                need_mapped = vma->addr + vma->length;
            }
        }
        ADD_CP_FUNC_ENTRY(off);
        ADD_CP_ENTRY(ADDR, need_mapped);
    } else {
        new_vma = (struct shim_vma_val *) (base + off);
    }

    if (objp)
        *objp = (void *) new_vma;
}
END_CP_FUNC(vma)

DEFINE_PROFILE_CATEGORY(inside_rs_vma, resume_func);
DEFINE_PROFILE_INTERVAL(vma_add_bookkeep,   inside_rs_vma);
DEFINE_PROFILE_INTERVAL(vma_map_file,       inside_rs_vma);
DEFINE_PROFILE_INTERVAL(vma_map_anonymous,  inside_rs_vma);

BEGIN_RS_FUNC(vma)
{
    struct shim_vma_val * vma = (void *) (base + GET_CP_FUNC_ENTRY());
    void * need_mapped = (void *) GET_CP_ENTRY(ADDR);
    BEGIN_PROFILE_INTERVAL();

    CP_REBASE(vma->file);

    int ret = bkeep_mmap(vma->addr, vma->length, vma->prot, vma->flags,
                         vma->file, vma->offset, vma->comment);
    if (ret < 0)
        return ret;

    SAVE_PROFILE_INTERVAL(vma_add_bookkeep);

    DEBUG_RS("vma: %p-%p flags %x prot 0x%08x\n",
             vma->addr, vma->addr + vma->length, vma->flags, vma->prot);

    if (!(vma->flags & VMA_UNMAPPED)) {
        if (vma->file) {
            struct shim_mount * fs = vma->file->fs;
            get_handle(vma->file);

            if (need_mapped < vma->addr + vma->length) {
                /* first try, use hstat to force it resumes pal handle */
                assert(vma->file->fs && vma->file->fs->fs_ops &&
                       vma->file->fs->fs_ops->mmap);

                void * addr = need_mapped;
                int ret = fs->fs_ops->mmap(vma->file, &addr,
                                           vma->addr + vma->length -
                                           need_mapped,
                                           vma->prot,
                                           vma->flags,
                                           vma->offset +
                                           (need_mapped - vma->addr));

                if (ret < 0)
                    return ret;
                if (!addr)
                    return -ENOMEM;
                if (addr != need_mapped)
                    return -EACCES;

                need_mapped += vma->length;
                SAVE_PROFILE_INTERVAL(vma_map_file);
            }
        }

        if (need_mapped < vma->addr + vma->length) {
            int pal_alloc_type = 0;
            int pal_prot = vma->prot;
            if (DkVirtualMemoryAlloc(need_mapped,
                                     vma->addr + vma->length - need_mapped,
                                     pal_alloc_type, pal_prot)) {
                need_mapped += vma->length;
                SAVE_PROFILE_INTERVAL(vma_map_anonymous);
            }
        }

        if (need_mapped < vma->addr + vma->length)
            SYS_PRINTF("vma %p-%p cannot be allocated!\n", need_mapped,
                       vma->addr + vma->length);
    }

    if (vma->file)
        get_handle(vma->file);

    if (vma->file)
        DEBUG_RS("%p-%p,size=%ld,prot=%08x,flags=%08x,off=%ld,path=%s,uri=%s",
                 vma->addr, vma->addr + vma->length, vma->length,
                 vma->prot, vma->flags, vma->offset,
                 qstrgetstr(&vma->file->path), qstrgetstr(&vma->file->uri));
    else
        DEBUG_RS("%p-%p,size=%ld,prot=%08x,flags=%08x,off=%ld",
                 vma->addr, vma->addr + vma->length, vma->length,
                 vma->prot, vma->flags, vma->offset);
}
END_RS_FUNC(vma)

BEGIN_CP_FUNC(all_vmas)
{
    size_t count = DEFAULT_VMA_COUNT;
    struct shim_vma_val * vmas = malloc(sizeof(*vmas) * count);
    int ret;
    __UNUSED(obj);
    __UNUSED(size);
    __UNUSED(objp);

    if (!vmas)
        return -ENOMEM;

    while (true) {
        ret = dump_all_vmas(vmas, count);
        if (ret != -EOVERFLOW)
            break;

        struct shim_vma_val * new_vmas
            = malloc(sizeof(*new_vmas) * count * 2);
        if (!new_vmas) {
            free(vmas);
            return -ENOMEM;
        }
        free(vmas);
        vmas = new_vmas;
        count *= 2;
    }

    if (ret < 0)
        return ret;

    count = ret;
    for (struct shim_vma_val * vma = &vmas[count - 1] ; vma >= vmas ; vma--)
        DO_CP(vma, vma, NULL);

    free_vma_val_array(vmas, count);
}
END_CP_FUNC_NO_RS(all_vmas)

void debug_print_vma (struct shim_vma *vma)
{
    const char * type = "", * name = "";

    if (vma->file) {
        if (!qstrempty(&vma->file->path)) {
            type = " path=";
            name = qstrgetstr(&vma->file->path);
        } else if (!qstrempty(&vma->file->uri)) {
            type = " uri=";
            name = qstrgetstr(&vma->file->uri);
        }
    }

    SYS_PRINTF("[%p-%p] prot=%08x flags=%08x%s%s offset=%ld%s%s%s%s\n",
               vma->start, vma->end,
               vma->prot,
               vma->flags & ~(VMA_INTERNAL|VMA_UNMAPPED|VMA_TAINTED|VMA_CP),
               type, name,
               vma->offset,
               vma->flags & VMA_INTERNAL ? " (internal)" : "",
               vma->flags & VMA_UNMAPPED ? " (unmapped)" : "",
               vma->comment[0] ? " comment=" : "",
               vma->comment[0] ? vma->comment : "");
}

void debug_print_vma_list (void)
{
    SYS_PRINTF("vma bookkeeping:\n");

    struct shim_vma * vma;
    LISTP_FOR_EACH_ENTRY(vma, &g_vma_list, list) {
        debug_print_vma(vma);
    }
}
