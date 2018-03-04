/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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
 * structure can only be accessed in this source file, with vma_list_lock
 * held. No reference counting needed in this data structure.
 */
DEFINE_LIST(shim_vma);
struct shim_vma {
    LIST_TYPE(shim_vma)     list;
    void *                  start;
    void *                  end;
    int                     prot;
    int                     flags;
    uint64_t                offset;
    struct shim_handle *    file;
    char                    comment[VMA_COMMENT_LEN];
};

#define VMA_MGR_ALLOC   DEFAULT_VMA_COUNT
#define PAGE_SIZE       allocsize
#define RESERVED_VMAS   4

static struct shim_vma * reserved_vmas[RESERVED_VMAS];
static struct shim_vma early_vmas[RESERVED_VMAS];

static void * __bkeep_unmapped (void * top_addr, void * bottom_addr,
                                uint64_t length, int prot, int flags,
                                struct shim_handle * file,
                                uint64_t offset, const char * comment);

/*
 * Because the default system_malloc() must create VMA(s), we need
 * a new system_malloc() to avoid cicular dependency. This __malloc()
 * stores the VMA address and size in the current thread to delay the
 * bookkeeping until the allocator finishes extension.
 */
static inline void * __malloc (size_t size)
{
    void * addr;
    size = ALIGN_UP(size);

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

#undef system_malloc
#define system_malloc __malloc

#define OBJ_TYPE struct shim_vma
#include <memmgr.h>

/*
 * "vma_mgr" has no specific lock. "vma_list_lock" must be held when
 * allocating or freeing any VMAs.
 */
static MEM_MGR vma_mgr = NULL;

/*
 * "vma_list" contains a sorted list of non-overlapping VMAs.
 * "vma_list_lock" must be held when accessing either the vma_list or any
 * field of a VMA.
 */
DEFINE_LISTP(shim_vma);
static LISTP_TYPE(shim_vma) vma_list = LISTP_INIT;
static LOCKTYPE vma_list_lock;

/*
 * Return true if [s, e) is exactly the area represented by vma.
 */
static inline bool test_vma_equal (struct shim_vma * vma,
                                   void * s, void * e)
{
    return vma->start == s && vma->end == e;
}

/*
 * Return true if [s, e) is part of the area represented by vma.
 */
static inline bool test_vma_contain (struct shim_vma * vma,
                                     void * s, void * e)
{
    return vma->start <= s && vma->end >= e;
}

/*
 * Return true if [s, e) contains the starting address of vma.
 */
static inline bool test_vma_startin (struct shim_vma * vma,
                                     void * s, void * e)
{
    return vma->start >= s && vma->start < e;
}

/*
 * Return true if [s, e) contains the ending address of vma.
 */
static inline bool test_vma_endin (struct shim_vma * vma,
                                   void * s, void * e)
{
    return vma->end > s && vma->end <= e;
}

/*
 * Return true if [s, e) overlaps with the area represented by vma.
 */
static inline bool test_vma_overlap (struct shim_vma * vma,
                                     void * s, void * e)
{
    return test_vma_contain(vma, s, s + 1) ||
           test_vma_contain(vma, e - 1, e) ||
           test_vma_startin(vma, s, e);
}

static inline struct shim_vma *
__lookup_vma (void * addr, struct shim_vma ** pprev)
{
    struct shim_vma * vma, * prev = NULL;

    listp_for_each_entry(vma, &vma_list, list) {
        if (addr < vma->start)
            goto none;
        if (test_vma_contain(vma, addr, addr + 1))
            goto out;

        prev = vma;
    }

none:
    vma = NULL;
out:
    if (pprev) *pprev = prev;
    return vma;
}

static inline void
__insert_vma (struct shim_vma * vma, struct shim_vma * prev)
{
    assert(!prev || prev->end <= vma->start);

    if (prev)
        listp_add_after(vma, prev, &vma_list, list);
    else
        listp_add(vma, &vma_list, list);
}

static inline void
__remove_vma (struct shim_vma * vma, struct shim_vma * prev)
{
    assert(!prev || prev->list.next == vma);

    listp_del(vma, &vma_list, list);
}

/*
 * Storing a cursor pointing to the current heap top. With ASLR, the cursor
 * is randomized at initialization. The cursor is monotonically decremented
 * when allocating user VMAs. Updating this cursor needs holding vma_list_lock.
 */
static void * current_heap_top;

int init_vma (void)
{
    for (int i = 0 ; i < RESERVED_VMAS ; i++)
        reserved_vmas[i] = &early_vmas[i];

    if (!(vma_mgr = create_mem_mgr(init_align_up(VMA_MGR_ALLOC)))) {
        debug("failed allocating VMAs\n");
        return -ENOMEM;
    }

    for (int i = 0 ; i < RESERVED_VMAS ; i++) {
        struct shim_vma * new = get_mem_obj_from_mgr(vma_mgr);
        assert(new);

        if (!reserved_vmas[i]) {
            struct shim_vma * e = &early_vmas[i];
            struct shim_vma * prev = listp_prev_entry(e, &vma_list, list);
            debug("Converting early VMA [%p] %p-%p\n", e, e->start, e->end);
            memcpy(new, e, sizeof(struct shim_vma));
            INIT_LIST_HEAD(new, list);
            __remove_vma(e, prev);
            __insert_vma(new, prev);
        }

        reserved_vmas[i] = new;
    }

    create_lock(vma_list_lock);

    uint64_t bottom = (uint64_t) PAL_CB(user_address.start);
    uint64_t top    = (uint64_t) PAL_CB(user_address.end);

#if ENABLE_ASLR == 1
    uint64_t rand;
    getrand(&rand, sizeof(rand));
    current_heap_top = (void *)
        bottom + rand % ((top - bottom) / allocsize) * allocsize;
#else
    current_heap_top = (void *) top;
#endif

    debug("User space range: 0x%llx-0x%llx\n", bottom, top);
    debug("heap top adjusted to %p\n", current_heap_top);

    return 0;
}

static int __bkeep_mmap (struct shim_vma * prev,
                         void * start, void * end, int prot, int flags,
                         struct shim_handle * file, uint64_t offset,
                         const char * comment);

static int __bkeep_munmap (struct shim_vma * prev,
                           void * start, void * end, int flags);

static int __bkeep_mprotect (struct shim_vma * prev,
                             void * start, void * end, int prot, int flags);

static inline struct shim_vma * __get_new_vma (void)
{
    struct shim_vma * tmp;

    if (vma_mgr) {
        tmp = get_mem_obj_from_mgr(vma_mgr);
        if (tmp)
            goto out;
    }

    for (int i = 0 ; i < RESERVED_VMAS ; i++)
        if (reserved_vmas[i]) {
            tmp = reserved_vmas[i];
            reserved_vmas[i] = NULL;
            goto out;
        }

    /* Should never reach here; if this happens, increase RESERVED_VMAS */
    bug();

out:
    memset(tmp, 0, sizeof(struct shim_vma));
    INIT_LIST_HEAD(tmp, list);
    return tmp;
}

static inline void __restore_reserved_vmas (void)
{
    bool nothing_reserved = true;
    do {
        for (int i = 0 ; i < RESERVED_VMAS ; i++)
            if (!reserved_vmas[i]) {
                struct shim_vma * new =
                    get_mem_obj_from_mgr_enlarge(vma_mgr,
                                                 size_align_up(VMA_MGR_ALLOC));

                /* this allocation must succeed */
                assert(new);
                reserved_vmas[i] = new;
                nothing_reserved = false;
            }
    } while (!nothing_reserved);
}

static inline void __drop_vma (struct shim_vma * vma)
{
    if (vma->file)
        put_handle(vma->file);

    if (MEMORY_MIGRATED(vma))
        memset(vma, 0, sizeof(*vma));
    else
        free_mem_obj_to_mgr(vma_mgr, vma);
}

static inline void
__assert_vma_flags (const struct shim_vma * vma, int flags)
{
    if (!(vma->flags & VMA_UNMAPPED)
          && (vma->flags & VMA_INTERNAL) != (flags & VMA_INTERNAL)) {
        debug("Check vma flag failure: vma flags %x, checked flags %x\n",
              vma->flags, flags);
        bug();
    }
}

static inline void
__set_vma_comment (struct shim_vma * vma, const char * comment)
{
    if (!comment) {
        vma->comment[0] = 0;
        return;
    }

    uint64_t len = strlen(comment);

    if (len > VMA_COMMENT_LEN - 1)
        len = VMA_COMMENT_LEN - 1;

    memcpy(vma->comment, comment, len);
    vma->comment[len] = 0;
}

static int __bkeep_mmap (struct shim_vma * prev,
                         void * start, void * end, int prot, int flags,
                         struct shim_handle * file, uint64_t offset,
                         const char * comment)
{
    int ret = 0;
    struct shim_vma * new = __get_new_vma();

    /* First, remove any overlapping VMAs */
    ret = __bkeep_munmap(prev, start, end, flags);
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

int bkeep_mmap (void * addr, uint64_t length, int prot, int flags,
                struct shim_handle * file, uint64_t offset,
                const char * comment)
{
    if (!addr || !length)
        return -EINVAL;

    debug("bkeep_mmap: %p-%p (%s)\n", addr, addr + length,
          comment ? : "unknown");

    lock(vma_list_lock);
    struct shim_vma * prev = NULL;
    __lookup_vma(addr, &prev);
    int ret = __bkeep_mmap(prev, addr, addr + length, prot, flags, file, offset,
                           comment);
    __restore_reserved_vmas();
    unlock(vma_list_lock);
    return ret;
}

static inline int __shrink_vma (struct shim_vma * cur, void * start, void * end,
                                struct shim_vma ** tailptr)
{
    /*
     * Dealing with the head: if the starting address of "cur" is in
     * [start, end), move the starting address.
     */
    if (test_vma_startin(cur, start, end)) {
        if (end < cur->end) {
            if (cur->file) /* must adjust offset */
                cur->offset += end - cur->start;
            cur->start = end;
        } else {
            if (cur->file) /* must adjust offset */
                cur->offset += cur->end - cur->start;
            cur->start = cur->end;
        }
    }

    /*
     * Dealing with the tail: if the ending address of "cur" is in
     * [start, end), move the ending address.
     */
    if (test_vma_endin(cur, start, end)) {
        if (start > cur->start) {
            cur->end = start;
        } else {
            cur->end = cur->start;
        }
        /* offset is not affected */
    }

    /*
     * If [start, end) is inside the range of "cur", divide up
     * the VMA. A new VMA is created to represent the remaining tail.
     */
    if (test_vma_contain(cur, start, end)) {
        void * old_end = cur->end;
        cur->end = start;

        /* Remaining space after [start, end), creating a new VMA */
        if (old_end > end) {
            struct shim_vma * tail = __get_new_vma();

            tail->start = end;
            tail->end   = old_end;
            tail->prot  = cur->prot;
            tail->flags = cur->flags;
            tail->file  = cur->file;
            if (tail->file) {
                get_handle(tail->file);
                tail->offset = cur->offset + (tail->start - cur->start);
            } else {
                tail->offset = 0;
            }
            memcpy(tail->comment, cur->comment, VMA_COMMENT_LEN);
            *tailptr = tail;
        }
    }

    return 0;
}

static int __bkeep_munmap (struct shim_vma * prev,
                           void * start, void * end, int flags)
{
    struct shim_vma * cur, * next;

    if (!prev) {
        cur = listp_first_entry(&vma_list, struct shim_vma, list);
        if (!cur)
            return 0;
    } else {
        cur = listp_next_entry(prev, &vma_list, list);
    }

    next = cur ? listp_next_entry(cur, &vma_list, list) : NULL;

    while (cur) {
        struct shim_vma * tail = NULL;

        /* Stop unmapping if "cur" no longer overlaps with [start, end) */
        if (!test_vma_overlap(cur, start, end))
            break;

        int ret = __shrink_vma(cur, start, end, &tail);
        if (ret < 0)
            return ret;

        if (cur->start < cur->end) {
            /* Keep the VMA. */
            if (tail) {
                __insert_vma(tail, cur); /* insert "tail" after "cur" */
                prev = cur;
                cur = tail; /* "tail" is the new "cur" */
                /* "next" is the same */
            }
        } else {
            __remove_vma(cur, prev);
            __drop_vma(cur);

            if (tail) {
                __insert_vma(tail, prev); /* insert "tail" after "prev" */
                cur = tail; /* "tail" is the new "cur" */
                /* next is the same */
            } else {
                /* nothing to insert, back off to "prev" */
                cur = prev;
            }
        }

        prev = cur;
        cur = next;
        next = cur ? listp_next_entry(cur, &vma_list, list) : NULL;
    }

    return 0;
}

int bkeep_munmap (void * addr, uint64_t length, int flags)
{
    if (!length)
        return -EINVAL;

    debug("bkeep_unmmap: %p-%p\n", addr, addr + length);

    lock(vma_list_lock);
    struct shim_vma * prev = NULL;
    __lookup_vma(addr, &prev);
    int ret = __bkeep_munmap(prev, addr, addr + length, flags);
    __restore_reserved_vmas();
    unlock(vma_list_lock);
    return ret;
}

static int __bkeep_mprotect (struct shim_vma * prev,
                             void * start, void * end, int prot, int flags)
{
    struct shim_vma * cur, * next;

    if (!prev) {
        cur = listp_first_entry(&vma_list, struct shim_vma, list);
        if (!cur)
            return 0;
    } else {
        cur = listp_next_entry(prev, &vma_list, list);
    }

    next = cur ? listp_next_entry(cur, &vma_list, list) : NULL;

    while (cur) {
        struct shim_vma * new, * tail = NULL;

        /* Stop protecting if "cur" no longer overlaps with [start, end) */
        if (!test_vma_overlap(cur, start, end))
            break;

        /* If protection doesn't change anything, move on to the next */
        if (cur->prot == prot)
            goto cont;

        /* Create a new VMA for the protected area */
        new = __get_new_vma();
        new->start = cur->start > start ? cur->start : start;
        new->end   = cur->end < end ? cur->end : end;
        new->prot  = prot;
        new->flags = cur->flags;
        new->file  = cur->file;
        if (new->file) {
            get_handle(new->file);
            new->offset = cur->offset + (new->start - cur->start);
        } else {
            new->offset = 0;
        }
        memcpy(new->comment, cur->comment, VMA_COMMENT_LEN);

        /* Like unmapping, shrink (and potentially split) the VMA first. */
        int ret = __shrink_vma(cur, start, end, &tail);
        if (ret < 0) {
            __drop_vma(new);
            return ret;
        }

        if (cur->start < cur->end) {
            /* Keep the VMA. */
            if (tail) {
                __insert_vma(tail, cur); /* insert "tail" after "cur" */
                prev = cur;
                cur = tail; /* "tail" is the new "cur" */
                /* "next" is the same */
            }
        } else {
            __remove_vma(cur, prev);
            __drop_vma(cur);

            if (tail) {
                __insert_vma(tail, prev); /* insert "tail" after "prev" */
                cur = tail; /* "tail" is the new "cur" */
                /* next is the same */
            } else {
                /* nothing to insert, back off to "prev" */
                cur = prev;
            }
        }

        /* Now insert the new protected vma */
        if (!cur || new->end <= cur->start) {
            __insert_vma(new, prev);
            prev = new;
            /* cur and next are the same */
        } else if (new->start >= cur->end) {
            __insert_vma(new, cur);
            prev = cur;
            cur = new;
            /* next is the same */
        } else {
            bug();
        }

cont:
        prev = cur;
        cur = next;
        next = cur ? listp_next_entry(cur, &vma_list, list) : NULL;
    }

    return 0;
}

int bkeep_mprotect (void * addr, uint64_t length, int prot, int flags)
{
    if (!addr || !length)
        return -EINVAL;

    debug("bkeep_mprotect: %p-%p\n", addr, addr + length);

    lock(vma_list_lock);
    struct shim_vma * prev = NULL;
    __lookup_vma(addr, &prev);
    int ret = __bkeep_mprotect(prev, addr, addr + length, prot, flags);
    __restore_reserved_vmas();
    unlock(vma_list_lock);
    return ret;
}

/*
 * Search for an unmapped area within [bottom, top) that is bigger enough
 * to allocate "length" bytes. The search approach is top-down.
 * If this function returns an non-NULL address, the corresponding VMA is
 * added to the VMA list.
 */
static void * __bkeep_unmapped (void * top_addr, void * bottom_addr,
                                uint64_t length, int prot, int flags,
                                struct shim_handle * file,
                                uint64_t offset, const char * comment)
{
    assert(top_addr > bottom_addr);

    if (!length || length > top_addr - bottom_addr)
        return NULL;

    struct shim_vma * prev = NULL;
    struct shim_vma * cur = __lookup_vma(top_addr, &prev);
    struct shim_vma * new = NULL;

    /* Check if there is enough space between prev and cur */
    while (true) {
        /* setting the range for searching */
        void * end = cur ? cur->start : top_addr;
        void * start =
            (prev && prev->end > bottom_addr) ? prev->end : bottom_addr;

        assert(start <= end);

        if (length <= start - end) {
            /* create a new VMA at the top of the range */
            new = __get_new_vma();
            new->start = end - length;
            new->end   = end;
            break;
        }

        if (!prev || prev->start <= bottom_addr)
            break;

        cur = prev;
        prev = listp_prev_entry(cur, &vma_list, list);
    }

    void * res_addr = NULL;
    if (new) {
        new->prot   = prot;
        new->flags  = flags|((file && (prot & PROT_WRITE)) ? VMA_TAINTED : 0);
        new->file   = file;
        if (new->file)
            get_handle(new->file);
        new->offset = offset;
        __set_vma_comment(new, comment);
        __insert_vma(new, prev);
        res_addr    = new->start;
    }

    return res_addr;
}

void * bkeep_unmapped (void * top_addr, void * bottom_addr, uint64_t length,
                       int prot, int flags, struct shim_handle * file,
                       uint64_t offset, const char * comment)
{
    lock(vma_list_lock);
    void * addr = __bkeep_unmapped(top_addr, bottom_addr, length, prot, flags,
                                   file, offset, comment);
    __restore_reserved_vmas();
    unlock(vma_list_lock);
    return addr;
}

void * bkeep_unmapped_heap (uint64_t length, int prot, int flags,
                            struct shim_handle * file,
                            uint64_t offset, const char * comment)
{
    lock(vma_list_lock);

    void * bottom_addr = PAL_CB(user_address.start);
    void * top_addr = current_heap_top;
    void * heap_max = PAL_CB(user_address.end);
    void * addr;
    bool update_heap_top = true;

#ifdef MAP_32BIT
    /*
     * If MAP_32BIT is given in the flags, force the searching range to
     * be lower than 1ULL << 32.
     */
#define ADDR_32BIT ((void *) (1ULL << 32))

    if (flags & MAP_32BIT) {
        if (heap_max > ADDR_32BIT)
            heap_max = ADDR_32BIT;

        if (bottom_addr >= heap_max) {
            unlock(vma_list_lock);
            return NULL;
        }

        if (top_addr > heap_max) {
            top_addr = heap_max;
            update_heap_top = false;
        }
    }
#endif

    addr = __bkeep_unmapped(top_addr, bottom_addr,
                            length, prot, flags,
                            file, offset, comment);

    if (addr) {
        if (update_heap_top)
            current_heap_top = addr;
        goto out;
    }

    if (top_addr == heap_max)
        goto out;

    /* Try to allocate above the current heap top */
    top_addr = heap_max;
    addr = __bkeep_unmapped(top_addr, bottom_addr,
                            length, prot, flags,
                            file, offset, comment);

out:
    __restore_reserved_vmas();
    unlock(vma_list_lock);
    return addr;
}

int lookup_vma (void * addr, struct shim_vma_val * res)
{
    lock(vma_list_lock);

    struct shim_vma * vma = __lookup_vma(addr, NULL);
    if (!vma) {
        unlock(vma_list_lock);
        return -ENOENT;
    }

    if (res) {
        res->addr   = vma->start;
        res->length = vma->end - vma->start;
        res->prot   = vma->prot;
        res->flags  = vma->flags;
        res->file   = vma->file;
        if (res->file)
            get_handle(res->file);
        res->offset = vma->offset;
        memcpy(res->comment, vma->comment, VMA_COMMENT_LEN);
    }

    unlock(vma_list_lock);
    return 0;
}

int lookup_overlap_vma (void * addr, uint64_t length,
                        struct shim_vma_val * res)
{
    struct shim_vma * tmp, * vma = NULL;

    lock(vma_list_lock);

    listp_for_each_entry(tmp, &vma_list, list)
        if (test_vma_overlap (tmp, addr, addr + length)) {
            vma = tmp;
            break;
        }


    if (!vma) {
        unlock(vma_list_lock);
        return -ENOENT;
    }

    if (res) {
        res->addr   = vma->start;
        res->length = vma->end - vma->start;
        res->prot   = vma->prot;
        res->flags  = vma->flags;
        res->file   = vma->file;
        if (res->file)
            get_handle(res->file);
        res->offset = vma->offset;
        memcpy(res->comment, vma->comment, VMA_COMMENT_LEN);
    }

    unlock(vma_list_lock);
    return 0;
}

int dump_all_vmas (struct shim_vma_val * vmas, size_t size)
{
    struct shim_vma_val * val = vmas;
    struct shim_vma * vma;
    int cnt = 0;
    lock(vma_list_lock);

    listp_for_each_entry(vma, &vma_list, list) {
        if (vma->flags & VMA_INTERNAL)
            continue;

        if (cnt == size) {
            cnt = -EOVERFLOW;
            for (int i = 0 ; i < size ; i++)
                if (vmas[i].file)
                    put_handle(vmas[i].file);
            break;
        }

        val->addr   = vma->start;
        val->length = vma->end - vma->start;
        val->prot   = vma->prot;
        val->flags  = vma->flags;
        val->file   = vma->file;
        if (val->file)
            get_handle(val->file);
        val->offset = vma->offset;
        memcpy(val->comment, vma->comment, VMA_COMMENT_LEN);

        cnt++;
        val++;
    }

    unlock(vma_list_lock);
    return cnt;
}

BEGIN_CP_FUNC(vma)
{
    assert(size == sizeof(struct shim_vma_val));

    struct shim_vma_val * vma = (struct shim_vma_val *) obj;
    struct shim_vma_val * new_vma = NULL;
    PAL_FLG pal_prot = PAL_PROT(vma->prot, 0);

    ptr_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_vma_val));
        ADD_TO_CP_MAP(obj, off);

        new_vma = (struct shim_vma_val *) (base + off);
        memcpy(new_vma, vma, sizeof(struct shim_vma_val));

        if (vma->file)
            DO_CP(handle, vma->file, &new_vma->file);

        void * need_mapped = vma->addr;

#if MIGRATE_MORE_GIPC == 1
        if (store->use_gipc ?
            !NEED_MIGRATE_MEMORY_IF_GIPC(vma) :
            !NEED_MIGRATE_MEMORY(vma))
#else
        if (!NEED_MIGRATE_MEMORY(vma))
#endif
            goto no_mem;

        void *   send_addr = vma->addr;
        uint64_t send_size = vma->length;
        bool protected = false;

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
            uint64_t file_len = get_file_size(vma->file);
            if (file_len >= 0 &&
                vma->offset + vma->length > file_len) {
                send_size = file_len > vma->offset ?
                            file_len - vma->offset : 0;
                send_size = ALIGN_UP(send_size);
            }
        }

        if (!send_size)
            goto no_mem;

        if (store->use_gipc) {
#if HASH_GIPC == 1
            if (!(pal_prot & PAL_PROT_READ)) {
                protected = true;
                DkVirtualMemoryProtect(send_addr, send_size,
                                       pal_prot|PAL_PROT_READ);
            }
#endif /* HASH_GIPC == 1 */
            struct shim_gipc_entry * gipc;
            DO_CP_SIZE(gipc, send_addr, send_size, &gipc);
            gipc->mem.prot = pal_prot;
        } else {
            if (!(pal_prot & PROT_READ)) {
                protected = true;
                DkVirtualMemoryProtect(send_addr, send_size,
                                       pal_prot|PAL_PROT_READ);
            }

            struct shim_mem_entry * mem;
            DO_CP_SIZE(memory, send_addr, send_size, &mem);
            mem->prot = pal_prot;
        }

        need_mapped = vma->addr + vma->length;

        if (protected)
            DkVirtualMemoryProtect(send_addr, send_size, pal_prot);

no_mem:
        ADD_CP_FUNC_ENTRY(off);
        ADD_CP_ENTRY(ADDR, need_mapped);
    } else {
        new_vma = (struct shim_vma_val *) (base + off);
    }

    if (objp)
        *objp = (void *) new_vma;
}
END_CP_FUNC(vma)

DEFINE_PROFILE_CATAGORY(inside_rs_vma, resume_func);
DEFINE_PROFILE_INTERVAL(vma_add_bookkeep,   inside_rs_vma);
DEFINE_PROFILE_INTERVAL(vma_map_file,       inside_rs_vma);
DEFINE_PROFILE_INTERVAL(vma_map_anonymous,  inside_rs_vma);

BEGIN_RS_FUNC(vma)
{
    struct shim_vma_val * vma = (void *) (base + GET_CP_FUNC_ENTRY());
    void * need_mapped = (void *) GET_CP_ENTRY(ADDR);
    BEGIN_PROFILE_INTERVAL();

    CP_REBASE(vma->file);
    bkeep_mmap(vma->addr, vma->length, vma->prot, vma->flags,
               vma->file, vma->offset, vma->comment);

    SAVE_PROFILE_INTERVAL(vma_add_bookkeep);

    DEBUG_RS("vma: %p-%p flags %x prot %p\n", vma->addr, vma->addr + vma->length,
             vma->flags, vma->prot);

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
            sys_printf("vma %p-%p cannot be allocated!\n", need_mapped,
                       vma->addr + vma->length);
    }

    if (vma->file)
        get_handle(vma->file);

    if (vma->file)
        DEBUG_RS("%p-%p,size=%d,prot=%08x,flags=%08x,off=%d,path=%s,uri=%s",
                 vma->addr, vma->addr + vma->length, vma->length,
                 vma->prot, vma->flags, vma->offset,
                 qstrgetstr(&vma->file->path), qstrgetstr(&vma->file->uri));
    else
        DEBUG_RS("%p-%p,size=%d,prot=%08x,flags=%08x,off=%d",
                 vma->addr, vma->addr + vma->length, vma->length,
                 vma->prot, vma->flags, vma->offset);
}
END_RS_FUNC(vma)

BEGIN_CP_FUNC(all_vmas)
{
    size_t count = DEFAULT_VMA_COUNT;
    struct shim_vma_val * vmas = malloc(sizeof(struct shim_vma_val) * count);
    int ret;

    if (!vmas)
        return -ENOMEM;

retry_dump_vmas:
    ret = dump_all_vmas(vmas, count);

    if (ret == -EOVERFLOW) {
        struct shim_vma_val * new_vmas
                = malloc(sizeof(struct shim_vma_val) * count * 2);
        if (!new_vmas) {
            free(vmas);
            return -ENOMEM;
        }
        free(vmas);
        vmas = new_vmas;
        count *= 2;
        goto retry_dump_vmas;
    }

    if (ret < 0)
        return ret;

    count = ret;
    for (struct shim_vma_val * vma = vmas ; vma < vmas + count ; vma++) {
        DO_CP(vma, vma, NULL);
        if (vma->file)
            put_handle(vma->file);
    }

    free(vmas);
}
END_CP_FUNC_NO_RS(all_vmas)
