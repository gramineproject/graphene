/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_vma.c
 *
 * This file contains codes to maintain bookkeeping of VMAs in library OS.
 */

#include <shim_internal.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_vma.h>
#include <shim_checkpoint.h>
#include <shim_fs.h>

#include <pal.h>
#include <linux_list.h>

#include <asm/mman.h>
#include <errno.h>

unsigned long mem_max_npages __attribute_migratable = DEFAULT_MEM_MAX_NPAGES;

static void * heap_top, * heap_bottom;

#define VMA_MGR_ALLOC   64
#define PAGE_SIZE       allocsize

static LOCKTYPE vma_mgr_lock;

#define system_lock()       lock(vma_mgr_lock)
#define system_unlock()     unlock(vma_mgr_lock)

static inline void * __vma_malloc (size_t size)
{
    struct shim_thread * thread = get_cur_thread();

    if (!thread)
        return system_malloc(size);

    size = ALIGN_UP(size);
    void * addr = (void *) DkVirtualMemoryAlloc(NULL, size, 0,
                                                PAL_PROT_WRITE|PAL_PROT_READ);

    debug("allocate %p-%p for vmas\n", addr, addr + size);
    thread->delayed_bkeep_mmap.addr = addr;
    thread->delayed_bkeep_mmap.length = size;
    return addr;
}

#undef system_malloc
#define system_malloc(size) __vma_malloc(size)

#define OBJ_TYPE struct shim_vma
#include <memmgr.h>

static MEM_MGR vma_mgr = NULL;

static LIST_HEAD(vma_list);
static LOCKTYPE vma_list_lock;

static inline int test_vma_equal (struct shim_vma * tmp,
                                  const void * addr, uint64_t length)
{
    return tmp->addr == addr &&
           tmp->addr + tmp->length == addr + length;
}

static inline int test_vma_contain (struct shim_vma * tmp,
                                    const void * addr, uint64_t length)
{
    return tmp->addr <= addr &&
           tmp->addr + tmp->length >= addr + length;
}

static inline int test_vma_startin (struct shim_vma * tmp,
                                    const void * addr, uint64_t length)
{
    return tmp->addr >= addr &&
           tmp->addr < addr + length;
}

static inline int test_vma_endin (struct shim_vma * tmp,
                                  const void * addr, uint64_t length)
{
    return tmp->addr + tmp->length > addr &&
           tmp->addr + tmp->length <= addr + length;
}

static inline int test_vma_overlap (struct shim_vma * tmp,
                                    const void * addr, uint64_t length)
{
    return test_vma_contain (tmp, addr + 1, 0) ||
           test_vma_contain (tmp, addr + length - 1, 0) ||
           test_vma_startin (tmp, addr, length - 1);
}

int bkeep_shim_heap (void);
static void __set_heap_top (void * bottom, void * top);

int init_vma (void)
{
    if (!(vma_mgr = create_mem_mgr(init_align_up(VMA_MGR_ALLOC)))) {
        debug("failed allocating VMAs\n");
        return -ENOMEM;
    }

    heap_bottom = (void *) PAL_CB(user_address.start);
    if (heap_bottom + DEFAULT_HEAP_MIN_SIZE > PAL_CB(executable_range.start) &&
        heap_bottom < PAL_CB(executable_range.end))
        heap_bottom = (void *) ALIGN_UP(PAL_CB(executable_range.end));

    __set_heap_top(heap_bottom, (void *) PAL_CB(user_address.end));

    bkeep_shim_heap();
    create_lock(vma_list_lock);

    return 0;
}

/* This might not give the same vma but we might need to
   split after we find something */
static inline void assert_vma (void)
{
    struct shim_vma * tmp;
    struct shim_vma * prev __attribute__((unused)) = NULL;

    list_for_each_entry(tmp, &vma_list, list) {
        /* Assert we are really sorted */
        assert(tmp->length > 0);
        assert(!prev || prev->addr + prev->length <= tmp->addr);
        prev = tmp;
    }
}

static struct shim_vma * __lookup_vma (const void * addr, uint64_t len);
static struct shim_vma * __lookup_supervma (const void * addr, uint64_t length,
                                            struct shim_vma ** prev);
static struct shim_vma * __lookup_overlap_vma (const void * addr, uint64_t length,
                                               struct shim_vma ** prev);

void get_vma (struct shim_vma * vma)
{
#ifdef DEBUG_REF
    int ref_count = REF_INC(vma->ref_count);

    debug("get vma %p(%p-%p) (ref_count = %d)\n", vma, vma->addr,
          vma->addr + vma->length, ref_count);
#else
    REF_INC(vma->ref_count);
#endif
}

void put_vma (struct shim_vma * vma)
{
    int ref_count = REF_DEC(vma->ref_count);

#ifdef DEBUG_REF
    debug("put vma %p(%p-%p) (ref_count = %d)\n", vma,
          vma->addr, vma->addr + vma->length, ref_count - 1);
#endif

    if (ref_count < 1) {
        if (vma->file)
            put_handle(vma->file);

        if (MEMORY_MIGRATED(vma))
            memset(vma, 0, sizeof(struct shim_vma));
        else
            free_mem_obj_to_mgr(vma_mgr, vma);
    }
}

static void __remove_vma (struct shim_vma * vma)
{
    list_del(&vma->list);
    put_vma(vma);
}

static int __bkeep_mmap (void * addr, uint64_t length, int prot, int flags,
                         struct shim_handle * file, uint64_t offset,
                         const char * comment);

static int __bkeep_mprotect (void * addr, uint64_t length, int prot,
                             const int * flags);

static void __check_delayed_bkeep (void)
{
    struct shim_thread * thread = get_cur_thread();

    if (!thread)
        return;
    if (!thread->delayed_bkeep_mmap.addr)
        return;

    void * bkeep_addr = thread->delayed_bkeep_mmap.addr;
    uint64_t bkeep_length = thread->delayed_bkeep_mmap.length;
    thread->delayed_bkeep_mmap.addr = NULL;
    thread->delayed_bkeep_mmap.length = 0;

    __bkeep_mmap(bkeep_addr, bkeep_length,
                 PROT_READ|PROT_WRITE,
                 MAP_PRIVATE|MAP_ANONYMOUS|VMA_INTERNAL,
                 NULL, 0, NULL);
}

static struct shim_vma * get_new_vma (void)
{
    struct shim_vma * tmp =
            get_mem_obj_from_mgr_enlarge(vma_mgr, size_align_up(VMA_MGR_ALLOC));
    if (!tmp)
        return NULL;

    memset(tmp, 0, sizeof(struct shim_vma));
    REF_SET(tmp->ref_count, 1);
    return tmp;
}

static bool check_vma_flags (const struct shim_vma * vma, const int * flags)
{
    if (!flags)
        return true;

    if (vma->flags & VMA_UNMAPPED)
        return true;

    if ((vma->flags & VMA_INTERNAL) != ((*flags) & VMA_INTERNAL)) {
        bug();
        return false;
    }

    return true;

}

static inline void __set_comment (struct shim_vma * vma, const char * comment)
{
    if (!comment) {
        vma->comment[0] = 0;
        return;
    }

    uint64_t len = strlen(comment);

    if (len > VMA_COMMENT_LEN - 1)
        len = VMA_COMMENT_LEN - 1;

    memcpy(vma->comment, comment, len + 1);
}

static int __bkeep_mmap (void * addr, uint64_t length,
                         int prot, int flags,
                         struct shim_handle * file, uint64_t offset,
                         const char * comment)
{
    struct shim_vma * prev = NULL;
    struct shim_vma * tmp = __lookup_supervma(addr, length, &prev);
    int ret = 0;

    debug("bkeep_mmap: %p-%p\n", addr, addr + length);

    if (file)
        get_handle(file);

    if (tmp) { /* the range is included in a vma */
        if (tmp->addr != addr || tmp->length != length) {
            /* we are inside some unmapped area, do a split case */
            ret = __bkeep_mprotect(addr, length, prot, &flags);
            if (ret < 0)
                goto err;
            /* now we get the exact vma handle */
            tmp = __lookup_vma(addr, length);
            assert(tmp);
            assert(check_vma_flags(tmp, &flags));
        }
    } else {
        struct shim_vma * cont = NULL, * n; /* cont: continue to scan vmas */
        struct list_head * pos = NULL; /* pos: position to add the vma */

        if (prev && prev->addr == addr &&
            prev->length <= length) { /* find a vma at the same addr */
            cont = tmp = prev;
        } else { /* need to add a new vma */
            if (!(tmp = get_new_vma()))
                return -ENOMEM;

            if (prev) { /* has a precendent vma */
                if (test_vma_endin(prev, addr, length)) {
                    if (!check_vma_flags(prev, &flags)) {
                        ret = -EACCES;
                        goto err;
                    }

                    /* the previous vma ends in the range; otherwise, there is
                     * no overlapping. Another case is handled by the supervma
                     * case. */
                    prev->length = addr - prev->addr;
                }

                assert(prev->addr + prev->length <= addr);
                cont = prev;
                pos = &prev->list;
            } else { /* has no precendent vma */
                cont = tmp;
                list_add(&tmp->list, &vma_list);
            }
        }

        if (cont)
            list_for_each_entry_safe_continue(cont, n, &vma_list, list) {
                if (!test_vma_startin(cont, addr, length))
                    break;

                if (!check_vma_flags(cont, &flags)) {
                    ret = -EACCES;
                    goto err;
                }

                if (test_vma_endin(cont, addr, length)) {
                    __remove_vma(cont);
                    continue;
                }

                long offset = addr + length - cont->addr;
                assert(offset > 0);
                if (cont->file)
                    cont->offset += offset;
                cont->addr += offset;
                cont->length -= offset;
                break;
            }

        if (tmp && pos)
            list_add(&tmp->list, pos);
    }

    tmp->addr = addr;
    tmp->length = length;
    tmp->prot = prot;
    tmp->flags = flags|((file && (prot & PROT_WRITE)) ? VMA_TAINTED : 0);
    tmp->file = file;
    tmp->offset = offset;
    __set_comment(tmp, comment);
    assert(!prev || prev == tmp || prev->addr + prev->length <= tmp->addr);
    return 0;

err:
    if (file)
        put_handle(file);

    return ret;
}

int bkeep_mmap (void * addr, uint64_t length, int prot, int flags,
                struct shim_handle * file, uint64_t offset, const char * comment)
{
    if (!addr || !length)
        return -EINVAL;

    lock(vma_list_lock);
    int ret = __bkeep_mmap(addr, length, prot, flags, file, offset,
                           comment);
    //assert_vma();
    __check_delayed_bkeep();
    unlock(vma_list_lock);
    return ret;
}

/*
 * munmap start at any address and it might be split in between so
 * We need to split the area aur reduce the size
 * Check the address falls between alread allocated area or not
 */
static int __bkeep_munmap (void * addr, uint64_t length, const int * flags)
{
    struct shim_vma * tmp, * n;

    debug("bkeep_unmmap: %p-%p\n", addr, addr + length);

    list_for_each_entry_safe(tmp, n, &vma_list, list) {
        if (test_vma_equal (tmp, addr, length)) {
            if (!check_vma_flags(tmp, flags))
                return -EACCES;
            __remove_vma(tmp);
        } else if (test_vma_overlap (tmp, addr, length)) {
            unsigned long before_length;
            unsigned long after_length;
            unsigned long after_offset;

            if (addr > tmp->addr)
                before_length = addr - tmp->addr;
            else
                before_length = 0;

            if (tmp->addr + tmp->length > addr + length)
                after_length  = (tmp->addr + tmp->length) - (addr + length);
            else
                after_length = 0;

            after_offset  = tmp->file ? tmp->offset + tmp->length -
                after_length : 0;

            /* split case
             * it is Unlikely that a process does an partical unmap
             * but We take care of it by splitting the book-keep
             *
             * case 1 if the vma is entirely between a mapped area
             * .e.g See case:
             *            ---unmap--
             *        ------map-----------
             */

            if (before_length) {
                /* Case 1: Space in the vma before */
                if (!check_vma_flags(tmp, flags))
                    return -EACCES;
                tmp->length = before_length;
                if (after_length) {
                    /* Case 2: Space before and also space after */
                    int ret = __bkeep_mmap((void *) addr + length, after_length,
                                           tmp->prot, tmp->flags,
                                           tmp->file, after_offset,
                                           tmp->comment);
                    if (ret < 0)
                        return ret;
                }
            } else if (after_length) {
                /* Case 3: Only after length */
                if (!check_vma_flags(tmp, flags))
                    return -EACCES;
                tmp->addr = (void *) addr + length;
                tmp->length = after_length;
                tmp->offset = after_offset;
            } else {
                if (!check_vma_flags(tmp, flags))
                    return -EACCES;
                __remove_vma(tmp);
            }
        } else if (tmp->addr > (addr + length))
            break;
    }

    return 0;
}

int bkeep_munmap (void * addr, uint64_t length, const int * flags)
{
    if (!addr || !length)
        return -EINVAL;

    lock(vma_list_lock);
    int ret = __bkeep_munmap(addr, length, flags);
    //assert_vma();
    __check_delayed_bkeep();
    unlock(vma_list_lock);

    return ret;
}

static int __bkeep_mprotect (void * addr, uint64_t length, int prot,
                             const int * flags)
{
    struct shim_vma * tmp = __lookup_vma(addr, length);
    int ret;

    debug("bkeep_mprotect: %p-%p\n", addr, addr + length);

    if (tmp) {
        /* exact match */
        if (!check_vma_flags(tmp, flags))
            return -EACCES;
        tmp->prot = prot;
        if (tmp->file && (prot & PROT_WRITE))
            tmp->flags |= VMA_TAINTED;
        return 0;
    }

    /* split case
     * it is Unlikely that a process does an partical unmap
     * but We take care of it by splitting the book-keep
     *
     * case 1 if the vma is entirely between a mapped area .e.g See case:
     *            ---unmap--
     *        ------map-----------
     */

    tmp = __lookup_supervma(addr, length, NULL);

    if (tmp) {
        if (!check_vma_flags(tmp, flags))
            return -EACCES;

        uint64_t before_length = addr - tmp->addr;
        uint64_t after_length  = tmp->addr + tmp->length - addr - length;
        uint64_t after_offset  = tmp->file ? tmp->offset + tmp->length -
                            after_length : 0;
        uint64_t inside_offset = tmp->file ? tmp->offset + before_length : 0;

        /* split the handler first, because we might call bkeep_mmap */
        tmp->addr = (void *) addr;
        tmp->length = length;

        if (before_length) {
            ret = __bkeep_mmap((void *) addr - before_length, before_length,
                               tmp->prot, tmp->flags,
                               tmp->file, tmp->offset,
                               tmp->comment);
            if (ret < 0)
                return ret;
        }

        if (after_length) {
            ret = __bkeep_mmap((void *)addr + length, after_length,
                               tmp->prot, tmp->flags,
                               tmp->file, after_offset,
                               tmp->comment);
            if (ret < 0)
                return ret;
        }

        tmp->prot = prot;
        tmp->offset = inside_offset;

        if (tmp->file && (prot & PROT_WRITE))
            tmp->flags |= VMA_TAINTED;

        return 0;
    }

    /* split case
     * if the unmap are in between to mapped
     * area then we need to split two VMA here
     * This is the most unlikely case
     *
     * case 2
     *        ------unmap------
     *      ----map1-----;-----map2-------
     *
     * TODO: this algorithm is very inefficient, and may change
     * the mapping if it fails
     */

    uint64_t o_length = length;

    while (length) {
        struct shim_vma * candidate = NULL;

        list_for_each_entry(tmp, &vma_list, list) {
            if (test_vma_contain (tmp, addr, 1)) {
                if (!check_vma_flags(tmp, flags))
                    return -EACCES;

                uint64_t before_length = addr - tmp->addr;
                uint64_t after_length  = tmp->addr + tmp->length > addr + length ?
                                    tmp->addr + tmp->length - addr - length : 0;
                uint64_t after_offset  = tmp->file ? tmp->offset + tmp->length -
                                    after_length : 0;
                uint64_t inside_length = tmp->addr + tmp->length > addr + length ?
                                    length :
                                    addr + length - tmp->addr - tmp->length;
                uint64_t inside_offset = tmp->file ? tmp->offset + before_length : 0;

                /* split the handler first, because we might call bkeep_mmap */
                tmp->addr = (void *) addr;
                tmp->length = inside_length;

                if (before_length) {
                    ret = __bkeep_mmap((void *) addr - before_length, before_length,
                                       tmp->prot, tmp->flags,
                                       tmp->file, tmp->offset,
                                       tmp->comment);
                    if (ret < 0)
                        return ret;
                }

                if (after_length) {
                    ret = __bkeep_mmap((void *) addr + length, after_length,
                                       tmp->prot, tmp->flags,
                                       tmp->file, after_offset,
                                       tmp->comment);
                    if (ret < 0)
                        return ret;
                }

                tmp->prot = prot;
                tmp->offset = inside_offset;

                if (tmp->file && (prot & PROT_WRITE))
                    tmp->flags |= VMA_TAINTED;

                addr += inside_length;
                length -= inside_length;

                break;
            }

            if (test_vma_startin(tmp, addr, length))
                if (!candidate || candidate->addr > tmp->addr)
                    candidate = tmp;
        }

        if (o_length == length) {
            if (!candidate) {
                /* no more vmas, protect the whole area */
                ret = __bkeep_mmap((void *) addr, length, prot,
                                   VMA_UNMAPPED|(flags ? *flags : 0),
                                   NULL, 0, NULL);
                if (ret < 0)
                    return ret;

                candidate = __lookup_vma((void *) addr, length);
                assert(candidate);

                /* DEP 10/19/16: If we make a vma that perfectly matches this
                 * region, we want to break the loop and stop. */
                length = 0;
            }

            length -= candidate->addr - addr;
        }

        o_length = length;
    }

    return 0;
}

int bkeep_mprotect (void * addr, uint64_t length, int prot, const int * flags)
{
    if (!addr || !length)
        return -EINVAL;

    lock(vma_list_lock);
    int ret = __bkeep_mprotect(addr, length, prot, flags);
    //assert_vma();
    unlock(vma_list_lock);

    return ret;
}

static void __set_heap_top (void * bottom, void * top)
{
    bottom += DEFAULT_HEAP_MIN_SIZE;

    if (bottom >= top) {
        heap_top = top;
        return;
    }

    unsigned long rand;
    while (getrand(&rand, sizeof(unsigned long)) < sizeof(unsigned long));

    rand %= (unsigned long) (top - bottom) / allocsize;
    heap_top = bottom + rand * allocsize;
    debug("heap top adjusted to %p\n", heap_top);
}

void * get_unmapped_vma (uint64_t length, int flags)
{
    struct shim_vma * new = get_new_vma(), * prev = NULL;
    if (!new)
        return NULL;

    lock(vma_list_lock);

    __check_delayed_bkeep();

    if (heap_top - heap_bottom < length) {
        unlock(vma_list_lock);
        put_vma(new);
        return NULL;
    }

    do {
        new->addr   = heap_top - length;
        new->length = length;
        new->flags  = flags|VMA_UNMAPPED;
        new->prot   = PROT_NONE;

        list_for_each_entry_reverse(prev, &vma_list, list) {
            if (new->addr >= prev->addr + prev->length)
                break;

            if (new->addr < heap_bottom)
                break;

            if (prev->addr - heap_bottom < length) {
                unlock(vma_list_lock);
                put_vma(new);
                return NULL;
            }

            if (new->addr > prev->addr - length)
                new->addr = prev->addr - length;
        }

        if (&prev->list == &vma_list) {
            prev = NULL;
            break;
        }

        if (new->addr < heap_bottom) {
            if (heap_top == PAL_CB(user_address.end)) {
                unlock(vma_list_lock);
                put_vma(new);
                return NULL;
            } else {
                __set_heap_top(heap_top, (void *) PAL_CB(user_address.end));
                new->addr = NULL;
            }
        }
    } while (!new->addr);

    assert(!prev || prev->addr + prev->length <= new->addr);
    get_vma(new);
    list_add(&new->list, prev ? &prev->list : &vma_list);
    debug("get unmapped: %p-%p\n", new->addr, new->addr + new->length);
    unlock(vma_list_lock);
    return new->addr;
}

#define NTRIES  4

void * get_unmapped_vma_for_cp (uint64_t length)
{
    struct shim_vma * new = get_new_vma(), * prev = NULL;
    if (!new)
        return NULL;

    lock(vma_list_lock);

    __check_delayed_bkeep();

    unsigned long top = (unsigned long) PAL_CB(user_address.end) - length;
    unsigned long bottom = (unsigned long) heap_top;
    int flags = MAP_ANONYMOUS|VMA_UNMAPPED|VMA_INTERNAL;
    void * addr;

    if (bottom >= top) {
        unlock(vma_list_lock);
        return get_unmapped_vma(length, flags);
    }

    debug("find unmapped vma between %p-%p\n", bottom, top);

    for (int i = 0 ; i < NTRIES ; i++) {
        unsigned long rand;
        while (getrand(&rand, sizeof(unsigned long)) < sizeof(unsigned long));
        rand %= (unsigned long) (top - bottom) / allocsize;
        addr = (void *) bottom + rand * allocsize;
        if (!__lookup_overlap_vma(addr, length, &prev))
            break;
        addr = NULL;
    }

    if (!addr) {
        unlock(vma_list_lock);
        debug("cannot find unmapped vma for checkpoint\n");
        return NULL;
    }

    new->addr   = addr;
    new->length = length;
    new->flags  = flags;
    new->prot   = PROT_NONE;

    list_add(&new->list, prev ? &prev->list : &vma_list);
    unlock(vma_list_lock);
    return addr;
}

/* This might not give the same vma but we might need to
   split after we find something */
static struct shim_vma * __lookup_overlap_vma (const void * addr, uint64_t length,
                                               struct shim_vma ** pprev)
{
    struct shim_vma * tmp, * prev = NULL;

    list_for_each_entry(tmp, &vma_list, list) {
        if (test_vma_overlap (tmp, addr, length)) {
            if (pprev)
                *pprev = prev;
            return tmp;
        }

        /* Assert we are really sorted */
        assert(!prev || prev->addr < tmp->addr);
        /* Insert in order; break once we are past the appropriate point  */
        if (tmp->addr > addr)
            break;
        prev = tmp;
    }

    if (pprev)
        *pprev = prev;
    return NULL;
}

int lookup_overlap_vma (const void * addr, uint64_t length,
                        struct shim_vma ** vma)
{
    struct shim_vma * tmp = NULL;
    void * tmp_addr = NULL;
    uint64_t tmp_length;
    lock(vma_list_lock);

    if ((tmp = __lookup_overlap_vma(addr, length, NULL)) && vma)
        get_vma((tmp));

    if (tmp) {
        tmp_addr = tmp->addr;
        tmp_length = tmp->length;
    }

    unlock(vma_list_lock);

    if (tmp)
        debug("vma overlapped at %p-%p\n", tmp_addr, tmp_addr + tmp_length);

    if (vma)
        *vma = tmp;
    return tmp ? 0: -ENOENT;
}

static struct shim_vma * __lookup_vma (const void * addr, uint64_t length)
{
    struct shim_vma * tmp;
    struct shim_vma * prev __attribute__((unused)) = NULL;

    list_for_each_entry(tmp, &vma_list, list) {
        if (test_vma_equal(tmp, addr, length))
            return tmp;

        /* Assert we are really sorted */
        assert(!prev || prev->addr + prev->length <= tmp->addr);
        prev = tmp;
    }

    return NULL;
}

static struct shim_vma * __lookup_supervma (const void * addr, uint64_t length,
                                            struct shim_vma ** pprev)
{
    struct shim_vma * tmp, * prev = NULL;

    list_for_each_entry(tmp, &vma_list, list) {
        if (test_vma_contain(tmp, addr, length)) {
            if (pprev)
                *pprev = prev;
            return tmp;
        }

        /* Assert we are really sorted */
        assert(!prev || prev->addr + prev->length <= tmp->addr);
        /* Insert in order; break once we are past the appropriate point  */
        if (tmp->addr > addr)
            break;
        prev = tmp;
    }

    if (pprev)
        *pprev = prev;
    return NULL;
}

int lookup_supervma (const void * addr, uint64_t length, struct shim_vma ** vma)
{
    struct shim_vma * tmp = NULL;

    lock(vma_list_lock);

    if ((tmp = __lookup_supervma(addr, length, NULL)) && vma)
        get_vma((tmp));

    unlock(vma_list_lock);

    if (vma)
        *vma = tmp;

    return tmp ? 0 : -ENOENT;
}

struct shim_vma * next_vma (struct shim_vma * vma)
{
    struct shim_vma * tmp = vma;

    lock(vma_list_lock);

    if (!tmp) {
        if (!list_empty(&vma_list) &&
            (tmp = list_first_entry(&vma_list, struct shim_vma, list)))
            get_vma(tmp);

        unlock(vma_list_lock);
        return tmp;
    }

    if (tmp->list.next == &vma_list) {
        tmp = NULL;
    } else if (tmp->list.next == &tmp->list) {
        struct shim_vma * tmp2;
        tmp = NULL;
        list_for_each_entry(tmp2, &vma_list, list)
            if (tmp2->addr >= vma->addr) {
                tmp = tmp2;
                get_vma(tmp);
                break;
            }
    } else {
        tmp = list_entry(tmp->list.next, struct shim_vma, list);
        get_vma(tmp);
    }

    put_vma(vma);
    unlock(vma_list_lock);
    return tmp;
}

/* to speed up the checkpointing, go organize the VMAs */
void __shrink_vmas (void)
{
    struct shim_vma * vma, * n, * last;

    list_for_each_entry_safe(vma, n, &vma_list, list) {
        if (!last)
            goto unmap;

        if (last->addr + last->length != vma->addr ||
            last->prot != vma->prot ||
            last->flags != vma->flags ||
            last->file != vma->file)
            goto unmap;

        if (last->file && last->offset + last->length != vma->offset)
            goto unmap;

        debug("shrink vma %p-%p and %p-%p\n", last->addr,
              last->addr + last->length, vma->addr, vma->addr + vma->length);

        last->length += vma->length;
        __remove_vma(vma);
        continue;
next:
        last = vma;
        continue;
unmap:
        if (vma->prot == PROT_NONE && !(vma->flags & VMA_TAINTED))
            vma->flags |= VMA_UNMAPPED;
        goto next;
    }
}

int dump_all_vmas (struct shim_thread * thread, char * buf, uint64_t size)
{
    struct shim_vma * vma;
    int cnt = 0;
    lock(vma_list_lock);

    list_for_each_entry(vma, &vma_list, list) {
        void * start = vma->addr, * end = vma->addr + vma->length;

        if ((vma->flags & (VMA_INTERNAL|VMA_UNMAPPED)) && !vma->comment[0])
            continue;

        char prot[3] = {'-', '-', '-'};
        if (vma->prot & PROT_READ)
            prot[0] = 'r';
        if (vma->prot & PROT_WRITE)
            prot[1] = 'w';
        if (vma->prot & PROT_EXEC)
            prot[2] = 'x';

        if (vma->file) {
            int dev_major = 0, dev_minor = 0;
            unsigned long ino = vma->file->dentry ? vma->file->dentry->ino : 0;
            const char * name = "[unknown]";

            if (!qstrempty(&vma->file->path))
                name = qstrgetstr(&vma->file->path);

            cnt += snprintf(buf + cnt, size - cnt,
                            start > (void *) 0xffffffff ? "%lx" : "%08x",
                            start);
            cnt += snprintf(buf + cnt, size - cnt,
                            end > (void *) 0xffffffff ? "-%lx" : "-%08x", end);
            cnt += snprintf(buf + cnt, size - cnt,
                            " %c%c%cp %08x %02d:%02d %u %s\n",
                            prot[0], prot[1], prot[2],
                            vma->offset, dev_major, dev_minor, ino, name);
        } else {
            cnt += snprintf(buf + cnt, size - cnt,
                            start > (void *) 0xffffffff ? "%lx" : "%08x",
                            start);
            cnt += snprintf(buf + cnt, size - cnt,
                            end > (void *) 0xffffffff ? "-%lx" : "-%08x", end);

            if (vma->comment[0])
                cnt += snprintf(buf + cnt, size - cnt,
                                " %c%c%cp 00000000 00:00 0 [%s]\n",
                                prot[0], prot[1], prot[2], vma->comment);
            else
                cnt += snprintf(buf + cnt, size - cnt,
                                " %c%c%cp 00000000 00:00 0\n",
                                prot[0], prot[1], prot[2]);
        }

        if (cnt >= size) {
            cnt = -EOVERFLOW;
            break;
        }
    }

    unlock(vma_list_lock);
    return cnt;
}

void unmap_all_vmas (void)
{
    struct shim_thread * cur_thread = get_cur_thread();
    struct shim_vma * tmp, * n;
    void * start = NULL, * end = NULL;
    lock(vma_list_lock);

    list_for_each_entry_safe(tmp, n, &vma_list, list) {
        /* a adhoc vma can never be removed */
        if (tmp->flags & VMA_INTERNAL)
            continue;

        if (tmp->flags & VMA_UNMAPPED) {
            __remove_vma(tmp);
            continue;
        }

        if (cur_thread->stack &&
            test_vma_overlap(tmp, cur_thread->stack,
                             cur_thread->stack_top - cur_thread->stack))
            continue;


        if (start == NULL)
            start = end = tmp->addr;

        if (end == tmp->addr) {
            end += tmp->length;
            __remove_vma(tmp);
            continue;
        }

        debug("removing vma %p - %p\n", start, end);
        DkVirtualMemoryFree(start, end - start);

        start = end = tmp->addr;
        end += tmp->length;

        __remove_vma(tmp);
    }

    if (start != NULL && start < end) {
        debug("removing vma %p - %p\n", start, end);
        DkVirtualMemoryFree(start, end - start);
    }

    unlock(vma_list_lock);
}

BEGIN_CP_FUNC(vma)
{
    assert(size == sizeof(struct shim_vma));

    struct shim_vma * vma = (struct shim_vma *) obj;
    struct shim_vma * new_vma = NULL;
    PAL_FLG pal_prot = PAL_PROT(vma->prot, 0);

    ptr_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_vma));
        ADD_TO_CP_MAP(obj, off);

        new_vma = (struct shim_vma *) (base + off);
        memcpy(new_vma, vma, sizeof(struct shim_vma));

        if (vma->file)
            DO_CP(handle, vma->file, &new_vma->file);

        REF_SET(new_vma->ref_count, 0);
        INIT_LIST_HEAD(&new_vma->list);

        void * need_mapped = vma->addr;

#if MIGRATE_MORE_GIPC == 1
        if (store->use_gipc) {
            if (!NEED_MIGRATE_MEMORY_IF_GIPC(vma))
                goto no_mem;
        } else {
            if (!NEED_MIGRATE_MEMORY(vma))
                goto no_mem;
        }
#else
        if (!NEED_MIGRATE_MEMORY(vma))
            goto no_mem;
#endif

        void * send_addr = vma->addr;
        uint64_t    send_size = vma->length;
        bool protected = false;

        if (vma->file) {
            uint64_t file_len = get_file_size(vma->file);
            if (file_len >= 0 &&
                vma->offset + vma->length > file_len)
                send_size = file_len > vma->offset ?
                    file_len - vma->offset : 0;
        }

        if (!send_size)
            goto no_mem;

        if (store->use_gipc) {
#if HASH_GIPC == 1
            if (!(pal_prot & PAL_PROT_READ)) {
                protected = true;
                DkVirtualMemoryProtect(send_addr,
                                       send_size,
                                       pal_prot|PAL_PROT_READ);
            }
#endif /* HASH_GIPC == 1 */
            struct shim_gipc_entry * gipc;
            DO_CP_SIZE(gipc, send_addr, send_size, &gipc);
            gipc->mem.prot = pal_prot;
        } else {
            if (!(pal_prot & PROT_READ)) {
                protected = true;
                DkVirtualMemoryProtect(send_addr,
                                       send_size,
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
        new_vma = (struct shim_vma *) (base + off);
    }

    if (objp)
        *objp = (void *) new_vma;
}
END_CP_FUNC(vma)

DEFINE_PROFILE_CATAGORY(inside_rs_vma, resume_func);
DEFINE_PROFILE_INTERVAL(vma_lookup_overlap, inside_rs_vma);
DEFINE_PROFILE_INTERVAL(vma_add_bookkeep,   inside_rs_vma);
DEFINE_PROFILE_INTERVAL(vma_map_file,       inside_rs_vma);
DEFINE_PROFILE_INTERVAL(vma_map_anonymous,  inside_rs_vma);

BEGIN_RS_FUNC(vma)
{
    struct shim_vma * vma = (void *) (base + GET_CP_FUNC_ENTRY());
    struct shim_vma * tmp, * prev = NULL;
    void * need_mapped = (void *) GET_CP_ENTRY(ADDR);
    int ret = 0;

    CP_REBASE(vma->file);
    CP_REBASE(vma->list);

    lock(vma_list_lock);

    BEGIN_PROFILE_INTERVAL();
    tmp = __lookup_overlap_vma(vma->addr, vma->length, &prev);
    SAVE_PROFILE_INTERVAL(vma_lookup_overlap);

    if (tmp) {
        if ((ret = __bkeep_munmap(vma->addr, vma->length, &vma->flags)) < 0)
            return ret;

        if (prev->list.next == &tmp->list &&
            tmp->addr < vma->addr)
            prev = tmp;
    }

    get_vma(vma);
    list_add(&vma->list, prev ? &prev->list : &vma_list);
    assert_vma();
    SAVE_PROFILE_INTERVAL(vma_add_bookkeep);

    __check_delayed_bkeep();

    unlock(vma_list_lock);

    debug("vma: %p-%p flags %x prot %p\n", vma->addr, vma->addr + vma->length,
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
    struct shim_vma * tmp, ** vmas;
    int nvmas = 0, cnt = 0;

    lock(vma_list_lock);

    __shrink_vmas();

    list_for_each_entry(tmp, &vma_list, list)
        if (!(tmp->flags & VMA_INTERNAL))
            nvmas++;

    if (!nvmas) {
        unlock(vma_list_lock);
        return 0;
    }

    vmas = __alloca(sizeof(struct shim_vam *) * nvmas);

    list_for_each_entry(tmp, &vma_list, list)
        if (!(tmp->flags & VMA_INTERNAL)) {
            get_vma(tmp);
            vmas[cnt++] = tmp;
        }

    unlock(vma_list_lock);

    for (cnt = 0 ; cnt < nvmas ; cnt++) {
        DO_CP(vma, vmas[cnt], NULL);
        put_vma(vmas[cnt]);
    }
}
END_CP_FUNC_NO_RS(all_vmas)

void debug_print_vma_list (void)
{
    sys_printf("vma bookkeeping:\n");

    struct shim_vma * vma;
    list_for_each_entry(vma, &vma_list, list) {
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

        sys_printf("[%p-%p] prot=%08x flags=%08x%s%s offset=%d%s%s%s%s\n",
                   vma->addr, vma->addr + vma->length,
                   vma->prot,
                   vma->flags & ~(VMA_INTERNAL|VMA_UNMAPPED|VMA_TAINTED),
                   type, name,
                   vma->offset,
                   vma->flags & VMA_INTERNAL ? " (internal)" : "",
                   vma->flags & VMA_UNMAPPED ? " (unmapped)" : "",
                   vma->comment[0] ? " comment=" : "",
                   vma->comment[0] ? vma->comment : "");
    }
}

void print_vma_hash (struct shim_vma * vma, void * addr, uint64_t len,
                     bool force_protect)
{
    if (!addr)
        addr = vma->addr;
    if (!len)
        len = vma->length - (addr - vma->addr);

    if (addr < vma->addr || addr + len > vma->addr + vma->length)
        return;

    if (!(vma->prot & PROT_READ)) {
        if (!force_protect)
            return;
        DkVirtualMemoryProtect(vma->addr, vma->length, PAL_PROT_READ);
    }

    for (unsigned long p = (unsigned long) addr ;
         p < (unsigned long) addr + len ; p += allocsize) {
            unsigned long hash = 0;
            struct shim_md5_ctx ctx;
            md5_init(&ctx);
            md5_update(&ctx, (void *) p, allocsize);
            md5_final(&ctx);
            memcpy(&hash, ctx.digest, sizeof(unsigned long));
        }

    if (!(vma->prot & PROT_READ))
        DkVirtualMemoryProtect(vma->addr, vma->length, vma->prot);
}
