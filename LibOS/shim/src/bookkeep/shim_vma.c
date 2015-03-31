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

#define VMA_MGR_ALLOC   64
#define PAGE_SIZE       allocsize

static LOCKTYPE vma_mgr_lock;

#define system_lock()       lock(vma_mgr_lock)
#define system_unlock()     unlock(vma_mgr_lock)

#define OBJ_TYPE struct shim_vma
#include <memmgr.h>

static MEM_MGR vma_mgr = NULL;

static LIST_HEAD(vma_list);
static LOCKTYPE vma_list_lock;

static inline int test_vma_equal (struct shim_vma * tmp,
                                  const void * addr, size_t length)
{
    return tmp->addr == addr &&
           tmp->addr + tmp->length == addr + length;
}

static inline int test_vma_contain (struct shim_vma * tmp,
                                    const void * addr, size_t length)
{
    return tmp->addr <= addr &&
           tmp->addr + tmp->length >= addr + length;
}

static inline int test_vma_startin (struct shim_vma * tmp,
                                    const void * addr, size_t length)
{
    return tmp->addr >= addr &&
           tmp->addr < addr + length;
}

static inline int test_vma_endin (struct shim_vma * tmp,
                                  const void * addr, size_t length)
{
    return tmp->addr + tmp->length > addr &&
           tmp->addr + tmp->length <= addr + length;
}

static inline int test_vma_overlap (struct shim_vma * tmp,
                                    const void * addr, size_t length)
{
    return test_vma_contain (tmp, addr + 1, 0) ||
           test_vma_contain (tmp, addr + length - 1, 0) ||
           test_vma_startin (tmp, addr, length - 1);
}

int bkeep_shim_heap (void);

int init_vma (void)
{
    if (!(vma_mgr = create_mem_mgr(init_align_up(VMA_MGR_ALLOC))))
        return -ENOMEM;

    bkeep_shim_heap();
    create_lock(vma_list_lock);

    return 0;
}

/* This might not give the same vma but we might need to
   split after we find something */
static inline void assert_vma (void)
{
    struct shim_vma * tmp;
    struct shim_vma * prv __attribute__((unused)) = NULL;

    list_for_each_entry(tmp, &vma_list, list) {
        /* Assert we are really sorted */
        assert(tmp->length > 0);
        assert(!prv || prv->addr + prv->length <= tmp->addr);
        prv = tmp;
    }
}

static struct shim_vma * __lookup_vma (const void * addr, size_t len);
static struct shim_vma * __lookup_supervma (const void * addr, size_t length,
                                            struct shim_vma ** prev);
static struct shim_vma * __lookup_overlap_vma (const void * addr, size_t length,
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
    list_del_init(&vma->list);
    put_vma(vma);
}

static int __bkeep_mmap (void * addr, size_t length,
                         int prot, int flags,
                         struct shim_handle * file, int offset,
                         const char * comment);

static int __bkeep_mprotect (void * addr, size_t length, int prot,
                             const int * flags);

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

    int len = strlen(comment);

    if (len > VMA_COMMENT_LEN - 1)
        len = VMA_COMMENT_LEN - 1;

    memcpy(vma->comment, comment, len + 1);
}

static int __bkeep_mmap (void * addr, size_t length,
                         int prot, int flags,
                         struct shim_handle * file, int offset,
                         const char * comment)
{
    struct shim_vma * prev = NULL;
    struct shim_vma * tmp = __lookup_supervma(addr, length, &prev);
    int ret = 0;

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
            unlock(vma_list_lock);

            if (!(tmp = get_new_vma()))
                return -ENOMEM;

            lock(vma_list_lock);
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

    return 0;

err:
    if (file)
        put_handle(file);

    return ret;
}

int bkeep_mmap (void * addr, size_t length, int prot, int flags,
                struct shim_handle * file, int offset,
                const char * comment)
{
    if (!addr || !length)
        return -EINVAL;

    lock(vma_list_lock);
    int ret = __bkeep_mmap(addr, length, prot, flags, file, offset,
                           comment);
    assert_vma();
    unlock(vma_list_lock);

    return ret;
}

/*
 * munmap start at any address and it might be split in between so
 * We need to split the area aur reduce the size
 * Check the address falls between alread allocated area or not
 */
static int __bkeep_munmap (void * addr, size_t length, const int * flags)
{
    struct shim_vma * tmp, * n;

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

int bkeep_munmap (void * addr, size_t length, const int * flags)
{
    if (!addr || !length)
        return -EINVAL;

    lock(vma_list_lock);
    int ret = __bkeep_munmap(addr, length, flags);
    assert_vma();
    unlock(vma_list_lock);

    return ret;
}

static int __bkeep_mprotect (void * addr, size_t length, int prot,
                             const int * flags)
{
    struct shim_vma * tmp = __lookup_vma(addr, length);
    int ret;

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

        int before_length = addr - tmp->addr;
        int after_length  = tmp->addr + tmp->length - addr - length;
        int after_offset  = tmp->file ? tmp->offset + tmp->length -
                            after_length : 0;
        int inside_offset = tmp->file ? tmp->offset + before_length : 0;

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

    int o_length = length;

    while (length) {
        struct shim_vma * candidate = NULL;

        list_for_each_entry(tmp, &vma_list, list) {
            if (test_vma_contain (tmp, addr, 1)) {
                if (!check_vma_flags(tmp, flags))
                    return -EACCES;

                int before_length = addr - tmp->addr;
                int after_length  = tmp->addr + tmp->length > addr + length ?
                                    tmp->addr + tmp->length - addr - length : 0;
                int after_offset  = tmp->file ? tmp->offset + tmp->length -
                                    after_length : 0;
                int inside_length = tmp->addr + tmp->length > addr + length ?
                                    length :
                                    addr + length - tmp->addr - tmp->length;
                int inside_offset = tmp->file ? tmp->offset + before_length : 0;

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
            }

            length -= candidate->addr - addr;
        }

        o_length = length;
    }

    return 0;
}

int bkeep_mprotect (void * addr, size_t length, int prot, const int * flags)
{
    if (!addr || !length)
        return -EINVAL;

    lock(vma_list_lock);
    int ret = __bkeep_mprotect(addr, length, prot, flags);
    assert_vma();
    unlock(vma_list_lock);

    return ret;
}

void * get_unmapped_vma (size_t length, int flags)
{
    struct shim_vma * new = get_new_vma();
    if (!new)
        return NULL;

    struct shim_vma * tmp, * prev = NULL;
    lock(vma_list_lock);

    new->addr = pal_control.user_address_begin;
    new->length = length;
    new->flags = flags|VMA_UNMAPPED;

    list_for_each_entry(tmp, &vma_list, list) {
        if (tmp->addr <= new->addr) {
            if (tmp->addr + tmp->length > new->addr)
                new->addr = tmp->addr + tmp->length;
            prev = tmp;
            continue;
        }

        if (tmp->addr >= new->addr + length)
            break;

        new->addr = tmp->addr + tmp->length;
        prev = tmp;
    }

    if (new->addr + length > pal_control.user_address_end) {
        unlock(vma_list_lock);
        put_vma(new);
        return NULL;
    }

    assert(!prev || prev->addr + prev->length <= new->addr);
    get_vma(new);
    list_add(&new->list, prev ? &prev->list : &vma_list);
    unlock(vma_list_lock);
    return new->addr;
}

/* This might not give the same vma but we might need to
   split after we find something */
static struct shim_vma * __lookup_overlap_vma (const void * addr, size_t length,
                                               struct shim_vma ** prev)
{
    struct shim_vma * tmp;
    struct shim_vma * prv = NULL;

    list_for_each_entry(tmp, &vma_list, list) {
        if (test_vma_overlap (tmp, addr, length)) {
            if (prev)
                *prev = prv;

            return tmp;
        }

        /* Assert we are really sorted */
        assert(!prv || prv->addr < tmp->addr);

        /* Insert in order; break once we are past the appropriate point  */
        if (tmp->addr > addr)
            break;

        prv = tmp;
    }

    if (prev)
        *prev = prv;

    return NULL;
}

int lookup_overlap_vma (const void * addr, size_t length,
                        struct shim_vma ** vma)
{
    struct shim_vma * tmp = NULL;

    lock(vma_list_lock);

    if ((tmp = __lookup_overlap_vma(addr, length, NULL)) && vma)
        get_vma((tmp));

    unlock(vma_list_lock);

    if (vma)
        *vma = tmp;

    return tmp ? 0: -ENOENT;
}

static struct shim_vma * __lookup_vma (const void * addr, size_t length)
{
    struct shim_vma * tmp;
    struct shim_vma * prv __attribute__((unused)) = NULL;

    list_for_each_entry(tmp, &vma_list, list) {
        if (test_vma_equal(tmp, addr, length))
            return tmp;

        /* Assert we are really sorted */
        assert(!prv || prv->addr + prv->length <= tmp->addr);

        prv = tmp;
    }

    return NULL;
}

static struct shim_vma * __lookup_supervma (const void * addr, size_t length,
                                            struct shim_vma ** prev)
{
    struct shim_vma * tmp;
    struct shim_vma * prv = NULL;

    list_for_each_entry(tmp, &vma_list, list) {
        if (test_vma_contain(tmp, addr, length)) {
            if (prev)
                *prev = prv;

            return tmp;
        }

        /* Assert we are really sorted */
        assert(!prv || prv->addr + prv->length <= tmp->addr);

        /* Insert in order; break once we are past the appropriate point  */
        if (tmp->addr > addr)
            break;

        prv = tmp;
    }

    if (prev)
        *prev = prv;

    return NULL;
}

int lookup_supervma (const void * addr, size_t length, struct shim_vma ** vma)
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

int dump_all_vmas (struct shim_thread * thread, char * buf, size_t size)
{
    lock(vma_list_lock);

    struct shim_vma * vma;
    int cnt = 0;

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
                            start > (void *) 0xffffffff ? "%lx" : "%08x", start);

            cnt += snprintf(buf + cnt, size - cnt,
                            end > (void *) 0xffffffff ? "-%lx" : "-%08x", end);

            cnt += snprintf(buf + cnt, size - cnt,
                            " %c%c%cp %08x %02d:%02d %u %s\n",
                            prot[0], prot[1], prot[2],
                            vma->offset, dev_major, dev_minor, ino,
                            name);
        } else {
            cnt += snprintf(buf + cnt, size - cnt,
                            start > (void *) 0xffffffff ? "%lx" : "%08x", start);

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

DEFINE_MIGRATE_FUNC(vma)

MIGRATE_FUNC_BODY(vma)
{
    assert(size == sizeof(struct shim_vma));

    struct shim_vma * vma = (struct shim_vma *) obj;
    struct shim_vma * new_vma = NULL;

    struct shim_handle * file = NULL;

    if (vma->file && recursive)
        __DO_MIGRATE(handle, vma->file, &file, 1);

    unsigned long off = ADD_TO_MIGRATE_MAP(obj, *offset, size);

    if (ENTRY_JUST_CREATED(off)) {
        ADD_OFFSET(sizeof(struct shim_vma));
        ADD_FUNC_ENTRY(*offset);
        ADD_ENTRY(SIZE, sizeof(struct shim_vma));

        if (!dry) {
            new_vma = (struct shim_vma *) (base + *offset);
            memcpy(new_vma, vma, sizeof(struct shim_vma));

            new_vma->file = file;
            new_vma->received = 0;
            REF_SET(new_vma->ref_count, 0);
            INIT_LIST_HEAD(&new_vma->list);
        }

        if (recursive && NEED_MIGRATE_MEMORY(vma)) {
            void * send_addr = vma->addr;
            size_t send_size = vma->length;

            if (vma->file) {
                size_t file_len = get_file_size(vma->file);
                if (file_len >= 0 &&
                    vma->offset + vma->length > file_len)
                    send_size = file_len > vma->offset ?
                                file_len - vma->offset : 0;
            }

            if (send_size) {
                bool protected = false;
                if (store->use_gipc) {
#if HASH_GIPC == 1
                    if (!dry && !(vma->prot & PROT_READ)) {
                        protected = true;
                        DkVirtualMemoryProtect(send_addr, send_size, vma->prot |
                                               PAL_PROT_READ);
                    }
#endif /* HASH_GIPC == 1 */
                    struct shim_gipc_entry * gipc;
                    DO_MIGRATE_SIZE(gipc, send_addr, send_size, &gipc, false);
                    if (!dry) {
                        gipc->prot = vma->prot;
                        gipc->vma  = new_vma;
                    }
#if HASH_GIPC == 1
                    if (protected)
                        DkVirtualMemoryProtect(send_addr, send_size, vma->prot);
#endif /* HASH_GIPC == 1 */
                } else {
                    if (!dry && !(vma->prot & PROT_READ)) {
                        protected = true;
                        DkVirtualMemoryProtect(send_addr, send_size, vma->prot |
                                               PAL_PROT_READ);
                    }

                    struct shim_mem_entry * mem;
                    DO_MIGRATE_SIZE(memory, send_addr, send_size, &mem, false);
                    if (!dry) {
                        mem->prot = vma->prot;
                        mem->vma = vma;
                    }

                    if (protected)
                        DkVirtualMemoryProtect(send_addr, send_size, vma->prot);
                }
            }
        }
    } else if (!dry)
        new_vma = (struct shim_vma *) (base + off);

    if (new_vma && objp)
        *objp = (void *) new_vma;
}
END_MIGRATE_FUNC

RESUME_FUNC_BODY(vma)
{
    unsigned long off = GET_FUNC_ENTRY();
    assert((size_t) GET_ENTRY(SIZE) == sizeof(struct shim_vma));
    struct shim_vma * vma = (struct shim_vma *) (base + off);
    struct shim_vma * tmp, * prev = NULL;
    int ret = 0;

    RESUME_REBASE(vma->file);
    RESUME_REBASE(vma->list);

    lock(vma_list_lock);

    tmp = __lookup_overlap_vma(vma->addr, vma->length, &prev);

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

    unlock(vma_list_lock);

    int allocated = vma->received;

    if (vma->flags & VMA_UNMAPPED)
#ifdef DEBUG_RESUME
        goto no_map;
#else
        return 0;
#endif

    if (vma->file)
        get_handle(vma->file);

    if (allocated < vma->length && vma->file) {
        /* first try, use hstat to force it resumes pal handle */
        assert(vma->file->fs && vma->file->fs->fs_ops &&
               vma->file->fs->fs_ops->mmap);

        void * addr = vma->addr + allocated;

        int ret = vma->file->fs->fs_ops->mmap(vma->file, &addr,
                                              vma->length - allocated,
                                              vma->prot|PAL_PROT_WRITECOPY,
                                              vma->flags,
                                              vma->offset + allocated);

        if (ret < 0)
            return ret;
        if (!addr)
            return -ENOMEM;
        if (addr != vma->addr + allocated)
            return -EACCES;

        allocated = vma->length;
    }

    if (allocated < vma->length) {
        int pal_alloc_type = ((vma->flags & MAP_32BIT) ? PAL_ALLOC_32BIT : 0);
        int pal_prot = vma->prot;
        if (DkVirtualMemoryAlloc(vma->addr + allocated, vma->length - allocated,
                                 pal_alloc_type, pal_prot))
            allocated = vma->length;
    }

    if (allocated < vma->length)
        debug("vma %p-%p cannot be allocated!\n", vma->addr + allocated,
              vma->addr + vma->length);

    vma->received = allocated;

#ifdef DEBUG_RESUME
    if (vma->file) {
        const char * type = "", * name = "";

        if (!qstrempty(&vma->file->path)) {
            type = ",path=";
            name = qstrgetstr(&vma->file->path);
        } else if (!qstrempty(&vma->file->uri)) {
            type = ",uri=";
            name = qstrgetstr(&vma->file->uri);
        }

        debug("vma: %p-%p,size=%d,prot=%08x,flags=%08x,offset=%d%s%s\n",
              vma->addr, vma->addr + vma->length, vma->length,
              vma->prot, vma->flags, vma->offset, type, name);
    } else {
no_map:
        debug("vma: %p-%p,size=%d,prot=%08x,flags=%08x,offset=%d\n",
              vma->addr, vma->addr + vma->length, vma->length,
              vma->prot, vma->flags, vma->offset);
    }
#endif /* DEBUG_RESUME */
}
END_RESUME_FUNC

DEFINE_MIGRATE_FUNC(all_vmas)

MIGRATE_FUNC_BODY(all_vmas)
{
    lock(vma_list_lock);

    if (!list_empty(&vma_list)) {
        struct shim_vma * tmp =
                list_first_entry(&vma_list, struct shim_vma, list);

        while (tmp) {
            if (tmp->flags & VMA_INTERNAL)
                goto next;

            get_vma(tmp);
            unlock(vma_list_lock);

            DO_MIGRATE(vma, tmp, NULL, recursive);

            lock(vma_list_lock);
            put_vma(tmp);

next:
            if (tmp->list.next == &vma_list)
                break;

            tmp = list_entry(tmp->list.next, struct shim_vma, list);
        }
    }

    unlock(vma_list_lock);
}
END_MIGRATE_FUNC

RESUME_FUNC_BODY(all_vmas)
{
    /* useless */
}
END_RESUME_FUNC

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

void print_vma_hash (struct shim_vma * vma, void * addr, int len,
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
