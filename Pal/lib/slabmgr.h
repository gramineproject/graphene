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
 * slabmgr.h
 *
 * This file contains implementation of SLAB (variable-size) memory allocator.
 */

#ifndef SLABMGR_H
#define SLABMGR_H

#include "list.h"
#include <assert.h>
#include <sys/mman.h>

#ifndef system_malloc
#error "macro \"void * system_malloc(int size)\" not declared"
#endif
#ifndef system_free
#error "macro \"void * system_free(void * ptr, int size)\" not declared"
#endif
#ifndef system_lock
#define system_lock() ({})
#endif
#ifndef system_unlock
#define system_unlock() ({})
#endif

/* malloc is supposed to provide some kind of alignment guarantees, but
 * I can't find a specific reference to what that should be for x86_64.
 * The first link here is a reference to a technical report from Mozilla,
 * which seems to indicate that 64-bit platforms align return values to
 * 16-bytes. calloc and malloc provide the same alignment guarantees.
 * calloc additionally sets the memory to 0, which malloc is not required
 * to do.
 *
 * http://www.erahm.org/2016/03/24/minimum-alignment-of-allocation-across-platforms/
 * http://pubs.opengroup.org/onlinepubs/9699919799/functions/malloc.html
 */
#define MIN_MALLOC_ALIGNMENT 16

/* Slab objects need to be a multiple of 16 bytes to ensure proper address
 * alignment for malloc and calloc. */
#define OBJ_PADDING   15

#define LARGE_OBJ_PADDING 8

/* Returns the smallest exact multiple of _y that is at least as large as _x.
 * In other words, returns _x if _x is a multiple of _y, otherwise rounds
 * _x up to be a multiple of _y.
 */
#define ROUND_UP(_x, _y) ((((_x) + (_y) - 1) / (_y)) * (_y))

DEFINE_LIST(slab_obj);

typedef struct __attribute__((packed)) slab_obj {
    unsigned char level;
    unsigned char padding[OBJ_PADDING];
    union {
        LIST_TYPE(slab_obj) __list;
        unsigned char *raw;
    };
} SLAB_OBJ_TYPE, * SLAB_OBJ;

/* In order for slab elements to be 16-byte aligned, struct slab_area must
 * be a multiple of 16 bytes. TODO: Add compile time assertion that this
 * invariant is respected. */
#define AREA_PADDING 12

DEFINE_LIST(slab_area);

typedef struct __attribute__((packed)) slab_area {
    LIST_TYPE(slab_area) __list;
    unsigned int size;
    unsigned char pad[AREA_PADDING];
    unsigned char raw[];
} SLAB_AREA_TYPE, * SLAB_AREA;

#ifdef SLAB_DEBUG
struct slab_debug {
    struct {
        const char * file;
        int          line;
    } alloc, free;
};

# define SLAB_DEBUG_SIZE    sizeof(struct slab_debug)
#else
# define SLAB_DEBUG_SIZE    0
#endif

#ifdef SLAB_CANARY
# define SLAB_CANARY_STRING 0xDEADBEEF
# define SLAB_CANARY_SIZE   sizeof(unsigned long)
#else
# define SLAB_CANARY_SIZE   0
#endif

#define SLAB_HDR_SIZE \
    ROUND_UP((sizeof(SLAB_OBJ_TYPE) - sizeof(LIST_TYPE(slab_obj)) +     \
              SLAB_DEBUG_SIZE + SLAB_CANARY_SIZE), \
             MIN_MALLOC_ALIGNMENT)

#ifndef SLAB_LEVEL
#define SLAB_LEVEL 8
#endif

#ifndef SLAB_LEVEL_SIZES
# define SLAB_LEVEL_SIZES  16, 32, 64,           \
                           128  - SLAB_HDR_SIZE, \
                           256  - SLAB_HDR_SIZE, \
                           512  - SLAB_HDR_SIZE, \
                           1024 - SLAB_HDR_SIZE, \
                           2048 - SLAB_HDR_SIZE
# define SLAB_LEVELS_SUM  (4080 - SLAB_HDR_SIZE * 5)
#else
# ifndef SLAB_LEVELS_SUM
# error "SALB_LEVELS_SUM not defined"
# endif
#endif

static int slab_levels[SLAB_LEVEL] = { SLAB_LEVEL_SIZES };

DEFINE_LISTP(slab_obj);
DEFINE_LISTP(slab_area);
typedef struct slab_mgr {
    LISTP_TYPE(slab_area) area_list[SLAB_LEVEL];
    LISTP_TYPE(slab_obj) free_list[SLAB_LEVEL];
    unsigned int size[SLAB_LEVEL];
    void * addr[SLAB_LEVEL], * addr_top[SLAB_LEVEL];
} SLAB_MGR_TYPE, * SLAB_MGR;

typedef struct __attribute__((packed)) large_mem_obj {
    // offset 0
    unsigned long size;
    unsigned char large_padding[LARGE_OBJ_PADDING];
    // offset 16
    unsigned char level;
    unsigned char padding[OBJ_PADDING];
    // offset 32
    unsigned char raw[];
} LARGE_MEM_OBJ_TYPE, * LARGE_MEM_OBJ;

#define OBJ_LEVEL(obj) ((obj)->level)
#define OBJ_RAW(obj) (&(obj)->raw)

#ifndef container_of
#define container_of(ptr, type, field) ((type *)((char *)(ptr) - offsetof(type, field)))
#endif

#define RAW_TO_LEVEL(raw_ptr) \
            (*((unsigned char *) (raw_ptr) - OBJ_PADDING - 1))
#define RAW_TO_OBJ(raw_ptr, type) container_of((raw_ptr), type, raw)

#define __SUM_OBJ_SIZE(slab_size, size) \
            (((slab_size) + SLAB_HDR_SIZE) * (size))
#define __MIN_MEM_SIZE() (sizeof(SLAB_AREA_TYPE))
#define __MAX_MEM_SIZE(slab_size, size) \
            (__MIN_MEM_SIZE() + __SUM_OBJ_SIZE((slab_size), (size)))

#define __INIT_SUM_OBJ_SIZE(size) \
            ((SLAB_LEVELS_SUM + SLAB_HDR_SIZE * SLAB_LEVEL) * (size))
#define __INIT_MIN_MEM_SIZE() \
            (sizeof(SLAB_MGR_TYPE) + sizeof(SLAB_AREA_TYPE) * SLAB_LEVEL)
#define __INIT_MAX_MEM_SIZE(size) \
            (__INIT_MIN_MEM_SIZE() + __INIT_SUM_OBJ_SIZE((size)))

#ifdef PAGE_SIZE
static inline int size_align_down(int slab_size, int size)
{
    int s = __MAX_MEM_SIZE(slab_size, size);
    int p = s - (s & ~(PAGE_SIZE - 1));
    int o = __SUM_OBJ_SIZE(slab_size, 1);
    return size - p / o - (p % o ? 1 : 0);
}

static inline int size_align_up(int slab_size, int size)
{
    int s = __MAX_MEM_SIZE(slab_size, size);
    int p = ((s + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)) - s;
    int o = __SUM_OBJ_SIZE(slab_size, 1);
    return size + p / o;
}

static inline int init_align_down(int size)
{
    int s = __INIT_MAX_MEM_SIZE(size);
    int p = s - (s & ~(PAGE_SIZE - 1));
    int o = __INIT_SUM_OBJ_SIZE(1);
    return size - p /o - (p % o ? 1 : 0);
}

static inline int init_size_align_up(int size)
{
    int s = __INIT_MAX_MEM_SIZE(size);
    int p = ((s + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)) - s;
    int o = __INIT_SUM_OBJ_SIZE(1);
    return size + p / o;
}
#endif /* PAGE_SIZE */

#ifndef STARTUP_SIZE
# define STARTUP_SIZE 16
#endif

static inline void __set_free_slab_area (SLAB_AREA area, SLAB_MGR mgr,
                                         int level)
{
    int slab_size = slab_levels[level] + SLAB_HDR_SIZE;
    mgr->addr[level] = (void *) area->raw;
    mgr->addr_top[level] = (void *) area->raw + area->size * slab_size;
    mgr->size[level] += area->size;
}

static inline SLAB_MGR create_slab_mgr (void)
{
#ifdef PAGE_SIZE
    int size = init_size_align_up(STARTUP_SIZE);
#else
    int size = STARTUP_SIZE;
#endif
    unsigned long mem;
    SLAB_AREA area;
    SLAB_MGR mgr;

    mem = (unsigned long) system_malloc(__INIT_MAX_MEM_SIZE(size));

    if (mem <= 0)
        return NULL;

    mgr = (SLAB_MGR) mem;

    void * addr = (void *) mgr + sizeof(SLAB_MGR_TYPE);
    int i;
    for (i = 0 ; i < SLAB_LEVEL ; i++) {
        area = (SLAB_AREA) addr;
        area->size = STARTUP_SIZE;

        INIT_LIST_HEAD(area, __list);
        INIT_LISTP(&mgr->area_list[i]);
        listp_add_tail(area, &mgr->area_list[i], __list);

        INIT_LISTP(&mgr->free_list[i]);
        mgr->size[i] = 0;
        __set_free_slab_area(area, mgr, i);

        addr += __MAX_MEM_SIZE(slab_levels[i], STARTUP_SIZE);
    }

    return mgr;
}

static inline void destroy_slab_mgr (SLAB_MGR mgr)
{
    void * addr = (void *) mgr + sizeof(SLAB_MGR_TYPE);
    SLAB_AREA area, tmp, n;
    int i;
    for (i = 0 ; i < SLAB_LEVEL; i++) {
        area = (SLAB_AREA) addr;

        listp_for_each_entry_safe(tmp, n, &mgr->area_list[i], __list) {
            if (tmp != area)
                system_free(area,
                            __MAX_MEM_SIZE(slab_levels[i], area->size));
        }

        addr += __MAX_MEM_SIZE(slab_levels[i], STARTUP_SIZE);
    }

    system_free(mgr, addr - (void *) mgr);
}

static inline SLAB_MGR enlarge_slab_mgr (SLAB_MGR mgr, int level)
{
    SLAB_AREA area;
    int size;

    if (level >= SLAB_LEVEL) {
        system_lock();
        goto out;
    }

    size = mgr->size[level];
    area = (SLAB_AREA) system_malloc(__MAX_MEM_SIZE(slab_levels[level], size));
    if (area <= 0)
        return NULL;

    system_lock();
    area->size = size;
    INIT_LIST_HEAD(area, __list);
    listp_add(area, &mgr->area_list[level], __list);
    __set_free_slab_area(area, mgr, level);
    system_unlock();

out:
    return mgr;
}

static inline void * slab_alloc (SLAB_MGR mgr, int size)
{
    SLAB_OBJ mobj;
    int i;
    int level = -1;

    for (i = 0 ; i < SLAB_LEVEL ; i++)
        if (size <= slab_levels[i]) {
            level = i;
            break;
        }

    if (level == -1) {
        LARGE_MEM_OBJ mem = (LARGE_MEM_OBJ)
                            system_malloc(sizeof(LARGE_MEM_OBJ_TYPE) + size);
        if (!mem)
            return NULL;

        mem->size = size;
        OBJ_LEVEL(mem) = (unsigned char) -1;

        return OBJ_RAW(mem);
    }

    system_lock();
    if (mgr->addr[level] == mgr->addr_top[level] &&
        listp_empty(&mgr->free_list[level])) {
        system_unlock();
        enlarge_slab_mgr(mgr, level);
        system_lock();
    }

    if (!listp_empty(&mgr->free_list[level])) {
        mobj = listp_first_entry(&mgr->free_list[level], SLAB_OBJ_TYPE, __list);
        listp_del(mobj, &mgr->free_list[level], __list);
    } else {
        mobj = (void *) mgr->addr[level];
        mgr->addr[level] += slab_levels[level] + SLAB_HDR_SIZE;
    }
    OBJ_LEVEL(mobj) = level;
    system_unlock();

#ifdef SLAB_CANARY
    unsigned long * m =
            (unsigned long *) ((void *) OBJ_RAW(mobj) + slab_levels[level]);
    *m = SLAB_CANARY_STRING;
#endif

    return OBJ_RAW(mobj);
}

#ifdef SLAB_DEBUG
static inline void * slab_alloc_debug (SLAB_MGR mgr, int size,
                                       const char * file, int line)
{
    void * mem = slab_alloc(mgr, size);
    int i;
    int level = -1;

    for (i = 0 ; i < SLAB_LEVEL ; i++)
        if (size <= slab_levels[i]) {
            level = i;
            break;
        }

    if (level != -1) {
        struct slab_debug * debug =
                (struct slab_debug *) (mem + slab_levels[level] +
                                       SLAB_CANARY_SIZE);
        debug->alloc.file = file;
        debug->alloc.line = line;
    }

    return mem;
}
#endif

static inline void slab_free (SLAB_MGR mgr, void * obj)
{
    /* In a general purpose allocator, free of NULL is allowed (and is a 
     * nop). We might want to enforce stricter rules for our allocator if
     * we're sure that no clients rely on being able to free NULL. */
    if (obj == NULL)
        return;
    
    unsigned char level = RAW_TO_LEVEL(obj);

    if (level == (unsigned char) -1) {
        LARGE_MEM_OBJ mem = RAW_TO_OBJ(obj, LARGE_MEM_OBJ_TYPE);
        system_free(mem, mem->size + sizeof(LARGE_MEM_OBJ_TYPE));
        return;
    }

    /* If this happens, either the heap is already corrupted, or someone's
     * freeing something that's wrong, which will most likely lead to heap
     * corruption. Either way, panic if this happens. TODO: this doesn't allow
     * us to detect cases where the heap headers have been zeroed, which
     * is a common type of heap corruption. We could make this case slightly
     * more likely to be detected by adding a non-zero offset to the level,
     * so a level of 0 in the header would no longer be a valid level. */
    if (level >= SLAB_LEVEL) {
        pal_printf("Heap corruption detected: invalid heap level %ud\n", level);
        assert(0); // panic
    }

#ifdef SLAB_CANARY
    unsigned long * m = (unsigned long *) (obj + slab_levels[level]);
    assert((*m) == SLAB_CANARY_STRING);
#endif

    SLAB_OBJ mobj = RAW_TO_OBJ(obj, SLAB_OBJ_TYPE);

    system_lock();
    INIT_LIST_HEAD(mobj, __list);
    listp_add_tail(mobj, &mgr->free_list[level], __list);
    system_unlock();
}

#ifdef SLAB_DEBUG

static inline void slab_free_debug (SLAB_MGR mgr, void * obj,
                                    const char * file, int line)
{
    if (obj == NULL)
        return;
    
    unsigned char level = RAW_TO_LEVEL(obj);

    if (level < SLAB_LEVEL) {
        struct slab_debug * debug =
                (struct slab_debug *) (obj + slab_levels[level] +
                                       SLAB_CANARY_SIZE);
        debug->free.file = file;
        debug->free.line = line;
    }

    slab_free(mgr, obj);
}
#endif

#endif /* SLABMGR_H */
