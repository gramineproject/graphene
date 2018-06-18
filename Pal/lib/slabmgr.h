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
#include <pal_debug.h>
#include <assert.h>
#include <errno.h>
#include <sys/mman.h>

// Before calling any of `system_malloc` and `system_free` this library will
// acquire `system_lock` (the systen_* implementation must not do it).
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
              SLAB_DEBUG_SIZE + SLAB_CANARY_SIZE),                      \
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

// User buffer sizes on each level (not counting mandatory header
// (SLAB_HDR_SIZE)).
static const int slab_levels[SLAB_LEVEL] = { SLAB_LEVEL_SIZES };

DEFINE_LISTP(slab_obj);
DEFINE_LISTP(slab_area);
typedef struct slab_mgr {
    LISTP_TYPE(slab_area) area_list[SLAB_LEVEL];
    LISTP_TYPE(slab_obj) free_list[SLAB_LEVEL];
    size_t size[SLAB_LEVEL];
    void * addr[SLAB_LEVEL], * addr_top[SLAB_LEVEL];
    SLAB_AREA active_area[SLAB_LEVEL];
} SLAB_MGR_TYPE, * SLAB_MGR;

typedef struct __attribute__((packed)) large_mem_obj {
    // offset 0
    unsigned long size;  // User buffer size (i.e. excluding control structures)
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
            (*((const unsigned char *) (raw_ptr) - OBJ_PADDING - 1))
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
    mgr->addr_top[level] = (void *) area->raw + (area->size * slab_size);
    mgr->size[level] += area->size;
    mgr->active_area[level] = area;
}

static inline SLAB_MGR create_slab_mgr (void)
{
#ifdef PAGE_SIZE
    size_t size = init_size_align_up(STARTUP_SIZE);
#else
    size_t size = STARTUP_SIZE;
#endif
    void * mem = NULL;
    SLAB_AREA area;
    SLAB_MGR mgr;

    /* If the allocation failed, always try smaller sizes */
    for (; size > 0; size >>= 1) {
        mem = system_malloc(__INIT_MAX_MEM_SIZE(size));
        if (mem)
            break;
    }

    if (!mem)
        return NULL;

    mgr = (SLAB_MGR) mem;

    void * addr = (void *) mgr + sizeof(SLAB_MGR_TYPE);
    int i;
    for (i = 0 ; i < SLAB_LEVEL ; i++) {
        area = (SLAB_AREA) addr;
        area->size = size;

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

// system_lock needs to be held by the caller on entry.
static inline int enlarge_slab_mgr (SLAB_MGR mgr, int level)
{
    assert(level < SLAB_LEVEL);
    /* DEP 11/24/17: This strategy basically doubles a level's size 
     * every time it grows.  The assumption if we get this far is that
     * mgr->addr == mgr->top_addr */
    assert(mgr->addr[level] == mgr->addr_top[level]);

    size_t size = mgr->size[level];
    SLAB_AREA area;

    /* If there is a previously allocated area, just activate it. */
    area = listp_prev_entry(mgr->active_area[level], &mgr->area_list[level], __list);
    if (area) {
        __set_free_slab_area(area, mgr, level);
        return 0;
    }

    /* system_malloc() may be blocking, so we release the lock before
     * allocating more memory */
    system_unlock();

    /* If the allocation failed, always try smaller sizes */
    for (; size > 0; size >>= 1) {
        area = (SLAB_AREA) system_malloc(__MAX_MEM_SIZE(slab_levels[level], size));
        if (area)
            break;
    }

    if (!area) {
        system_lock();
        return -ENOMEM;
    }

    system_lock();

    area->size = size;
    INIT_LIST_HEAD(area, __list);

    /* There can be concurrent operations to extend the SLAB manager. In case
     * someone has already enlarged the space, we just add the new area to the
     * list for later use. */
    listp_add(area, &mgr->area_list[level], __list);
    if (mgr->size[level] == size) /* check if the size has changed */
        __set_free_slab_area(area, mgr, level);

    return 0;
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
    assert(mgr->addr[level] <= mgr->addr_top[level]);
    if (mgr->addr[level] == mgr->addr_top[level] &&
          listp_empty(&mgr->free_list[level])) {
        int ret = enlarge_slab_mgr(mgr, level);
        if (ret < 0) {
            system_unlock();
            return NULL;
        }
    }

    if (!listp_empty(&mgr->free_list[level])) {
        mobj = listp_first_entry(&mgr->free_list[level], SLAB_OBJ_TYPE, __list);
        listp_del(mobj, &mgr->free_list[level], __list);
    } else {
        mobj = (void *) mgr->addr[level];
        mgr->addr[level] += slab_levels[level] + SLAB_HDR_SIZE;
    }
    assert(mgr->addr[level] <= mgr->addr_top[level]);
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

// Returns user buffer size (i.e. excluding size of control structures).
static inline size_t slab_get_buf_size(SLAB_MGR mgr, const void * ptr)
{
    assert(ptr);

    unsigned char level = RAW_TO_LEVEL(ptr);

    if (level == (unsigned char) -1) {
        LARGE_MEM_OBJ mem = RAW_TO_OBJ(ptr, LARGE_MEM_OBJ_TYPE);
        return mem->size;
    }

    if (level >= SLAB_LEVEL) {
        pal_printf("Heap corruption detected: invalid heap level %u\n", level);
        __abort();
    }

#ifdef SLAB_CANARY
    const unsigned long * m = (const unsigned long *)(ptr + slab_levels[level]);
    assert((*m) == SLAB_CANARY_STRING);
#endif

    return slab_levels[level];
}

static inline void slab_free (SLAB_MGR mgr, void * obj)
{
    /* In a general purpose allocator, free of NULL is allowed (and is a 
     * nop). We might want to enforce stricter rules for our allocator if
     * we're sure that no clients rely on being able to free NULL. */
    if (!obj)
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
        pal_printf("Heap corruption detected: invalid heap level %d\n", level);
        __abort();
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
    if (!obj)
        return;

    unsigned char level = RAW_TO_LEVEL(obj);

    if (level < SLAB_LEVEL && level != (unsigned char) -1) {
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
