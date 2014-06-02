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
 * memmgr.h
 *
 * This file contains implementation of fix-sized memory allocator.
 */

#ifndef MEMMGR_H
#define MEMMGR_H

#include "linux_list.h"
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

#ifndef OBJ_TYPE
#error "OBJ_TYPE not defined"
#endif

typedef struct mem_obj {
    union {
        struct list_head __list;
        OBJ_TYPE obj;
    };
} MEM_OBJ_TYPE, * MEM_OBJ;

typedef struct mem_area {
    struct list_head __list;
    uint64_t size;
    MEM_OBJ_TYPE objs[];
} MEM_AREA_TYPE, * MEM_AREA;

typedef struct mem_mgr {
    struct list_head area_list;
    struct list_head free_list;
    unsigned int size;
} MEM_MGR_TYPE, * MEM_MGR;

#define __SUM_OBJ_SIZE(size) (sizeof(MEM_OBJ_TYPE) * (size))
#define __MIN_MEM_SIZE() (sizeof(MEM_MGR_TYPE) + sizeof(MEM_AREA_TYPE))
#define __MAX_MEM_SIZE(size) (__MIN_MEM_SIZE() + __SUM_OBJ_SIZE(size))

#ifdef PAGE_SIZE
static inline int size_align_down(int size)
{
    size_t s = __MAX_MEM_SIZE(size) - sizeof(MEM_MGR_TYPE);
    size_t p = s - (s & ~(PAGE_SIZE - 1));
    size_t o = __SUM_OBJ_SIZE(1);
    return size - p / o - (p % o ? 1 : 0);
}

static inline int size_align_up(int size)
{
    size_t s = __MAX_MEM_SIZE(size) - sizeof(MEM_MGR_TYPE);
    size_t p = ((s + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)) - s;
    size_t o = __SUM_OBJ_SIZE(1);
    return size + p / o;
}

static inline int init_align_down(int size)
{
    size_t s = __MAX_MEM_SIZE(size);
    size_t p = s - (s & ~(PAGE_SIZE - 1));
    size_t o = __SUM_OBJ_SIZE(1);
    return size - p / o - (p % o ? 1 : 0);
}

static inline int init_align_up(int size)
{
    size_t s = __MAX_MEM_SIZE(size);
    size_t p = ((s + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)) - s;
    size_t o = __SUM_OBJ_SIZE(1);
    return size + p / o;
}
#endif

static inline void __set_free_mem_area (MEM_AREA area, MEM_MGR mgr, int size)
{
    int i;

    for (i = 0 ; i < size ; i++) {
        INIT_LIST_HEAD(&area->objs[i].__list);
        list_add_tail(&area->objs[i].__list, &mgr->free_list);
    }

    mgr->size += size;
}

static inline MEM_MGR create_mem_mgr (unsigned int size)
{
    unsigned long mem = (unsigned long) system_malloc(__MAX_MEM_SIZE(size));
    MEM_AREA area;
    MEM_MGR mgr;

    if (mem <= 0)
        return NULL;

    mgr = (MEM_MGR) mem;
    area = (MEM_AREA) (mem + sizeof(MEM_MGR_TYPE));
#if DEBUG_MEMMGR == 1
    area->size = size;

    INIT_LIST_HEAD(&area->__list);
    INIT_LIST_HEAD(&mgr->area_list);
    list_add(&area->__list, &mgr->area_list);
#endif

    INIT_LIST_HEAD(&mgr->free_list);
    mgr->size = 0;
    __set_free_mem_area(area, mgr, size);

    return mgr;
}

static inline MEM_MGR enlarge_mem_mgr (MEM_MGR mgr, unsigned int size)
{
    MEM_AREA area;

    area = (MEM_AREA) system_malloc(sizeof(MEM_AREA_TYPE) +
                                    __SUM_OBJ_SIZE(size));
    if (area <= 0)
        return NULL;

    system_lock();
#if DEBUG_MEMMGR == 1
    area->size = size;
    INIT_LIST_HEAD(&area->__list);
    list_add(&area->__list, &mgr->area_list);
#endif
    __set_free_mem_area(area, mgr, size);
    system_unlock();
    return mgr;
}

static inline void destroy_mem_mgr (MEM_MGR mgr)
{
    MEM_AREA tmp, n, first = NULL;

    first = tmp = list_first_entry(&mgr->area_list, MEM_AREA_TYPE, __list);

    if (!first)
        return;

    list_for_each_entry_safe_continue(tmp, n, &mgr->area_list, __list) {
        list_del(&tmp->__list);
        system_free(tmp, sizeof(MEM_AREA_TYPE) + __SUM_OBJ_SIZE(tmp->size));
    }

    system_free(mgr, __MAX_MEM_SIZE(first->size));
}

static inline OBJ_TYPE * get_mem_obj_from_mgr (MEM_MGR mgr)
{
    MEM_OBJ mobj;

    system_lock();
    if (list_empty(&mgr->free_list)) {
        system_unlock();
        return NULL;
    }

    mobj = list_first_entry(&mgr->free_list, MEM_OBJ_TYPE, __list);
    list_del(&mobj->__list);
    system_unlock();
    return &mobj->obj;
}

static inline OBJ_TYPE * get_mem_obj_from_mgr_enlarge (MEM_MGR mgr,
                                                       unsigned int size)
{
    MEM_OBJ mobj;

    system_lock();
    if (list_empty(&mgr->free_list)) {
        system_unlock();

        if (!size)
            return NULL;

        MEM_AREA area;
        area = (MEM_AREA) system_malloc(sizeof(MEM_AREA_TYPE) +
                                        __SUM_OBJ_SIZE(size));
        if (!area)
            return NULL;

        system_lock();
#if DEBUG_MEMMGR == 1
        area->size = size;
        INIT_LIST_HEAD(&area->__list);
        list_add(&area->__list, &mgr->area_list);
#endif
        __set_free_mem_area(area, mgr, size);
    }

    mobj = list_first_entry(&mgr->free_list, MEM_OBJ_TYPE, __list);
    list_del_init(&mobj->__list);
    check_list_head(&mgr->free_list);
    system_unlock();
    return &mobj->obj;
}

static inline void free_mem_obj_to_mgr (MEM_MGR mgr, OBJ_TYPE * obj)
{
    MEM_OBJ mobj = container_of(obj, MEM_OBJ_TYPE, obj);

    system_lock();

#if DEBUG_MEMMGR == 1
    MEM_AREA area, found = NULL;
    list_for_each_entry(area, &mgr->area_list, __list)
        if (mobj >= area->objs && mobj < area->objs + area->size) {
            found = area;
            break;
        }
#else
    int found = 1;
#endif /* DEBUG_MEMMGR != 1 */

    if (found) {
        INIT_LIST_HEAD(&mobj->__list);
        list_add_tail(&mobj->__list, &mgr->free_list);
        check_list_head(&mgr->free_list);
    }

    system_unlock();
}

#endif /* MEMMGR_H */
