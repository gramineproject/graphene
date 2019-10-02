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
 * memmgr.h
 *
 * This file contains implementation of fixed-size memory allocator.
 */

#ifndef MEMMGR_H
#define MEMMGR_H

#include <sys/mman.h>

#include "api.h"
#include "assert.h"
#include "list.h"

#ifndef OBJ_TYPE
#error "OBJ_TYPE not defined"
#endif

#ifndef system_malloc
#error "macro \"void * system_malloc (size_t size)\" not declared"
#endif
#ifndef system_free
#error "macro \"void * system_free (void * ptr, size_t size)\" not declared"
#endif
#ifndef SYSTEM_LOCK
#define SYSTEM_LOCK() ({})
#endif
#ifndef SYSTEM_UNLOCK
#define SYSTEM_UNLOCK() ({})
#endif
#ifndef SYSTEM_LOCKED
#define SYSTEM_LOCKED() true
#endif

DEFINE_LIST(mem_obj);
typedef struct mem_obj {
    union {
        LIST_TYPE(mem_obj) __list;
        OBJ_TYPE obj;
    };
} MEM_OBJ_TYPE, *MEM_OBJ;

DEFINE_LIST(mem_area);
typedef struct mem_area {
    LIST_TYPE(mem_area) __list;
    unsigned int size;
    MEM_OBJ_TYPE objs[];
} MEM_AREA_TYPE, *MEM_AREA;

DEFINE_LISTP(mem_area);
DEFINE_LISTP(mem_obj);
typedef struct mem_mgr {
    LISTP_TYPE(mem_area) area_list;
    LISTP_TYPE(mem_obj) free_list;
    size_t size;
    MEM_OBJ_TYPE* obj;
    MEM_OBJ_TYPE* obj_top;
    MEM_AREA active_area;
} MEM_MGR_TYPE, *MEM_MGR;

#define __SUM_OBJ_SIZE(size) (sizeof(MEM_OBJ_TYPE) * (size))
#define __MIN_MEM_SIZE()     (sizeof(MEM_MGR_TYPE) + sizeof(MEM_AREA_TYPE))
#define __MAX_MEM_SIZE(size) (__MIN_MEM_SIZE() + __SUM_OBJ_SIZE(size))

#ifdef ALLOC_ALIGNMENT
static inline int size_align_down(int size) {
    assert(IS_POWER_OF_2(ALLOC_ALIGNMENT));
    int s = __MAX_MEM_SIZE(size) - sizeof(MEM_MGR_TYPE);
    int p = s - ALIGN_DOWN_POW2(s, ALLOC_ALIGNMENT);
    int o = __SUM_OBJ_SIZE(1);
    return size - p / o - (p % o ? 1 : 0);
}

static inline int size_align_up(int size) {
    assert(IS_POWER_OF_2(ALLOC_ALIGNMENT));
    int s = __MAX_MEM_SIZE(size) - sizeof(MEM_MGR_TYPE);
    int p = ALIGN_UP_POW2(s, ALLOC_ALIGNMENT) - s;
    int o = __SUM_OBJ_SIZE(1);
    return size + p / o;
}

static inline int init_align_down(int size) {
    assert(IS_POWER_OF_2(ALLOC_ALIGNMENT));
    int s = __MAX_MEM_SIZE(size);
    int p = s - ALIGN_DOWN_POW2(s, ALLOC_ALIGNMENT);
    int o = __SUM_OBJ_SIZE(1);
    return size - p / o - (p % o ? 1 : 0);
}

static inline int init_align_up(int size) {
    assert(IS_POWER_OF_2(ALLOC_ALIGNMENT));
    int s = __MAX_MEM_SIZE(size);
    int p = ALIGN_UP_POW2(s, ALLOC_ALIGNMENT) - s;
    int o = __SUM_OBJ_SIZE(1);
    return size + p / o;
}
#endif

static inline void __set_free_mem_area(MEM_AREA area, MEM_MGR mgr) {
    assert(SYSTEM_LOCKED());

    mgr->size += area->size;
    mgr->obj         = area->objs;
    mgr->obj_top     = area->objs + area->size;
    mgr->active_area = area;
}

static inline MEM_MGR create_mem_mgr(unsigned int size) {
    void* mem = system_malloc(__MAX_MEM_SIZE(size));
    MEM_AREA area;
    MEM_MGR mgr;

    if (!mem)
        return NULL;

    mgr        = (MEM_MGR)mem;
    mgr->size  = 0;
    area       = (MEM_AREA)(mem + sizeof(MEM_MGR_TYPE));
    area->size = size;

    INIT_LIST_HEAD(area, __list);
    INIT_LISTP(&mgr->area_list);
    LISTP_ADD(area, &mgr->area_list, __list);

    INIT_LISTP(&mgr->free_list);
    __set_free_mem_area(area, mgr);

    return mgr;
}

static inline MEM_MGR enlarge_mem_mgr(MEM_MGR mgr, unsigned int size) {
    MEM_AREA area;

    area = (MEM_AREA)system_malloc(sizeof(MEM_AREA_TYPE) + __SUM_OBJ_SIZE(size));
    if (!area)
        return NULL;

    SYSTEM_LOCK();
    area->size = size;
    INIT_LIST_HEAD(area, __list);
    LISTP_ADD(area, &mgr->area_list, __list);
    __set_free_mem_area(area, mgr);
    SYSTEM_UNLOCK();
    return mgr;
}

static inline void destroy_mem_mgr(MEM_MGR mgr) {
    MEM_AREA tmp, n, first = NULL;

    first = tmp = LISTP_FIRST_ENTRY(&mgr->area_list, MEM_AREA_TYPE, __list);

    if (!first)
        goto free_mgr;

    LISTP_FOR_EACH_ENTRY_SAFE_CONTINUE(tmp, n, &mgr->area_list, __list) {
        LISTP_DEL(tmp, &mgr->area_list, __list);
        system_free(tmp, sizeof(MEM_AREA_TYPE) + __SUM_OBJ_SIZE(tmp->size));
    }

free_mgr:
    system_free(mgr, __MAX_MEM_SIZE(first->size));
}

static inline OBJ_TYPE* get_mem_obj_from_mgr(MEM_MGR mgr) {
    MEM_OBJ mobj;

    SYSTEM_LOCK();
    if (mgr->obj == mgr->obj_top && LISTP_EMPTY(&mgr->free_list)) {
        SYSTEM_UNLOCK();
        return NULL;
    }

    if (!LISTP_EMPTY(&mgr->free_list)) {
        mobj = LISTP_FIRST_ENTRY(&mgr->free_list, MEM_OBJ_TYPE, __list);
        LISTP_DEL_INIT(mobj, &mgr->free_list, __list);
        CHECK_LIST_HEAD(MEM_OBJ, &mgr->free_list, __list);
    } else {
        mobj = mgr->obj++;
    }
    SYSTEM_UNLOCK();
    return &mobj->obj;
}

static inline OBJ_TYPE* get_mem_obj_from_mgr_enlarge(MEM_MGR mgr, unsigned int size) {
    MEM_OBJ mobj;

    SYSTEM_LOCK();
    if (mgr->obj == mgr->obj_top && LISTP_EMPTY(&mgr->free_list)) {
        size_t mgr_size = mgr->size;
        MEM_AREA area;

        /* If there is a previously allocated area, just activate it. */
        area = LISTP_PREV_ENTRY(mgr->active_area, &mgr->area_list, __list);
        if (area) {
            __set_free_mem_area(area, mgr);
            goto alloc;
        }

        SYSTEM_UNLOCK();

        if (!size)
            return NULL;

        /* There can be concurrent attempt to try to enlarge the
           allocator, but we prevent deadlocks or crashes. */
        area = (MEM_AREA)system_malloc(sizeof(MEM_AREA_TYPE) + __SUM_OBJ_SIZE(size));
        if (!area)
            return NULL;

        SYSTEM_LOCK();
        area->size = size;
        INIT_LIST_HEAD(area, __list);

        /* There can be concurrent operations to extend the manager. In case
         * someone has already enlarged the space, we just add the new area to
         * the list for later use. */
        LISTP_ADD(area, &mgr->area_list, __list);
        if (mgr_size == mgr->size) /* check if the size has changed */
            __set_free_mem_area(area, mgr);
    }

alloc:
    if (!LISTP_EMPTY(&mgr->free_list)) {
        mobj = LISTP_FIRST_ENTRY(&mgr->free_list, MEM_OBJ_TYPE, __list);
        LISTP_DEL_INIT(mobj, &mgr->free_list, __list);
        CHECK_LIST_HEAD(MEM_OBJ, &mgr->free_list, __list);
    } else {
        mobj = mgr->obj++;
    }
    assert(mgr->obj <= mgr->obj_top);
    SYSTEM_UNLOCK();
    return &mobj->obj;
}

static inline void free_mem_obj_to_mgr(MEM_MGR mgr, OBJ_TYPE* obj) {
    MEM_OBJ mobj = container_of(obj, MEM_OBJ_TYPE, obj);

    SYSTEM_LOCK();
    MEM_AREA area, found = NULL;
    LISTP_FOR_EACH_ENTRY(area, &mgr->area_list, __list) {
        if (mobj >= area->objs && mobj < area->objs + area->size) {
            found = area;
            break;
        }
    }

    if (found) {
        INIT_LIST_HEAD(mobj, __list);
        LISTP_ADD_TAIL(mobj, &mgr->free_list, __list);
        CHECK_LIST_HEAD(MEM_OBJ, &mgr->free_list, __list);
    }

    SYSTEM_UNLOCK();
}

#endif /* MEMMGR_H */
