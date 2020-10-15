/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains functions to allocate / free a fixed-size string object.
 */

#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_utils.h"

static struct shim_lock str_mgr_lock;

#define SYSTEM_LOCK()   lock(&str_mgr_lock)
#define SYSTEM_UNLOCK() unlock(&str_mgr_lock)
#define SYSTEM_LOCKED() locked(&str_mgr_lock)

#define STR_MGR_ALLOC 32

#define OBJ_TYPE struct shim_str
#include "memmgr.h"

static MEM_MGR str_mgr = NULL;

int init_str_mgr(void) {
    if (!create_lock(&str_mgr_lock)) {
        return -ENOMEM;
    }
    str_mgr = create_mem_mgr(init_align_up(STR_MGR_ALLOC));
    if (!str_mgr) {
        destroy_lock(&str_mgr_lock);
        return -ENOMEM;
    }
    return 0;
}

struct shim_str* get_str_obj(void) {
    return get_mem_obj_from_mgr_enlarge(str_mgr, size_align_up(STR_MGR_ALLOC));
}

int free_str_obj(struct shim_str* str) {
    if (str == NULL)
        return 0;

    free_mem_obj_to_mgr(str_mgr, str);
    return 0;
}
