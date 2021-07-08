/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the implementation of `/sys/devices/system/cpu/cpuX/cache` and its
 * sub-directories.
 */

#include "api.h"
#include "shim_fs.h"
#include "shim_fs_pseudo.h"

int sys_cache_load(struct shim_dentry* dent, char** out_data, size_t* out_size) {
    int ret;

    unsigned int cache_num;
    ret = sys_resource_find(dent, "cache", &cache_num);
    if (ret < 0)
        return ret;

    unsigned int cpu_num;
    ret = sys_resource_find(dent, "cpu", &cpu_num);
    if (ret < 0)
        return ret;

    const char* name = dent->name;
    PAL_CORE_CACHE_INFO* cache = &g_pal_control->topo_info.core_topology[cpu_num].cache[cache_num];
    const char* str;
    if (strcmp(name, "shared_cpu_map") == 0) {
        str = cache->shared_cpu_map;
    } else if (strcmp(name, "level") == 0) {
        str = cache->level;
    } else if (strcmp(name, "type") == 0) {
        str = cache->type;
    } else if (strcmp(name, "size") == 0) {
        str = cache->size;
    } else if (strcmp(name, "coherency_line_size") == 0) {
        str = cache->coherency_line_size;
    } else if (strcmp(name, "number_of_sets") == 0) {
        str = cache->number_of_sets;
    } else if (strcmp(name, "physical_line_partition") == 0) {
        str = cache->physical_line_partition;
    } else {
        log_debug("unrecognized file: %s", name);
        return -ENOENT;
    }

    return sys_load(str, out_data, out_size);
}
