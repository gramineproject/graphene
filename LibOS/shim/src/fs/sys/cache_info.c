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
    char str[PAL_SYSFS_MAP_FILESZ] = {'\0'};
    if (strcmp(name, "shared_cpu_map") == 0) {
        ret = sys_convert_range_info_bitmap_str(cache->shared_cpu_map, str, PAL_SYSFS_MAP_FILESZ);
    } else if (strcmp(name, "level") == 0) {
        ret = sys_convert_int_to_str(cache->level, DEFAULT_SZ, str, PAL_SYSFS_MAP_FILESZ);
    } else if (strcmp(name, "type") == 0) {
        switch (cache->type) {
            case DATA:
                ret = snprintf(str, PAL_SYSFS_MAP_FILESZ, "%s", "Data\n");
                break;
            case INSTRUCTION:
                ret = snprintf(str, PAL_SYSFS_MAP_FILESZ, "%s", "Instruction\n");
                break;
            case UNIFIED:
                ret = snprintf(str, PAL_SYSFS_MAP_FILESZ, "%s", "Unified\n");
                break;
            default:
                ret = -ENOENT;
        }
    } else if (strcmp(name, "size") == 0) {
        ret = sys_convert_int_to_str(cache->size, cache->size_qualifier, str, PAL_SYSFS_MAP_FILESZ);
    } else if (strcmp(name, "coherency_line_size") == 0) {
        ret = sys_convert_int_to_str(cache->coherency_line_size, DEFAULT_SZ, str,
                                     PAL_SYSFS_MAP_FILESZ);
    } else if (strcmp(name, "number_of_sets") == 0) {
        ret = sys_convert_int_to_str(cache->number_of_sets, DEFAULT_SZ, str, PAL_SYSFS_MAP_FILESZ);
    } else if (strcmp(name, "physical_line_partition") == 0) {
        ret = sys_convert_int_to_str(cache->physical_line_partition, DEFAULT_SZ, str,
                                     PAL_SYSFS_MAP_FILESZ);
    } else {
        log_debug("unrecognized file: %s", name);
        ret = -ENOENT;
    }

    if (ret < 0)
        return ret;
    return sys_load(str, out_data, out_size);
}
