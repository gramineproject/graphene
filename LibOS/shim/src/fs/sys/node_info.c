/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the implementation of `/sys/devices/system/node` and its sub-directories.
 */

#include "api.h"
#include "shim_fs.h"
#include "shim_fs_pseudo.h"

int sys_node_general_load(struct shim_dentry* dent, char** out_data, size_t* out_size) {
    int ret;

    const char* name = dent->name;
    char str[PAL_SYSFS_BUF_FILESZ] = {'\0'};

    if (strcmp(name, "online") != 0) {
        log_debug("unrecognized file: %s", name);
        return -ENOENT;
    }

    ret = sys_convert_ranges_to_str(&g_pal_control->topo_info.nodes, str, sizeof(str), ",");
    if (ret < 0)
        return ret;

    return sys_load(str, out_data, out_size);
}

int sys_node_load(struct shim_dentry* dent, char** out_data, size_t* out_size) {
    int ret;
    unsigned int node_num;
    ret = sys_resource_find(dent, "node", &node_num);
    if (ret < 0)
        return ret;

    const char* name = dent->name;
    PAL_NUMA_TOPO_INFO* numa_topology = &g_pal_control->topo_info.numa_topology[node_num];
    char str[PAL_SYSFS_MAP_FILESZ] = {'\0'};
    if (strcmp(name, "cpumap" ) == 0) {
        ret = sys_convert_ranges_to_cpu_bitmap_str(&numa_topology->cpumap, str, sizeof(str));
    } else if (strcmp(name, "distance") == 0) {
        ret = sys_convert_ranges_to_str(&numa_topology->distance, str, sizeof(str), " ");
    } else if (strcmp(name, "nr_hugepages") == 0) {
        const char* parent_name = dent->parent->name;
        if (strcmp(parent_name, "hugepages-2048kB") == 0) {
            ret = sys_convert_int_to_sizestr(numa_topology->nr_hugepages[HUGEPAGES_2M],
                                             MULTIPLIER_NONE, str, sizeof(str));
        } else if (strcmp(parent_name, "hugepages-1048576kB") == 0) {
            ret = sys_convert_int_to_sizestr(numa_topology->nr_hugepages[HUGEPAGES_1G],
                                             MULTIPLIER_NONE, str, sizeof(str));
        } else {
            log_debug("unrecognized hugepage file: %s", parent_name);
            ret = -ENOENT;
        }
    } else {
        log_debug("unrecognized file: %s", name);
        ret = -ENOENT;
    }

    if (ret < 0)
        return ret;
    return sys_load(str, out_data, out_size);
}
