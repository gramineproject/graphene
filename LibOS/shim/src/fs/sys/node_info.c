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
    const char* name = dent->name;
    const char* str;
    if (strcmp(name, "online") == 0) {
        str = g_pal_control->topo_info.online_nodes;
    } else {
        log_debug("unrecognized file: %s", name);
        return -ENOENT;
    }

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
    const char* str = NULL;
    if (strcmp(name, "cpumap" ) == 0) {
        str = numa_topology->cpumap;
    } else if (strcmp(name, "distance") == 0) {
        str = numa_topology->distance;
    } else if (strcmp(name, "nr_hugepages") == 0) {
        const char* parent_name = dent->parent->name;
        if (strcmp(parent_name, "hugepages-2048kB") == 0) {
            str = numa_topology->hugepages[HUGEPAGES_2M].nr_hugepages;
        } else if (strcmp(parent_name, "hugepages-1048576kB") == 0) {
            str = numa_topology->hugepages[HUGEPAGES_1G].nr_hugepages;
        }
    }
    if (!str) {
        log_debug("unrecognized file: %s", name);
        return -ENOENT;
    }

    return sys_load(str, out_data, out_size);
}
