/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the implementation of `/sys/devices/system/cpu` and its sub-directories
 * (except for `cache`, which is implemented in cache_info.c).
 */

#include "api.h"
#include "shim_fs.h"
#include "shim_fs_pseudo.h"

int sys_cpu_general_load(struct shim_dentry* dent, char** out_data, size_t* out_size) {
    int ret;
    const char* name = dent->name;
    char str[PAL_SYSFS_BUF_FILESZ] = {'\0'};

    if (strcmp(name, "online") == 0) {
        ret = sys_convert_ranges_to_str(&g_pal_control->topo_info.online_logical_cores, str,
                                        sizeof(str), ",");
    } else if (strcmp(name, "possible") == 0) {
        ret = sys_convert_ranges_to_str(&g_pal_control->topo_info.possible_logical_cores, str,
                                        sizeof(str), ",");
    } else {
        log_debug("unrecognized file: %s", name);
        ret = -ENOENT;
    }

    if (ret < 0)
        return ret;
    return sys_load(str, out_data, out_size);
}

int sys_cpu_load(struct shim_dentry* dent, char** out_data, size_t* out_size) {
    int ret;
    unsigned int cpu_num;
    ret = sys_resource_find(dent, "cpu", &cpu_num);
    if (ret < 0)
        return ret;

    const char* name = dent->name;
    PAL_CORE_TOPO_INFO* core_topology = &g_pal_control->topo_info.core_topology[cpu_num];
    char str[PAL_SYSFS_MAP_FILESZ] = {'\0'};
    if (strcmp(name, "online") == 0) {
        /* `cpu/cpuX/online` is not present for cpu0 */
        if (cpu_num == 0)
            return -ENOENT;
        ret = sys_convert_int_to_sizestr(core_topology->is_logical_core_online, MULTIPLIER_NONE,
                                         str, sizeof(str));
    } else if (strcmp(name, "core_id") == 0) {
        ret = sys_convert_int_to_sizestr(core_topology->core_id, MULTIPLIER_NONE, str, sizeof(str));
    } else if (strcmp(name, "physical_package_id") == 0) {
        ret = sys_convert_int_to_sizestr(core_topology->cpu_socket, MULTIPLIER_NONE, str,
                                         sizeof(str));
    } else if (strcmp(name, "core_siblings") == 0) {
        ret = sys_convert_ranges_to_cpu_bitmap_str(&core_topology->core_siblings, str, sizeof(str));
    } else if (strcmp(name, "thread_siblings") == 0) {
        ret = sys_convert_ranges_to_cpu_bitmap_str(&core_topology->thread_siblings, str,
                                                   sizeof(str));
    } else {
        log_debug("unrecognized file: %s", name);
        ret = -ENOENT;
    }

    if (ret < 0)
        return ret;
    return sys_load(str, out_data, out_size);
}

bool sys_cpu_online_name_exists(struct shim_dentry* parent, const char* name) {
    if (strcmp(name, "online") != 0)
        return false;

    int ret;
    unsigned int cpu_num;
    ret = sys_resource_find(parent, "cpu", &cpu_num);
    if (ret < 0)
        return false;

    return cpu_num != 0;
}

int sys_cpu_online_list_names(struct shim_dentry* parent, readdir_callback_t callback, void* arg) {
    int ret;
    unsigned int cpu_num;
    ret = sys_resource_find(parent, "cpu", &cpu_num);
    if (ret < 0)
        return ret;

    if (cpu_num != 0) {
        ret = callback("online", arg);
        if (ret < 0)
            return ret;
    }
    return 0;
}
