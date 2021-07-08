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
    const char* name = dent->name;
    const char* str;

    if (strcmp(name, "online") == 0) {
        str = g_pal_control->topo_info.online_logical_cores;
    } else if (strcmp(name, "possible") == 0) {
        str = g_pal_control->topo_info.possible_logical_cores;
    } else {
        log_debug("unrecognized file: %s", name);
        return -ENOENT;
    }

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
    const char* str;
    if (strcmp(name, "online") == 0) {
        /* `cpu/cpuX/online` is not present for cpu0 */
        if (cpu_num == 0)
            return -ENOENT;
        str = core_topology->is_logical_core_online;
    } else if (strcmp(name, "core_id") == 0) {
        str = core_topology->core_id;
    } else if (strcmp(name, "physical_package_id") == 0) {
        char buf[12];
        snprintf(buf, sizeof(buf), "%d\n", g_pal_control->cpu_info.cpu_socket[cpu_num]);
        str = buf;
    } else if (strcmp(name, "core_siblings") == 0) {
        str = core_topology->core_siblings;
    } else if (strcmp(name, "thread_siblings") == 0) {
        str = core_topology->thread_siblings;
    } else {
        log_debug("unrecognized file: %s", name);
        return -ENOENT;
    }

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
