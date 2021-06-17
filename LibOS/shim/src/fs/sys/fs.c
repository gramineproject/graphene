/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the implementation of `/sys/devices/system/{cpu,node}/` pseudo-filesystem and
 * its sub-directories.
 */

#include <limits.h>

#include "shim_fs.h"
#include "shim_fs_pseudo.h"
#include "stat.h"

static int sys_resource(struct shim_dentry* parent, const char* name, unsigned int* num,
                        readdir_callback_t callback, void* arg) {
    const char* parent_name = qstrgetstr(&parent->name);
    int total;
    const char* prefix;

    if (strcmp(parent_name, "node") == 0) {
        total = g_pal_control->topo_info.num_online_nodes;
        prefix = "node";
    } else if (strcmp(parent_name, "cpu") == 0) {
        total = g_pal_control->cpu_info.online_logical_cores;
        prefix = "cpu";
    } else if (strcmp(parent_name, "cache") == 0) {
        total = g_pal_control->topo_info.num_cache_index;
        prefix = "index";
    } else {
        log_debug("unrecognized resource: %s\n", parent_name);
        return -ENOENT;
    }

    assert(total >= 0);

    if (name) {
        if (!strstartswith(name, prefix))
            return -ENOENT;
        size_t prefix_len = strlen(prefix);
        unsigned long n;
        const char* end;
        if (str_to_ulong(&name[prefix_len], 10, &n, &end) < 0 || *end != '\0' || n > UINT_MAX)
            return -ENOENT;
        if (n >= (unsigned int)total)
            return -ENOENT;

        if (num)
            *num = n;
        return 0;
    } else {
        for (unsigned int i = 0; i < (unsigned int)total; i++) {
            char ent_name[42];
            snprintf(ent_name, sizeof(ent_name), "%s%u", prefix, i);
            int ret = callback(ent_name, arg);
            if (ret < 0)
                return ret;
        }
        return 0;
    }
}

int sys_resource_find(struct shim_dentry* dent, const char* name, unsigned int* num) {
    struct shim_dentry* parent = dent->parent;
    while (parent) {
        const char* parent_name = qstrgetstr(&parent->name);
        if (strcmp(parent_name, name) == 0) {
            return sys_resource(parent, qstrgetstr(&dent->name), num, /*callback=*/NULL,
                                /*arg=*/NULL);
        }

        dent = parent;
        parent = parent->parent;
    }
    return -ENOENT;
}

int sys_resource_match_name(struct shim_dentry* parent, const char* name) {
    return sys_resource(parent, name, /*num=*/NULL, /*callback=*/NULL, /*arg=*/NULL);
}

int sys_resource_list_names(struct shim_dentry* parent, readdir_callback_t callback, void* arg) {
    return sys_resource(parent, /*name=*/NULL, /*num=*/NULL, callback, arg);
}

int sys_load(const char* str, char** data, size_t* size) {
    assert(str);

    /* Use the string (without null terminator) as file data */
    size_t _size = strlen(str);
    char* _data = malloc(_size);
    if (!_data)
        return -ENOMEM;
    memcpy(_data, str, _size);
    *data = _data;
    *size = _size;
    return 0;
}

static void init_cpu_dir(struct pseudo_node* cpu) {
    pseudo_add_str(cpu, "online", &sys_cpu_general_load);
    pseudo_add_str(cpu, "possible", &sys_cpu_general_load);

    struct pseudo_node* cpuX = pseudo_add_dir(cpu, NULL);
    cpuX->match_name = &sys_resource_match_name;
    cpuX->list_names = &sys_resource_list_names;

    /* Create a node for `cpu/cpuX/online`. We provide name callbacks instead of a hardcoded name,
     * because we want the file to exist for all CPUs *except* `cpu0`. */
    struct pseudo_node* online = pseudo_add_str(cpuX, NULL, &sys_cpu_load);
    online->match_name = &sys_cpu_online_match_name;
    online->list_names = &sys_cpu_online_list_names;

    struct pseudo_node* topology = pseudo_add_dir(cpuX, "topology");
    pseudo_add_str(topology, "core_id", &sys_cpu_load);
    pseudo_add_str(topology, "physical_package_id", &sys_cpu_load);
    pseudo_add_str(topology, "core_siblings", &sys_cpu_load);
    pseudo_add_str(topology, "thread_siblings", &sys_cpu_load);

    struct pseudo_node* cache = pseudo_add_dir(cpuX, "cache");
    struct pseudo_node* indexX = pseudo_add_dir(cache, NULL);
    indexX->match_name = &sys_resource_match_name;
    indexX->list_names = &sys_resource_list_names;

    pseudo_add_str(indexX, "shared_cpu_map", &sys_cache_load);
    pseudo_add_str(indexX, "level", &sys_cache_load);
    pseudo_add_str(indexX, "type", &sys_cache_load);
    pseudo_add_str(indexX, "size", &sys_cache_load);
    pseudo_add_str(indexX, "coherency_line_size", &sys_cache_load);
    pseudo_add_str(indexX, "physical_line_partition", &sys_cache_load);
}

static void init_node_dir(struct pseudo_node* node) {
    pseudo_add_str(node, "online", &sys_node_general_load);

    struct pseudo_node* nodeX = pseudo_add_dir(node, NULL);
    nodeX->match_name = &sys_resource_match_name;
    nodeX->list_names = &sys_resource_list_names;

    pseudo_add_str(nodeX, "cpumap", &sys_node_load);
    pseudo_add_str(nodeX, "distance", &sys_node_load);

    struct pseudo_node* hugepages = pseudo_add_dir(nodeX, "hugepages");
    struct pseudo_node* hugepages_2m = pseudo_add_dir(hugepages, "hugepages-2048kB");
    pseudo_add_str(hugepages_2m, "nr_hugepages", &sys_node_load);
    struct pseudo_node* hugepages_1g = pseudo_add_dir(hugepages, "hugepages-1048576kB");
    pseudo_add_str(hugepages_1g, "nr_hugepages", &sys_node_load);
}

int init_sysfs(void) {
    struct pseudo_node* root = pseudo_add_root_dir("sys");
    struct pseudo_node* devices = pseudo_add_dir(root, "devices");
    struct pseudo_node* system = pseudo_add_dir(devices, "system");

    struct pseudo_node* cpu = pseudo_add_dir(system, "cpu");
    init_cpu_dir(cpu);

    struct pseudo_node* node = pseudo_add_dir(system, "node");
    init_node_dir(node);

    return 0;
}
