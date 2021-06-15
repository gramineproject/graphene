/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the implementation of `/sys/devices/system/{cpu,node}/` pseudo-filesystem and
 * its sub-directories.
 */

#include "shim_fs.h"
#include "shim_fs_pseudo.h"
#include "stat.h"

static int sys_resource(struct shim_dentry* parent, const char* name, readdir_callback_t callback,
                      void* arg) {
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
        unsigned int n;
        if (parse_uint(&name[prefix_len], &n) < 0)
            return -ENOENT;
        if (n >= (unsigned int)total)
            return -ENOENT;
        return n;
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

int sys_resource_find(struct shim_dentry* dent, const char* name) {
    struct shim_dentry* parent = dent->parent;
    while (parent) {
        const char* parent_name = qstrgetstr(&parent->name);
        if (strcmp(parent_name, name) == 0)
            return sys_resource(parent, qstrgetstr(&dent->name), /*callback=*/NULL, /*arg=*/NULL);

        dent = parent;
        parent = parent->parent;
    }
    return -ENOENT;
}

int sys_resource_match_name(struct shim_dentry* parent, const char* name) {
    int ret = sys_resource(parent, name, /*callback=*/NULL, /*arg=*/NULL);
    if (ret < 0)
        return ret;
    return 0;
}

int sys_resource_list_names(struct shim_dentry* parent, readdir_callback_t callback, void* arg) {
    return sys_resource(parent, /*name=*/NULL, callback, arg);
}

int sys_get_content(const char* str, char** content, size_t* size) {
    assert(str);
    char* _content = strdup(str);
    if (!_content)
        return -ENOMEM;
    *content = _content;
    *size = strlen(_content);
    return 0;
}


static void init_cpu_dir(struct pseudo2_ent* cpu) {
    pseudo_add_str(cpu, "online", &sys_cpu_general_get_content);
    pseudo_add_str(cpu, "possible", &sys_cpu_general_get_content);

    struct pseudo2_ent* cpuX = pseudo_add_dir(cpu, NULL);
    cpuX->match_name = &sys_resource_match_name;
    cpuX->list_names = &sys_resource_list_names;

    /* `cpu/cpuX/online` is not present for cpu0 */
    struct pseudo2_ent* online = pseudo_add_str(cpuX, NULL, &sys_cpu_get_content);
    online->match_name = &sys_cpu_online_match_name;
    online->list_names = &sys_cpu_online_list_names;

    struct pseudo2_ent* topology = pseudo_add_dir(cpuX, "topology");
    pseudo_add_str(topology, "core_id", &sys_cpu_get_content);
    pseudo_add_str(topology, "physical_package_id", &sys_cpu_get_content);
    pseudo_add_str(topology, "core_siblings", &sys_cpu_get_content);
    pseudo_add_str(topology, "thread_siblings", &sys_cpu_get_content);

    struct pseudo2_ent* cache = pseudo_add_dir(cpuX, "cache");
    struct pseudo2_ent* indexX = pseudo_add_dir(cache, NULL);
    indexX->match_name = &sys_resource_match_name;
    indexX->list_names = &sys_resource_list_names;

    pseudo_add_str(indexX, "shared_cpu_map", &sys_cache_get_content);
    pseudo_add_str(indexX, "level", &sys_cache_get_content);
    pseudo_add_str(indexX, "type", &sys_cache_get_content);
    pseudo_add_str(indexX, "size", &sys_cache_get_content);
    pseudo_add_str(indexX, "coherency_line_size", &sys_cache_get_content);
    pseudo_add_str(indexX, "physical_line_partition", &sys_cache_get_content);
}

static void init_node_dir(struct pseudo2_ent* node) {
    pseudo_add_str(node, "online", &sys_node_general_get_content);

    struct pseudo2_ent* nodeX = pseudo_add_dir(node, NULL);
    nodeX->match_name = &sys_resource_match_name;
    nodeX->list_names = &sys_resource_list_names;

    pseudo_add_str(nodeX, "cpumap", &sys_node_get_content);
    pseudo_add_str(nodeX, "distance", &sys_node_get_content);

    struct pseudo2_ent* hugepages = pseudo_add_dir(nodeX, "hugepages");
    struct pseudo2_ent* hugepages_2m = pseudo_add_dir(hugepages, "hugepages-2048kB");
    pseudo_add_str(hugepages_2m, "nr_hugepages", &sys_node_get_content);
    struct pseudo2_ent* hugepages_1g = pseudo_add_dir(hugepages, "hugepages-1048576kB");
    pseudo_add_str(hugepages_1g, "nr_hugepages", &sys_node_get_content);
}

int init_sysfs(void) {
    struct pseudo2_ent* root = pseudo_add_root_dir("sys");
    struct pseudo2_ent* devices = pseudo_add_dir(root, "devices");
    struct pseudo2_ent* system = pseudo_add_dir(devices, "system");

    struct pseudo2_ent* cpu = pseudo_add_dir(system, "cpu");
    init_cpu_dir(cpu);

    struct pseudo2_ent* node = pseudo_add_dir(system, "node");
    init_node_dir(node);

    return 0;
}
