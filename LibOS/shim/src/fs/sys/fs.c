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

int sys_convert_int_to_str(uint64_t val, uint64_t size_mult, char* str, int max_len) {
    int ret = 0;
    switch (size_mult) {
        case MULTIPLIER_KB:
            ret = snprintf(str, max_len, "%luK", val);
            break;
        case MULTIPLIER_MB:
            ret = snprintf(str, max_len, "%luM", val);
            break;
        case MULTIPLIER_GB:
            ret = snprintf(str, max_len, "%luG", val);
            break;
        default:
            ret = snprintf(str, max_len, "%lu", val);
            break;
    }
    return ret;
}

int sys_convert_range_to_str(const PAL_RES_RANGE_INFO* res_range_info, char* str, int max_len,
                             const char* sep) {
    if (res_range_info->range_count > INT64_MAX)
        return -EINVAL;

    int64_t range_cnt = (int64_t)res_range_info->range_count;
    int offset = 0;
    for (int64_t i = 0; i < range_cnt; i++) {
        if (max_len - offset < 0)
            return -ENOMEM;

        int ret;
        char end_str[PAL_SYSFS_BUF_FILESZ] = {'\0'};
        if (res_range_info->ranges[i].end == UINT64_MAX) {
            ret = snprintf(end_str, sizeof(end_str), "%s", "");
        } else {
            ret = snprintf(end_str, sizeof(end_str), "-%lu", res_range_info->ranges[i].end);
        }

        if (ret < 0)
            return ret;

        ret = snprintf(str + offset, max_len - offset, "%lu%s%s", res_range_info->ranges[i].start,
                       end_str, (i + 1 == range_cnt) ? "\0" : sep);
        if (ret < 0)
            return ret;
        offset += ret;
    }
    return 0;
}

int sys_convert_range_to_cpu_bitmap_str(const PAL_RES_RANGE_INFO* res_range_info, char* str,
                                        int max_len) {
    if (g_pal_control->topo_info.possible_logical_cores.resource_count > INT64_MAX)
        return -1;
    int ret = 0;

    /* Extract cpumask from the ranges */
    int64_t possible_cores =  g_pal_control->topo_info.possible_logical_cores.resource_count;
    int64_t num_cpumask = BITS_TO_INTS(possible_cores);
    unsigned int* bitmap = (unsigned int*)calloc(num_cpumask, sizeof(unsigned int));
    if (!bitmap)
        return -ENOMEM;

    if (res_range_info->range_count > INT64_MAX)
        return -EINVAL;

    for (int64_t i = 0; i < (int64_t)res_range_info->range_count; i++) {
        uint64_t start = res_range_info->ranges[i].start;
        uint64_t end = res_range_info->ranges[i].end;
        if (end == UINT64_MAX)
            end = start;
        if (start > INT64_MAX || end > INT64_MAX)
            return -EINVAL;
        for (int64_t j = (int64_t)start; j <= (int64_t)end; j++) {
            int64_t index = j / (sizeof(int) * BITS_IN_BYTE);
            if (index >= num_cpumask) {
                ret = -EINVAL;
                goto out;
            }
            bitmap[index] |= 1U << (j % (sizeof(int) * BITS_IN_BYTE));
        }
    }

    /* Convert cpumask to strings */
    int offset = 0;
    for (int64_t j = num_cpumask - 1; j >= 0; j-- ) {
        if (max_len - offset < 0) {
            ret = -ENOMEM;
            goto out;
        }
        int ret = snprintf(str + offset, max_len - offset, "%x%x%x%x%x%x%x%x%s",
                           (bitmap[j] & 0xf0000000) >> 28, (bitmap[j] & 0xf000000) >> 24,
                           (bitmap[j] & 0xf00000) >> 20, (bitmap[j] & 0xf0000) >> 16,
                           (bitmap[j] & 0xf000) >> 12, (bitmap[j] & 0xf00) >> 8,
                           (bitmap[j] & 0xf0) >> 4, (bitmap[j] & 0xf), (j == 0) ? "\0" : ",");
        if (ret < 0)
            goto out;
        offset += ret;
    }
    ret = 0;

out:
    free(bitmap);
    return ret;
}

static int sys_resource(struct shim_dentry* parent, const char* name, unsigned int* out_num,
                        readdir_callback_t callback, void* arg) {
    const char* parent_name = parent->name;
    PAL_NUM pal_total;
    unsigned int total;
    const char* prefix;

    if (strcmp(parent_name, "node") == 0) {
        pal_total = g_pal_control->topo_info.nodes.resource_count;
        prefix = "node";
    } else if (strcmp(parent_name, "cpu") == 0) {
        pal_total = g_pal_control->topo_info.online_logical_cores.resource_count;
        prefix = "cpu";
    } else if (strcmp(parent_name, "cache") == 0) {
        pal_total = g_pal_control->topo_info.num_cache_index;
        prefix = "index";
    } else {
        log_debug("unrecognized resource: %s", parent_name);
        return -ENOENT;
    }

    assert(pal_total <= UINT_MAX);
    total = pal_total;

    if (name) {
        if (total == 0)
            return -ENOENT;

        if (!strstartswith(name, prefix))
            return -ENOENT;
        size_t prefix_len = strlen(prefix);
        unsigned long n;
        if (pseudo_parse_ulong(&name[prefix_len], total - 1, &n) < 0)
            return -ENOENT;

        if (out_num)
            *out_num = n;
        return 0;
    } else {
        for (unsigned int i = 0; i < total; i++) {
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
        if (strcmp(parent->name, name) == 0) {
            return sys_resource(parent, dent->name, num, /*callback=*/NULL, /*arg=*/NULL);
        }

        dent = parent;
        parent = parent->parent;
    }
    return -ENOENT;
}

bool sys_resource_name_exists(struct shim_dentry* parent, const char* name) {
    int ret = sys_resource(parent, name, /*num=*/NULL, /*callback=*/NULL, /*arg=*/NULL);
    return ret == 0;
}

int sys_resource_list_names(struct shim_dentry* parent, readdir_callback_t callback, void* arg) {
    return sys_resource(parent, /*name=*/NULL, /*num=*/NULL, callback, arg);
}

int sys_load(const char* str, char** out_data, size_t* out_size) {
    assert(str);

    /* Use the string (without null terminator) as file data */
    size_t size = strlen(str);
    char* data = malloc(size);
    if (!data)
        return -ENOMEM;
    memcpy(data, str, size);
    *out_data = data;
    *out_size = size;
    return 0;
}

static void init_cpu_dir(struct pseudo_node* cpu) {
    pseudo_add_str(cpu, "online", &sys_cpu_general_load);
    pseudo_add_str(cpu, "possible", &sys_cpu_general_load);

    struct pseudo_node* cpuX = pseudo_add_dir(cpu, NULL);
    cpuX->name_exists = &sys_resource_name_exists;
    cpuX->list_names = &sys_resource_list_names;

    /* Create a node for `cpu/cpuX/online`. We provide name callbacks instead of a hardcoded name,
     * because we want the file to exist for all CPUs *except* `cpu0`. */
    struct pseudo_node* online = pseudo_add_str(cpuX, NULL, &sys_cpu_load);
    online->name_exists = &sys_cpu_online_name_exists;
    online->list_names = &sys_cpu_online_list_names;

    struct pseudo_node* topology = pseudo_add_dir(cpuX, "topology");
    pseudo_add_str(topology, "core_id", &sys_cpu_load);
    pseudo_add_str(topology, "physical_package_id", &sys_cpu_load);
    pseudo_add_str(topology, "core_siblings", &sys_cpu_load);
    pseudo_add_str(topology, "thread_siblings", &sys_cpu_load);

    struct pseudo_node* cache = pseudo_add_dir(cpuX, "cache");
    struct pseudo_node* indexX = pseudo_add_dir(cache, NULL);
    indexX->name_exists = &sys_resource_name_exists;
    indexX->list_names = &sys_resource_list_names;

    pseudo_add_str(indexX, "shared_cpu_map", &sys_cache_load);
    pseudo_add_str(indexX, "level", &sys_cache_load);
    pseudo_add_str(indexX, "type", &sys_cache_load);
    pseudo_add_str(indexX, "size", &sys_cache_load);
    pseudo_add_str(indexX, "coherency_line_size", &sys_cache_load);
    pseudo_add_str(indexX, "number_of_sets", &sys_cache_load);
    pseudo_add_str(indexX, "physical_line_partition", &sys_cache_load);
}

static void init_node_dir(struct pseudo_node* node) {
    pseudo_add_str(node, "online", &sys_node_general_load);

    struct pseudo_node* nodeX = pseudo_add_dir(node, NULL);
    nodeX->name_exists = &sys_resource_name_exists;
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
