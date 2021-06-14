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

static int cache_info_open(struct shim_handle* hdl, const char* name, int flags) {
    char filename[32];

    size_t size = sizeof(filename);
    int ret = get_base_name(name, filename, &size);
    if (ret < 0)
        return -ENOENT;

    int cpunum = extract_first_num_from_string(name);
    if (cpunum < 0)
        return -ENOENT;

    assert(strstr(name, "index"));
    int idx = extract_first_num_from_string(strstr(name, "index"));
    if (idx < 0)
        return -ENOENT;

    PAL_CORE_CACHE_INFO* cache = &g_pal_control->topo_info.core_topology[cpunum].cache[idx];
    const char* cache_filebuf;
    if (!strcmp(filename, "shared_cpu_map")) {
        cache_filebuf = cache->shared_cpu_map;
    } else if (!strcmp(filename, "level")) {
        cache_filebuf = cache->level;
    } else if (!strcmp(filename, "type")) {
        cache_filebuf = cache->type;
    } else if (!strcmp(filename, "size")) {
        cache_filebuf = cache->size;
    } else if (!strcmp(filename, "coherency_line_size")) {
        cache_filebuf = cache->coherency_line_size;
    } else if (!strcmp(filename, "number_of_sets")) {
        cache_filebuf = cache->number_of_sets;
    } else if (!strcmp(filename, "physical_line_partition")) {
        cache_filebuf = cache->physical_line_partition;
    } else {
        log_debug("Unrecognized file %s\n", name);
        return -ENOENT;
    }

    size = strlen(cache_filebuf) + 1;
    char* str = malloc(size);
    if (!str)
        return -ENOMEM;
    memcpy(str, cache_filebuf, size);

    struct shim_str_data* data = calloc(1, sizeof(*data));
    if (!data) {
        free(str);
        return -ENOMEM;
    }

    data->str          = str;
    data->len          = size;
    hdl->type          = TYPE_STR;
    hdl->flags         = flags & ~O_RDONLY;
    hdl->acc_mode      = MAY_READ;
    hdl->info.str.data = data;

    return 0;
}

static const struct pseudo_fs_ops cache_idx_info = {
    .mode = &sys_info_mode,
    .stat = &sys_info_stat,
    .open = &cache_info_open,
};

static const struct pseudo_dir cache_idx_dir = {
    .size = 7,
    .ent  = {
        {.name = "shared_cpu_map",          .fs_ops = &cache_idx_info, .type = LINUX_DT_REG},
        {.name = "level",                   .fs_ops = &cache_idx_info, .type = LINUX_DT_REG},
        {.name = "type",                    .fs_ops = &cache_idx_info, .type = LINUX_DT_REG},
        {.name = "size",                    .fs_ops = &cache_idx_info, .type = LINUX_DT_REG},
        {.name = "coherency_line_size",     .fs_ops = &cache_idx_info, .type = LINUX_DT_REG},
        {.name = "number_of_sets",          .fs_ops = &cache_idx_info, .type = LINUX_DT_REG},
        {.name = "physical_line_partition", .fs_ops = &cache_idx_info, .type = LINUX_DT_REG},
    }
};

static const struct pseudo_fs_ops cache_info = {
    .mode = &sys_dir_mode,
    .stat = &sys_dir_stat,
    .open = &sys_dir_open,
};

static const struct pseudo_name_ops cache_ops = {
    .match_name = &sys_match_resource_num,
    .list_name  = &sys_list_resource_num,
};

const struct pseudo_dir cpunum_cache_dir = {
    .size = 1,
    .ent  = {
        {.name_ops = &cache_ops, .fs_ops = &cache_info, .dir = &cache_idx_dir, .type = LINUX_DT_DIR},
    }
};


int sys_cache_get_content(struct shim_dentry* dent, char** content, size_t* size) {
    const char* name = qstrgetstr(&dent->name);
    /* we're at /sys/devices/system/cpu/cpu0/cache/indexX/ */
    struct shim_dentry* indexX = dent->parent;
    struct shim_dentry* cpuX = dent->parent->parent->parent;

    int cache_num = sys_resource_find(indexX->parent, qstrgetstr(&indexX->name),
                                    /*callback=*/NULL, /*arg=*/NULL);
    if (cache_num < 0)
        return cache_num;

    int cpu_num = sys_resource_find(cpuX->parent, qstrgetstr(&cpuX->name),
                                    /*callback=*/NULL, /*arg=*/NULL);
    if (cpu_num < 0)
        return cpu_num;

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
        log_debug("Unrecognized file: %s\n", name);
        return -ENOENT;
    }

    return sys_get_content(str, content, size);
}
