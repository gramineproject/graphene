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

    const char* cache_filebuf;
    if (!strcmp(filename, "shared_cpu_map")) {
        cache_filebuf = pal_control.topo_info.core_topology[cpunum].cache[idx].shared_cpu_map;
    } else if (!strcmp(filename, "level")) {
        cache_filebuf = pal_control.topo_info.core_topology[cpunum].cache[idx].level;
    } else if (!strcmp(filename, "type")) {
        cache_filebuf = pal_control.topo_info.core_topology[cpunum].cache[idx].type;
    } else if (!strcmp(filename, "size")) {
        cache_filebuf = pal_control.topo_info.core_topology[cpunum].cache[idx].size;
    } else if (!strcmp(filename, "coherency_line_size")) {
        cache_filebuf = pal_control.topo_info.core_topology[cpunum].cache[idx].coherency_line_size;
    } else if (!strcmp(filename, "number_of_sets")) {
        cache_filebuf = pal_control.topo_info.core_topology[cpunum].cache[idx].number_of_sets;
    } else if (!strcmp(filename, "physical_line_partition")) {
        cache_filebuf = pal_control.topo_info.core_topology[cpunum].cache[idx].physical_line_partition;
    } else {
        debug("Unrecognized file %s\n", name);
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
