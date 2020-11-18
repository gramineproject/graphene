/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation */

/*
 * This file contains the implementation of `/sys/devices/system/cpu/cpuX/cache`
 */

#include "shim_fs.h"

static int cache_info_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(hdl);
    __UNUSED(flags);

    size_t len;
    char filename[32];
    char* str = malloc(SYSFS_FILESZ);
    if (!str)
        return -ENOMEM;

    get_base_name(name, filename, &len);
    int cpunum = extract_num_from_path(name);
    if (cpunum < 0 )
        return -ENOENT;

    int idx = extract_num_from_path(strstr(name, "index"));
    if (idx < 0 )
        return -ENOENT;

    if (!strcmp(filename, "shared_cpu_map")) {
        const char* cachemap;
        cachemap = pal_control.topo_info.core_topology[cpunum].cache[idx].shared_cpu_map;
        len =  strlen(cachemap) + 1;
        memcpy(str, cachemap, len);

    } else if (!strcmp(filename, "level")) {
        const char* level = pal_control.topo_info.core_topology[cpunum].cache[idx].level;
        len =  strlen(level) + 1;
        memcpy(str, level, len);

    } else if (!strcmp(filename, "type")) {
        const char* type = pal_control.topo_info.core_topology[cpunum].cache[idx].type;
        len =  strlen(type) + 1;
        memcpy(str, type, len);

    } else if (!strcmp(filename, "size")) {
        const char* size = pal_control.topo_info.core_topology[cpunum].cache[idx].size;
        len =  strlen(size) + 1;
        memcpy(str, size, len);

    } else if (!strcmp(filename, "coherency_line_size")) {
        const char* coherency;
        coherency = pal_control.topo_info.core_topology[cpunum].cache[idx].coherency_line_size;
        len =  strlen(coherency) + 1;
        memcpy(str, coherency, len);

    } else if (!strcmp(filename, "number_of_sets")) {
        const char* sets  = pal_control.topo_info.core_topology[cpunum].cache[idx].number_of_sets;
        len =  strlen(sets) + 1;
        memcpy(str, sets, len);

    } else if (!strcmp(filename, "physical_line_partition")) {
        const char* partition;
        partition = pal_control.topo_info.core_topology[cpunum].cache[idx].physical_line_partition;
        len =  strlen(partition) + 1;
        memcpy(str, partition, len);

    } else {
        debug("Unsupported Filepath %s\n", name);
        return -ENOENT;
    }

    struct shim_str_data* data = malloc(sizeof(struct shim_str_data));
    if (!data) {
        free(str);
        return -ENOMEM;
    }

    memset(data, 0, sizeof(struct shim_str_data));
    data->str          = str;
    data->len          = len;
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
              { .name   = "shared_cpu_map",
                .fs_ops = &cache_idx_info,
                .type   = LINUX_DT_REG },
              { .name   = "level",
                .fs_ops = &cache_idx_info,
                .type   = LINUX_DT_REG },
              { .name   = "type",
                .fs_ops = &cache_idx_info,
                .type   = LINUX_DT_REG },
              { .name   = "size",
                .fs_ops = &cache_idx_info,
                .type   = LINUX_DT_REG },
              { .name   = "coherency_line_size",
                .fs_ops = &cache_idx_info,
                .type   = LINUX_DT_REG },
              { .name   = "number_of_sets",
                .fs_ops = &cache_idx_info,
                .type   = LINUX_DT_REG },
              { .name   = "physical_line_partition",
                .fs_ops = &cache_idx_info,
                .type   = LINUX_DT_REG },
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
              { .name_ops = &cache_ops,
                .fs_ops   = &cache_info,
                .dir      = &cache_idx_dir,
                .type     = LINUX_DT_DIR },
            }
};
