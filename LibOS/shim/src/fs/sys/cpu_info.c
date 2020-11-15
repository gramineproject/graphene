/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation */

/*!
 * \file
 *
 * This file contains the implementation of `/sys/devices/system/cpu` and its sub-directories.
 */

#include "shim_fs.h"
extern const struct pseudo_dir cpunum_cache_dir;

static int cpu_info_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(hdl);
    __UNUSED(flags);

    int len;
    char* str = malloc(SYSFS_FILESZ);
    if (!str)
        return -ENOMEM;

    const char* filename = extract_filename(name);
    if (!strcmp(filename, "online")) {
        const char* online_info;
        if (strstr(name, "cpu/cpu")) {
            int cpunum = extract_num_from_path(name);
            if (cpunum < 0 )
                return -ENOENT;
            online_info = pal_control.topo_info.core_topology[cpunum].is_logical_core_online;
        }
        else
            online_info = pal_control.topo_info.online_logical_cores;

        len = strlen(online_info) + 1;
        memcpy(str, online_info, len);

    } else if (!strcmp(filename, "possible")) {
        const char* possible_info = pal_control.topo_info.possible_logical_cores;
        len = strlen(possible_info) + 1;
        memcpy(str, possible_info, len);

    } else if (!strcmp(filename, "core_id")) {
        int cpunum = extract_num_from_path(name);
        if (cpunum < 0 )
            return -ENOENT;

        const char* core_id;
        core_id = pal_control.topo_info.core_topology[cpunum].core_id;
        len = strlen(core_id) + 1;
        memcpy(str, core_id, len);

    } else if (!strcmp(filename, "physical_package_id")) {
        int cpunum = extract_num_from_path(name);
        if (cpunum < 0 )
            return -ENOENT;
        /* we have already collected this info as part of /proc/cpuinfo. So reuse it */
        snprintf(str, sizeof(str), "%d", pal_control.cpu_info.cpu_socket[cpunum]);
        len = strlen(str) + 1;
        str[len] = '\0';

    } else if (!strcmp(filename, "core_siblings")) {
        int cpunum = extract_num_from_path(name);
        if (cpunum < 0 )
            return -ENOENT;

        const char* coresiblings_info;
        coresiblings_info = pal_control.topo_info.core_topology[cpunum].core_siblings;
        len = strlen(coresiblings_info) + 1;
        memcpy(str, coresiblings_info, len);

    } else if (!strcmp(filename, "thread_siblings")) {
        int cpunum = extract_num_from_path(name);
        if (cpunum < 0 )
            return -ENOENT;

        const char* threadsiblings_info;
        threadsiblings_info = pal_control.topo_info.core_topology[cpunum].thread_siblings;
        len = strlen(threadsiblings_info) + 1;
        memcpy(str, threadsiblings_info, len);

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

static const struct pseudo_fs_ops cpu_info = {
    .mode = &sys_info_mode,
    .stat = &sys_info_stat,
    .open = &cpu_info_open,
};

static const struct pseudo_dir cpunum_topo_dir = {
    .size = 4,
    .ent  = {
              { .name   = "core_id",
                .fs_ops = &cpu_info,
                .type   = LINUX_DT_REG },
              { .name   = "physical_package_id",
                .fs_ops = &cpu_info,
                .type   = LINUX_DT_REG },
              { .name   = "core_siblings",
                .fs_ops = &cpu_info,
                .type   = LINUX_DT_REG },
              { .name   = "thread_siblings",
                .fs_ops = &cpu_info,
                .type   = LINUX_DT_REG },
            }
};

static const struct pseudo_fs_ops cpunum_dirinfo = {
    .mode = &sys_dir_mode,
    .stat = &sys_dir_stat,
    .open = &sys_dir_open,
};

static const struct pseudo_dir cpunum_dir = {
    .size = 3,
    .ent  = {
              { .name   = "online",
		        .fs_ops = &cpu_info,
                .type   = LINUX_DT_REG },
              { .name   = "topology",
		        .fs_ops = &cpunum_dirinfo,
                .dir    = &cpunum_topo_dir,
                .type   = LINUX_DT_DIR },
              { .name   = "cache",
		        .fs_ops = &cpunum_dirinfo,
                .dir    = &cpunum_cache_dir,
                .type   = LINUX_DT_DIR },
            }
};

static const struct pseudo_name_ops cpunum_ops = {
    .match_name = &sys_match_resource_num,
    .list_name  = &sys_list_resource_num,
};

const struct pseudo_dir sys_cpu_dir = {
    .size = 3,
    .ent  = {
              { .name     = "online",
                .fs_ops   = &cpu_info,
                .type     = LINUX_DT_REG },
              { .name     = "possible",
                .fs_ops   = &cpu_info,
                .type     = LINUX_DT_REG },
              { .name_ops = &cpunum_ops,
                .dir      = &cpunum_dir,
                .type     = LINUX_DT_DIR },
            }
};
