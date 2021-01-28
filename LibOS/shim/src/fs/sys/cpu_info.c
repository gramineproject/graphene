/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the implementation of `/sys/devices/system/cpu` and its sub-directories.
 */

#include "api.h"
#include "shim_fs.h"

/* Sub-directory /sys/devices/system/cpu/cpuX/cache is implemented in separate file cache_info.c */
extern const struct pseudo_dir cpunum_cache_dir;

static int cpu_info_open(struct shim_handle* hdl, const char* name, int flags) {
    char filename[32];

    size_t size = sizeof(filename);
    int ret = get_base_name(name, filename, &size);
    if (ret < 0)
        return -ENOENT;

    int cpunum = extract_first_num_from_string(name);
    if (cpunum < 0)
        return -ENOENT;

    char temp_buf[16];
    const char* cpu_filebuf;
    if (!strcmp(filename, "online")) {
        /* distinguish /sys/devices/system/cpu/online from /sys/devices/system/cpu/cpuX/online */
        if (strstr(name, "cpu/cpu")) {
            /* core 0 is always online, so file /sys/devices/system/cpu/cpu0/online doesn't exist */
            if (cpunum == 0)
                return -ENOENT;
            cpu_filebuf = pal_control.topo_info.core_topology[cpunum].is_logical_core_online;
        } else {
            cpu_filebuf = pal_control.topo_info.online_logical_cores;
        }
    } else if (!strcmp(filename, "possible")) {
        cpu_filebuf = pal_control.topo_info.possible_logical_cores;
    } else if (!strcmp(filename, "core_id")) {
        cpu_filebuf = pal_control.topo_info.core_topology[cpunum].core_id;
    } else if (!strcmp(filename, "physical_package_id")) {
        /* we have already collected this info as part of /proc/cpuinfo. So reuse it */
        snprintf(temp_buf, sizeof(temp_buf), "%d\n", pal_control.cpu_info.cpu_socket[cpunum]);
        cpu_filebuf = temp_buf;
    } else if (!strcmp(filename, "core_siblings")) {
        cpu_filebuf = pal_control.topo_info.core_topology[cpunum].core_siblings;
    } else if (!strcmp(filename, "thread_siblings")) {
        cpu_filebuf = pal_control.topo_info.core_topology[cpunum].thread_siblings;
    } else {
        debug("Unrecognized file %s\n", name);
        return -ENOENT;
    }

    size = strlen(cpu_filebuf) + 1;
    char* str = malloc(size);
    if (!str)
        return -ENOMEM;
    memcpy(str, cpu_filebuf, size);

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

static const struct pseudo_fs_ops cpu_info = {
    .mode = &sys_info_mode,
    .stat = &sys_info_stat,
    .open = &cpu_info_open,
};

static const struct pseudo_dir cpunum_topo_dir = {
    .size = 4,
    .ent  = {
        {.name = "core_id",             .fs_ops = &cpu_info, .type = LINUX_DT_REG},
        {.name = "physical_package_id", .fs_ops = &cpu_info, .type = LINUX_DT_REG},
        {.name = "core_siblings",       .fs_ops = &cpu_info, .type = LINUX_DT_REG},
        {.name = "thread_siblings",     .fs_ops = &cpu_info, .type = LINUX_DT_REG},
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
        {.name = "online", .fs_ops = &cpu_info, .type = LINUX_DT_REG},
        {.name   = "topology",
         .fs_ops = &cpunum_dirinfo,
         .dir    = &cpunum_topo_dir,
         .type   = LINUX_DT_DIR},
        {.name   = "cache",
         .fs_ops = &cpunum_dirinfo,
         .dir    = &cpunum_cache_dir,
         .type   = LINUX_DT_DIR},
    }
};

static const struct pseudo_name_ops cpunum_ops = {
    .match_name = &sys_match_resource_num,
    .list_name  = &sys_list_resource_num,
};

const struct pseudo_dir sys_cpu_dir = {
    .size = 3,
    .ent  = {
        {.name = "online",        .fs_ops = &cpu_info, .type = LINUX_DT_REG},
        {.name = "possible",      .fs_ops = &cpu_info, .type = LINUX_DT_REG},
        {.name_ops = &cpunum_ops, .dir = &cpunum_dir,  .type = LINUX_DT_DIR},
    }
};
