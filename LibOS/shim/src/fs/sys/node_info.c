/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation */

/*
 * This file contains the implementation of `/sys/devices/system/node` and its sub-directories.
 */

#include "shim_fs.h"

static int node_info_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(hdl);
    __UNUSED(flags);

    char filename[32];

    size_t len = sizeof(filename);
    int ret = get_base_name(name, filename, &len);
    if (ret < 0 || (strlen(filename) != len))
        return -ENOENT;

    int nodenum = extract_num_from_path(name);
    if (nodenum < 0)
        return -ENOENT;

    const char* node_filebuf;
    if (!strcmp(filename, "online")) {
        node_filebuf = pal_control.topo_info.online_nodes;
    } else if (!strcmp(filename, "cpumap")) {
        node_filebuf = pal_control.topo_info.numa_topology[nodenum].cpumap;
    } else if (!strcmp(filename, "distance")) {
        node_filebuf = pal_control.topo_info.numa_topology[nodenum].distance;
    } else if (strstr(name, "hugepages-2048kB/nr_hugepages")) {
        node_filebuf = pal_control.topo_info.numa_topology[nodenum].hugepages[0].nr_hugepages;
    } else if (strstr(name, "hugepages-1048576kB/nr_hugepages")) {
        node_filebuf = pal_control.topo_info.numa_topology[nodenum].hugepages[1].nr_hugepages;
    } else {
        debug("Unrecognized file %s\n", name);
        return -ENOENT;
    }

    len = strlen(node_filebuf) + 1;
    char* str = malloc(len);
    if (!str)
        return -ENOMEM;
    memcpy(str, node_filebuf, len);

    struct shim_str_data* data = calloc(1, sizeof(*data));
    if (!data) {
        free(str);
        return -ENOMEM;
    }

    data->str          = str;
    data->len          = len;
    hdl->type          = TYPE_STR;
    hdl->flags         = flags & ~O_RDONLY;
    hdl->acc_mode      = MAY_READ;
    hdl->info.str.data = data;

    return 0;
}

static const struct pseudo_fs_ops node_info = {
    .mode = &sys_info_mode,
    .stat = &sys_info_stat,
    .open = &node_info_open,
};
static const struct pseudo_name_ops nodenum_ops = {
    .match_name = &sys_match_resource_num,
    .list_name  = &sys_list_resource_num,
};

static const struct pseudo_fs_ops nodenum_dirinfo = {
    .mode = &sys_dir_mode,
    .stat = &sys_dir_stat,
    .open = &sys_dir_open,
};

static const struct pseudo_dir nr_hugepage_dir = {
    .size = 1,
    .ent  = {
              { .name   = "nr_hugepages",
                .fs_ops = &node_info,
                .type   = LINUX_DT_REG },
            }
};

static const struct pseudo_dir nodenum_hugepg_dir = {
    .size = 2,
    .ent  = {
              { .name   = "hugepages-2048kB",
                .fs_ops = &nodenum_dirinfo,
                .dir    = &nr_hugepage_dir,
                .type   = LINUX_DT_DIR },
              { .name   = "hugepages-1048576kB",
                .fs_ops = &nodenum_dirinfo,
                .dir    = &nr_hugepage_dir,
                .type   = LINUX_DT_DIR },
            }
};

static const struct pseudo_dir node_num_dir = {
    .size = 3,
    .ent  = {
              { .name   = "cpumap",
                .fs_ops = &node_info,
                .type   = LINUX_DT_REG },
              { .name   = "distance",
                .fs_ops = &node_info,
                .type   = LINUX_DT_REG },
              { .name   = "hugepages",
                .fs_ops = &nodenum_dirinfo,
                .dir    = &nodenum_hugepg_dir,
                .type   = LINUX_DT_DIR },
            }
};

const struct pseudo_dir sys_node_dir = {
    .size = 2,
    .ent  = {
              { .name     = "online",
                .fs_ops   = &node_info,
                .type     = LINUX_DT_REG },
              { .name_ops = &nodenum_ops,
                .dir      = &node_num_dir,
                .type     = LINUX_DT_DIR },
            }
};
