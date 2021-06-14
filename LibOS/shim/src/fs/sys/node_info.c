/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the implementation of `/sys/devices/system/node` and its sub-directories.
 */

#include "api.h"
#include "shim_fs.h"
#include "shim_fs_pseudo.h"

static int node_info_open(struct shim_handle* hdl, const char* name, int flags) {
    char filename[32];

    size_t size = sizeof(filename);
    int ret = get_base_name(name, filename, &size);
    if (ret < 0)
        return -ENOENT;

    const char* node_filebuf;
    if (!strcmp(filename, "online")) {
        /* This file refers to /sys/devices/system/node/online */
        node_filebuf = g_pal_control->topo_info.online_nodes;
    } else {
        /* The below files are under /sys/devices/system/node/nodeX/ */
        int nodenum = extract_first_num_from_string(name);
        if (nodenum < 0)
            return -ENOENT;

        PAL_NUMA_TOPO_INFO* numa_topology = &g_pal_control->topo_info.numa_topology[nodenum];
        if (!strcmp(filename, "cpumap")) {
            node_filebuf = numa_topology->cpumap;
        } else if (!strcmp(filename, "distance")) {
            node_filebuf = numa_topology->distance;
        } else if (strendswith(name, "hugepages-2048kB/nr_hugepages")) {
            node_filebuf = numa_topology->hugepages[HUGEPAGES_2M].nr_hugepages;
        } else if (strendswith(name, "hugepages-1048576kB/nr_hugepages")) {
            node_filebuf = numa_topology->hugepages[HUGEPAGES_1G].nr_hugepages;
        } else {
            log_debug("Unrecognized file %s\n", name);
            return -ENOENT;
        }
    }

    size = strlen(node_filebuf) + 1;
    char* str = malloc(size);
    if (!str)
        return -ENOMEM;
    memcpy(str, node_filebuf, size);

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
        {.name = "nr_hugepages", .fs_ops = &node_info, .type = LINUX_DT_REG},
    }
};

static const struct pseudo_dir nodenum_hugepg_dir = {
    .size = 2,
    .ent  = {
        {.name   = "hugepages-2048kB",
         .fs_ops = &nodenum_dirinfo,
         .dir    = &nr_hugepage_dir,
         .type   = LINUX_DT_DIR},
        {.name   = "hugepages-1048576kB",
         .fs_ops = &nodenum_dirinfo,
         .dir    = &nr_hugepage_dir,
         .type   = LINUX_DT_DIR},
    }
};

static const struct pseudo_dir node_num_dir = {
    .size = 3,
    .ent  = {
        {.name = "cpumap",   .fs_ops = &node_info, .type = LINUX_DT_REG},
        {.name = "distance", .fs_ops = &node_info, .type = LINUX_DT_REG},
        {.name   = "hugepages",
         .fs_ops = &nodenum_dirinfo,
         .dir    = &nodenum_hugepg_dir,
         .type   = LINUX_DT_DIR},
    }
};

const struct pseudo_dir sys_node_dir = {
    .size = 2,
    .ent  = {
        {.name = "online",         .fs_ops = &node_info, .type = LINUX_DT_REG},
        {.name_ops = &nodenum_ops, .dir = &node_num_dir, .type = LINUX_DT_DIR},
    }
};

int sys_node_general_get_content(struct shim_dentry* dent, char** content, size_t* size) {
    const char* name = qstrgetstr(&dent->name);
    const char* str;
    if (strcmp(name, "online") == 0) {
        str = g_pal_control->topo_info.online_nodes;
    } else {
        log_debug("unrecognized file: %s\n", name);
        return -ENOENT;
    }

    return sys_get_content(str, content, size);
}


int sys_node_get_content(struct shim_dentry* dent, char** content, size_t* size) {
    const char* name = qstrgetstr(&dent->name);
    struct shim_dentry* nodeX;

    if (strstartswith(qstrgetstr(&dent->parent->name), "hugepages")) {
        /* we're under /sys/devices/system/node/nodeX/hugepages/hugepages-X/ */
        nodeX = dent->parent->parent->parent;
    } else {
        /* we're under /sys/devices/system/node/nodeX/ */
        nodeX = dent->parent;
    }

    int node_num = sys_resource_find(nodeX->parent, qstrgetstr(&nodeX->name),
                                     /*callback=*/NULL, /*arg=*/NULL);
    if (node_num < 0)
        return node_num;

    PAL_NUMA_TOPO_INFO* numa_topology = &g_pal_control->topo_info.numa_topology[node_num];
    const char* str;
    if (strcmp(name, "cpumap" ) == 0) {
        str = numa_topology->cpumap;
    } else if (strcmp(name, "distance") == 0) {
        str = numa_topology->distance;
    } else if (strcmp(name, "nr_hugepages") == 0) {
        const char* parent_name = qstrgetstr(&dent->parent->name);
        if (strcmp(parent_name, "hugepages-2048kB") == 0) {
            str = numa_topology->hugepages[HUGEPAGES_2M].nr_hugepages;
        } else if (strcmp(parent_name, "hugepages-1048576kB") == 0) {
            str = numa_topology->hugepages[HUGEPAGES_1G].nr_hugepages;
        }
    }
    if (!str) {
        log_debug("unrecognized file: %s\n", name);
        return -ENOENT;
    }

    return sys_get_content(str, content, size);
}
