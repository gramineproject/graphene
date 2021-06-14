/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the implementation of `/sys/devices/system/{cpu,node}/` pseudo-filesystem and
 * its sub-directories.
 */
#include <limits.h>

#include "api.h"
#include "perm.h"
#include "shim_fs.h"
#include "shim_fs_pseudo.h"
#include "stat.h"

/* Sub-directores /sys/devices/system/{cpu,node} are implemented in separate files cpu_info.c and
 * node_info.c */
extern const struct pseudo_dir sys_cpu_dir;
extern const struct pseudo_dir sys_node_dir;

int extract_first_num_from_string(const char* pathname) {
    const char* str = pathname;

    while (*str) {
        if (*str >= '0' && *str <= '9') {
            long val = strtol(str, NULL, 10);
            if (val < 0 || val > INT_MAX)
                return -1;
            return (int)val;
        }
        str++;
    }

    return -1;
}

/* This function will extract "cpu105" from "cpu105/cache/index0/type" and return it in a newly
 * created buffer. If string doesn't have "/" delimiter, a copy of original string is returned. */
static char* extract_first_token_from_path(const char* pathname) {
    char* delim_ptr = strchr(pathname, '/');
    size_t len = delim_ptr ? (size_t)(delim_ptr - pathname) : strlen(pathname);

    return alloc_substr(pathname, len);
}

int sys_match_resource_num(const char* pathname) {
    int num, totalcnt;
    int ret = 1;

    char* token = extract_first_token_from_path(pathname);
    if (!token) {
        ret = 0;
        goto out;
    }

    num = extract_first_num_from_string(token);
    if (num < 0) {
        ret = 0;
        goto out;
    }

    char dirname[32];
    if (strstartswith(token, "node")) {
        snprintf(dirname, sizeof(dirname), "node%d", num);
        if (strcmp(token, dirname)) {
            ret = 0;
            goto out;
        }
        totalcnt = g_pal_control->topo_info.num_online_nodes;
    } else if (strstartswith(token, "cpu")) {
        snprintf(dirname, sizeof(dirname), "cpu%d", num);
        if (strcmp(token, dirname)) {
            ret = 0;
            goto out;
        }
        totalcnt = g_pal_control->cpu_info.online_logical_cores;
    } else if (strstartswith(token, "index")) {
        snprintf(dirname, sizeof(dirname), "index%d", num);
        if (strcmp(token, dirname)) {
            ret = 0;
            goto out;
        }
        totalcnt = g_pal_control->topo_info.num_cache_index;
    } else {
        log_debug("Invalid resource %s in file %s!\n", token, pathname);
        ret = 0;
        goto out;
    }

    /* sysfs resources like NUMA nodes, CPU cores, CPU caches have indexes from 0 to totalcnt - 1 */
    if (num >= totalcnt) {
        log_debug("Incorrect index %d in file %s (max supported is %d)\n", num, pathname, totalcnt);
        ret = 0;
        goto out;
    }
out:
    free(token);
    return ret;
}

int sys_list_resource_num(const char* pathname, readdir_callback_t callback, void* arg) {
    int totalcnt;

    char filename[32];
    size_t fsize = sizeof(filename);
    int ret = get_base_name(pathname, filename, &fsize);
    if (ret < 0)
        return -ENOENT;

    if (!strcmp(filename, "node")) {
        totalcnt = g_pal_control->topo_info.num_online_nodes;
    } else if (!strcmp(filename, "cache")) {
        totalcnt = g_pal_control->topo_info.num_cache_index;
    } else if (!strcmp(filename, "cpu")) {
        totalcnt = g_pal_control->cpu_info.online_logical_cores;
    } else {
        log_debug("Invalid resource name in file %s\n", pathname);
        return -EINVAL;
    }

    for (int i = 0; i < totalcnt; i++) {
        char ent_name[42];
        snprintf(ent_name, sizeof(ent_name), "%s%d", filename, i);
        if ((ret = callback(ent_name, arg)) < 0)
            return ret;
    }

    return 0;
}

int sys_info_mode(const char* name, mode_t* mode) {
    __UNUSED(name);
    *mode = FILE_R_MODE | S_IFREG;
    return 0;
}

int sys_info_stat(const char* name, struct stat* buf) {
    __UNUSED(name);
    memset(buf, 0, sizeof(*buf));
    buf->st_dev  = 1;    /* dummy ID of device containing file */
    buf->st_mode = FILE_R_MODE | S_IFREG;
    return 0;
}

int sys_dir_open(struct shim_handle* hdl, const char* name, int flags) {
    __UNUSED(hdl);
    __UNUSED(name);

    if (flags & (O_WRONLY | O_RDWR))
        return -EISDIR;

    return 0;
}

int sys_dir_mode(const char* name, mode_t* mode) {
    __UNUSED(name);

    *mode = PERM_r_x______;
    return 0;
}

int sys_dir_stat(const char* name, struct stat* buf) {
    __UNUSED(name);

    memset(buf, 0, sizeof(*buf));
    buf->st_mode  = PERM_r_x______ | S_IFDIR;
    /* FIXME: Libs like hwloc assume that nlink is 4 for paths like
     * /sys/devices/system/node/nodeX/hugepages(".", "..", "hugepages-2048kB", "hugepages-1048576kB").
     * Thus we currently set nlink to 4; need a more generic solution. */
    buf->st_nlink = 4;

    return 0;
}

static const struct pseudo_fs_ops fs_sys_dir = {
    .mode = &sys_dir_mode,
    .stat = &sys_dir_stat,
    .open = &sys_dir_open,
};

static const struct pseudo_dir sys_sys_dir = {
    .size = 2,
    .ent  = {
        {.name = "cpu",  .dir = &sys_cpu_dir,  .fs_ops = &fs_sys_dir, .type = LINUX_DT_DIR},
        {.name = "node", .dir = &sys_node_dir, .fs_ops = &fs_sys_dir, .type = LINUX_DT_DIR},
    }
};

static const struct pseudo_dir sys_dev_dir = {
    .size = 1,
    .ent  = {
        {.name = "system", .dir = &sys_sys_dir, .type = LINUX_DT_DIR},
    }
};

static const struct pseudo_dir sys_root_dir = {
    .size = 1,
    .ent  = {
        {.name = "devices", .dir = &sys_dev_dir, .type = LINUX_DT_DIR},
    }
};

static const struct pseudo_fs_ops sys_root_fs = {
    .open = &pseudo_dir_open,
    .mode = &pseudo_dir_mode,
    .stat = &pseudo_dir_stat,
};

static const struct pseudo_ent sys_root_ent = {
    .name   = "",
    .fs_ops = &sys_root_fs,
    .dir    = &sys_root_dir,
};

static int sys_mode(struct shim_dentry* dent, mode_t* mode) {
    return pseudo_mode(dent, mode, &sys_root_ent);
}

static int sys_lookup(struct shim_dentry* dent) {
    return pseudo_lookup(dent, &sys_root_ent);
}

static int sys_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags) {
    return pseudo_open(hdl, dent, flags, &sys_root_ent);
}

static int sys_readdir(struct shim_dentry* dent, readdir_callback_t callback, void* arg) {
    return pseudo_readdir(dent, callback, arg, &sys_root_ent);
}

static int sys_stat(struct shim_dentry* dent, struct stat* buf) {
    return pseudo_stat(dent, buf, &sys_root_ent);
}

static int sys_hstat(struct shim_handle* hdl, struct stat* buf) {
    return pseudo_hstat(hdl, buf, &sys_root_ent);
}

static int sys_close(struct shim_handle* hdl) {
    if (hdl->type == TYPE_PSEUDO) {
        /* e.g. a directory */
        return 0;
    }
    assert(hdl->type == TYPE_STR);
    return str_close(hdl);
}

struct shim_fs_ops sys_fs_ops = {
    .mount   = &pseudo_mount,
    .unmount = &pseudo_unmount,
    .close   = &sys_close,
    .read    = &str_read,
    .seek    = &str_seek,
    .hstat   = &sys_hstat,
};

struct shim_d_ops sys_d_ops = {
    .open    = &sys_open,
    .stat    = &sys_stat,
    .mode    = &sys_mode,
    .lookup  = &sys_lookup,
    .readdir = &sys_readdir,
};

struct shim_fs sys_builtin_fs = {
    .name   = "sys",
    .fs_ops = &sys_fs_ops,
    .d_ops  = &sys_d_ops,
};

int sys_resource_find(struct shim_dentry* parent, const char* name, readdir_callback_t callback,
                      void* arg) {
    const char* parent_name = qstrgetstr(&parent->name);
    size_t parent_name_len = parent->name.len;
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
        unsigned int n;
        if (parse_uint(&name[parent_name_len], &n) < 0)
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

int sys_resource_match_name(struct shim_dentry* parent, const char* name) {
    int ret = sys_resource_find(parent, name, /*callback=*/NULL, /*arg=*/NULL);
    if (ret < 0)
        return ret;
    return 0;
}

int sys_resource_list_names(struct shim_dentry* parent, readdir_callback_t callback, void* arg) {
    return sys_resource_find(parent, /*name=*/NULL, callback, arg);
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

    /* TODO /topology/... */
    pseudo_add_str(cpuX, "online", &sys_cpu_get_content);
    pseudo_add_str(cpuX, "core_id", &sys_cpu_get_content);
    pseudo_add_str(cpuX, "physical_package_id", &sys_cpu_get_content);
    pseudo_add_str(cpuX, "core_siblings", &sys_cpu_get_content);
    pseudo_add_str(cpuX, "thread_siblings", &sys_cpu_get_content);

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
    pseudo_add_str(hugepages_2m, "nr_online", &sys_node_get_content);
    struct pseudo2_ent* hugepages_1g = pseudo_add_dir(hugepages, "hugepages-1048576kB");
    pseudo_add_str(hugepages_1g, "nr_online", &sys_node_get_content);
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
