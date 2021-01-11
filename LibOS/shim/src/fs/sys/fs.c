/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation */

/*
 * This file contains the implementation of `/sys/devices/system/{cpu,node}/` pseudo-filesystem and
 * its sub-directories.
 */

#include "perm.h"
#include "shim_fs.h"
#include "stat.h"

extern const struct pseudo_dir sys_cpu_dir;
extern const struct pseudo_dir sys_node_dir;

int extract_first_num_from_string (const char* pathname) {
    const char* str = pathname;

    while (*str) {
        if ((*str >= '0') && (*str <= '9') ) {
            return strtol(str, NULL, 10);
        }
        str++;
    }

    return -1;
}

/* This function will extract "cpu105" from "cpu105/cache/index0/type". If string doesn't have "/"
 * delimiter, a copy of original string is returned. Note: Caller's responsibility to free returned
 * buffer.*/
static char* extract_first_token_from_path(const char* pathname) {
    if (pathname == NULL)
        return NULL;

    char* name = strdup(pathname);
    if (!name)
        return NULL;

    char *delim_ptr = strchr(name, '/');
    if (delim_ptr)
        *delim_ptr = '\0';

    return name;
}

int sys_match_resource_num(const char* pathname) {
    int num, totalcnt;
    int ret = 1;

    char* token = extract_first_token_from_path(pathname);
    if (!token) {
        ret = 0;
        goto out;
    }

    num = extract_first_num_from_string (token);
    if (num < 0) {
        ret = 0;
        goto out;
    }

    if (strstartswith(token, "node")) {
        totalcnt = pal_control.topo_info.num_online_nodes;
    } else if (strstartswith(token, "cpu")) {
        totalcnt = pal_control.cpu_info.online_logical_cores;
    } else if (strstartswith(token, "index")) {
        totalcnt = pal_control.topo_info.num_cache_index;
    } else {
        debug("Invalid resource %s in file %s!", token, pathname);
        ret = 0;
        goto out;
    }

    if (num > totalcnt) {
        debug("Incorrect index %d in file %s (max supported is %d)\n", num, pathname, totalcnt);
        ret = 0;
        goto out;
    }
out:
    free(token);
    return ret;
}

int sys_list_resource_num(const char* pathname, struct shim_dirent** buf, size_t size) {
    int totalcnt;
    char res_name[6];
    char ent_name[32];
    struct shim_dirent* dirent_in_buf = *buf;
    size_t total_size = 0;

    if (strendswith(pathname, "node")) {
        snprintf(res_name, sizeof(res_name), "node");
        totalcnt = pal_control.topo_info.num_online_nodes;
    } else if (strendswith(pathname, "index")) {
        snprintf(res_name, sizeof(res_name), "index");
        totalcnt = pal_control.topo_info.num_cache_index;
    } else if (strendswith(pathname, "cpu")) {
        snprintf(res_name, sizeof(res_name), "cpu");
        totalcnt = pal_control.cpu_info.online_logical_cores;
    } else {
        debug("Invalid resource name in file %s\n", pathname);
        return -EINVAL;
    }

    for (int i = 0; i < totalcnt; i++) {
        snprintf(ent_name, sizeof(ent_name), "%s%d", res_name, i);
        size_t name_size   = strlen(ent_name) + 1;
        size_t dirent_size = sizeof(struct shim_dirent) + name_size;

        total_size += dirent_size;
        if (total_size > size)
            return -ENOMEM;

        memcpy(dirent_in_buf->name, ent_name, name_size);
        dirent_in_buf->next = (void*)dirent_in_buf + dirent_size;
        dirent_in_buf->ino  = 1;
        dirent_in_buf->type = LINUX_DT_DIR;
        dirent_in_buf = dirent_in_buf->next;
    }

    *buf = dirent_in_buf;
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
    buf->st_ino  = 1;    /* dummy inode number */
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

static const struct pseudo_fs_ops fs_sysdir = {
    .mode = &sys_dir_mode,
    .stat = &sys_dir_stat,
    .open = &sys_dir_open,
};

static const struct pseudo_dir sys_sys_dir = {
    .size = 2,
    .ent  = {
        {.name = "cpu",  .dir = &sys_cpu_dir,  .fs_ops = &fs_sysdir, .type = LINUX_DT_DIR},
        {.name = "node", .dir = &sys_node_dir, .fs_ops = &fs_sysdir, .type = LINUX_DT_DIR},
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

static int sys_readdir(struct shim_dentry* dent, struct shim_dirent** dirent) {
    return pseudo_readdir(dent, dirent, &sys_root_ent);
}

static int sys_stat(struct shim_dentry* dent, struct stat* buf) {
    return pseudo_stat(dent, buf, &sys_root_ent);
}

static int sys_hstat(struct shim_handle* hdl, struct stat* buf) {
    return pseudo_hstat(hdl, buf, &sys_root_ent);
}

struct shim_fs_ops sys_fs_ops = {
    .mount   = &pseudo_mount,
    .unmount = &pseudo_unmount,
    .close   = &str_close,
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
