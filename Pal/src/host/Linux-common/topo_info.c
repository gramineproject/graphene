/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the APIs to expose host topology information.
 */

#include <asm/errno.h>
#include <asm/fcntl.h>
#include <limits.h>

#include "api.h"
#include "pal_linux.h"
#include "syscall.h"
#include "topo_info.h"

int get_hw_resource(const char* filename, bool count) {
    int fd = DO_SYSCALL(open, filename, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0)
        return fd;

    char buf[64];
    int ret = DO_SYSCALL(read, fd, buf, sizeof(buf) - 1);
    DO_SYSCALL(close, fd);
    if (ret < 0)
        return ret;

    buf[ret] = '\0'; /* ensure null-terminated buf even in partial read */

    char* ptr = buf;
    int resource_cnt = 0;
    int retval = -ENOENT;
    while (*ptr) {
        while (*ptr == ' ' || *ptr == '\t' || *ptr == ',')
            ptr++;

        char* end;
        long firstint = strtol(ptr, &end, 10);
        if (firstint < 0 || firstint > INT_MAX)
            return -ENOENT;

        if (ptr == end)
            break;

        /* caller wants to read an int stored in the file */
        if (!count) {
            if (*end == '\n' || *end == '\0')
                retval = (int)firstint;
            return retval;
        }

        /* caller wants to count the number of HW resources */
        if (*end == '\0' || *end == ',' || *end == '\n') {
            /* single HW resource index, count as one more */
            resource_cnt++;
        } else if (*end == '-') {
            /* HW resource range, count how many HW resources are in range */
            ptr = end + 1;
            long secondint = strtol(ptr, &end, 10);
            if (secondint < 0 || secondint > INT_MAX)
                return -EINVAL;

            if (secondint > firstint) {
                long diff = secondint - firstint;
                long total_cnt;
                if (__builtin_add_overflow(resource_cnt, diff, &total_cnt) || total_cnt >= INT_MAX)
                     return -EINVAL;
                resource_cnt += (int)secondint - (int)firstint + 1; //inclusive (e.g., 0-7, or 8-16)
            }
        }
        ptr = end;
    }

    if (count && resource_cnt > 0)
        retval = resource_cnt;

    return retval;
}

int read_file_buffer(const char* filename, char* buf, size_t count) {
    int fd = DO_SYSCALL(open, filename, O_RDONLY);
    if (fd < 0)
        return fd;

    int ret = DO_SYSCALL(read, fd, buf, count);
    DO_SYSCALL(close, fd);
    if (ret < 0)
        return ret;

    return ret;
}

#define READ_FILE_BUFFER(filepath, buf, failure_label)                           \
    ({                                                                           \
        ret = read_file_buffer(filepath, buf, ARRAY_SIZE(buf)-1);                \
        if (ret < 0)                                                             \
            goto failure_label;                                                  \
        buf[ret] = '\0';                                                         \
    })

/* Returns number of cache levels present on this system by counting "indexX" dir entries under
 * `/sys/devices/system/cpu/cpuX/cache` on success and negative UNIX error code on failure. */
static int get_num_cache_level(const char* path) {
    char buf[1024];
    int num_dirs = 0;

    int fd = DO_SYSCALL(open, path, O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        return fd;

    while (true) {
        int nread = DO_SYSCALL(getdents64, fd, buf, 1024);
        if (nread < 0) {
            num_dirs = nread;
            goto out;
        }

        if (nread == 0)
            break;

        for (int bpos = 0; bpos < nread;) {
            struct linux_dirent64* dirent64 = (struct linux_dirent64*)(buf + bpos);
            if (dirent64->d_type == DT_DIR && strstartswith(dirent64->d_name, "index"))
                num_dirs++;
            bpos += dirent64->d_reclen;
        }
    }

out:
    DO_SYSCALL(close, fd);
    return num_dirs ?: -ENOENT;
}

static int get_cache_topo_info(int num_cache_lvl, int core_idx, PAL_CORE_CACHE_INFO** cache_info) {
    int ret;
    char filename[128];
    PAL_CORE_CACHE_INFO* core_cache = (PAL_CORE_CACHE_INFO*)malloc(num_cache_lvl *
                                                                   sizeof(PAL_CORE_CACHE_INFO));
    if (!core_cache) {
        return -ENOMEM;
    }

    for (int lvl = 0; lvl < num_cache_lvl; lvl++) {
        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/cache/index%d/shared_cpu_map", core_idx, lvl);
        READ_FILE_BUFFER(filename, core_cache[lvl].shared_cpu_map, /*failure_label=*/out_cache);

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/cache/index%d/level", core_idx, lvl);
        READ_FILE_BUFFER(filename, core_cache[lvl].level, /*failure_label=*/out_cache);

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/cache/index%d/type", core_idx, lvl);
        READ_FILE_BUFFER(filename, core_cache[lvl].type, /*failure_label=*/out_cache);

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/cache/index%d/size", core_idx, lvl);
        READ_FILE_BUFFER(filename, core_cache[lvl].size, /*failure_label=*/out_cache);

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/cache/index%d/coherency_line_size", core_idx, lvl);
        READ_FILE_BUFFER(filename, core_cache[lvl].coherency_line_size,
                         /*failure_label=*/out_cache);

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/cache/index%d/number_of_sets", core_idx, lvl);
        READ_FILE_BUFFER(filename, core_cache[lvl].number_of_sets, /*failure_label=*/out_cache);

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/cache/index%d/physical_line_partition", core_idx,
                 lvl);
        READ_FILE_BUFFER(filename, core_cache[lvl].physical_line_partition,
                         /*failure_label=*/out_cache);
    }
    *cache_info = core_cache;
    return 0;

out_cache:
    free(core_cache);
    return ret;
}

/* Get core topology-related info */
static int get_core_topo_info(PAL_TOPO_INFO* topo_info) {
    int ret;
    READ_FILE_BUFFER("/sys/devices/system/cpu/online", topo_info->online_logical_cores,
                     /*failure_label=*/out);

    READ_FILE_BUFFER("/sys/devices/system/cpu/possible", topo_info->possible_logical_cores,
                     /*failure_label=*/out);

    int online_logical_cores = get_hw_resource("/sys/devices/system/cpu/online", /*count=*/true);
    if (online_logical_cores < 0)
        return online_logical_cores;

    int num_cache_lvl = get_num_cache_level("/sys/devices/system/cpu/cpu0/cache");
    if (num_cache_lvl < 0)
        return num_cache_lvl;
    topo_info->num_cache_index = num_cache_lvl;

    PAL_CORE_TOPO_INFO* core_topology = (PAL_CORE_TOPO_INFO*)malloc(online_logical_cores *
                                                                    sizeof(PAL_CORE_TOPO_INFO));
    if (!core_topology)
        return -ENOMEM;

    char filename[128];
    for (int idx = 0; idx < online_logical_cores; idx++) {
        /* cpu0 is always online and thus the "online" file is not present. */
        if (idx != 0) {
            snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/online", idx);
            READ_FILE_BUFFER(filename, core_topology[idx].is_logical_core_online,
                             /*failure_label=*/out_topology);
        }

        snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/topology/core_id", idx);
        READ_FILE_BUFFER(filename, core_topology[idx].core_id, /*failure_label=*/out_topology);

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/topology/core_siblings", idx);
        READ_FILE_BUFFER(filename, core_topology[idx].core_siblings,
                         /*failure_label=*/out_topology);

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/topology/thread_siblings", idx);
        READ_FILE_BUFFER(filename, core_topology[idx].thread_siblings,
                         /*failure_label=*/out_topology);

        ret = get_cache_topo_info(num_cache_lvl, idx, &core_topology[idx].cache);
        if (ret < 0)
            goto out_topology;
    }
    topo_info->core_topology = core_topology;
    return 0;

out_topology:
    free(core_topology);
out:
    return ret;
}

/* Get NUMA topology-related info */
static int get_numa_topo_info(PAL_TOPO_INFO* topo_info) {
    int ret;
    READ_FILE_BUFFER("/sys/devices/system/node/online", topo_info->online_nodes,
                     /*failure_label=*/out);

    int num_nodes = get_hw_resource("/sys/devices/system/node/online", /*count=*/true);
    if (num_nodes < 0)
        return num_nodes;
    topo_info->num_online_nodes = num_nodes;

    PAL_NUMA_TOPO_INFO* numa_topology = (PAL_NUMA_TOPO_INFO*)malloc(num_nodes *
                                                                    sizeof(PAL_NUMA_TOPO_INFO));
    if (!numa_topology)
        return -ENOMEM;

    char filename[128];
    for (int idx = 0; idx < num_nodes; idx++) {
        snprintf(filename, sizeof(filename), "/sys/devices/system/node/node%d/cpumap", idx);
        READ_FILE_BUFFER(filename, numa_topology[idx].cpumap, /*failure_label=*/out_topology);

        snprintf(filename, sizeof(filename), "/sys/devices/system/node/node%d/distance", idx);
        READ_FILE_BUFFER(filename, numa_topology[idx].distance, /*failure_label=*/out_topology);

        /* Since our /sys fs doesn't support writes, set persistent hugepages to their default value
         * of zero */
        memcpy(numa_topology[idx].hugepages[HUGEPAGES_2M].nr_hugepages, "0\n", 3);
        memcpy(numa_topology[idx].hugepages[HUGEPAGES_1G].nr_hugepages, "0\n", 3);
    }
    topo_info->numa_topology = numa_topology;
    return 0;

out_topology:
    free(numa_topology);
out:
    return ret;
}

int get_topology_info(PAL_TOPO_INFO* topo_info) {
    /* Get CPU topology information */
    int ret = get_core_topo_info(topo_info);
    if (ret < 0)
        return ret;

    /* Get NUMA topology information */
    ret = get_numa_topo_info(topo_info);
    if (ret < 0)
        return ret;

    return 0;
}
