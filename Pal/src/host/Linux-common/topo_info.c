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

// FIXME: remove once global realloc is enabled
static void* realloc_sz(void* ptr, size_t old_size, size_t new_size) {
    void* tmp = malloc(new_size);
    if (!tmp) {
        return NULL;
    }

    if (ptr) {
        memcpy(tmp, ptr, old_size);
        free(ptr);
    }
    return tmp;
}

int get_hw_resource(const char* filename, bool count, PAL_RES_RANGE_INFO* res_info,
                    SIZE_QUALIFIER_T* size_qual) {
    if (res_info) {
        res_info->resource_count = 0;
        res_info->range_count = 0;
        res_info->ranges =  NULL;
    }

    if(size_qual)
        *size_qual = DEFAULT_SZ;

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
            if (*end == '\n' || *end == '\0' || *end == 'K' || *end == 'M' || *end == 'G') {
                retval = (int)firstint;
                if (size_qual) {
                    if (*end == 'K') {
                        *size_qual = KILO;
                    } else if (*end == 'M') {
                        *size_qual = MEGA;
                    } else if (*end == 'G') {
                        *size_qual = GIGA;
                    } else {
                        *size_qual = DEFAULT_SZ;
                    }
                }
            }
            return retval;
        }

        /* caller wants to count the number of HW resources */
        if (*end == '\0' || *end == ',' || *end == '\n' || *end == ' ') {
            /* single HW resource index, count as one more */
            resource_cnt++;
            if (res_info) {
                res_info->range_count++;
                size_t new_sz = sizeof(PAL_RANGE_INFO) * res_info->range_count;
                size_t old_sz = new_sz - sizeof(PAL_RANGE_INFO);
                res_info->ranges = realloc_sz(res_info->ranges, old_sz, new_sz);
                if (!res_info->ranges)
                    return -ENOMEM;
                res_info->ranges[res_info->range_count - 1].start = firstint;
                res_info->ranges[res_info->range_count - 1].end = UINT64_MAX;
            }
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
                if (res_info) {
                    res_info->range_count++;
                    size_t new_sz = sizeof(PAL_RANGE_INFO) * res_info->range_count;
                    size_t old_sz = new_sz - sizeof(PAL_RANGE_INFO);
                    res_info->ranges = realloc_sz(res_info->ranges, old_sz, new_sz);
                    if (!res_info->ranges)
                        return -ENOMEM;
                    res_info->ranges[res_info->range_count - 1].start = firstint;
                    res_info->ranges[res_info->range_count - 1].end = secondint;
                }
            }
        }
        ptr = end;
    }

    if (count && resource_cnt > 0) {
        retval = resource_cnt;
        if (res_info)
            res_info->resource_count = resource_cnt;
    }

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
    PAL_CORE_CACHE_INFO* core_cache = (PAL_CORE_CACHE_INFO*)malloc(num_cache_lvl *
                                                                   sizeof(PAL_CORE_CACHE_INFO));
    if (!core_cache) {
        return -ENOMEM;
    }

    char filename[128];
    for (int lvl = 0; lvl < num_cache_lvl; lvl++) {
        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/cache/index%d/shared_cpu_list", core_idx, lvl);
        ret = get_hw_resource(filename, /*count=*/true, &core_cache[lvl].shared_cpu_map, NULL);
        if (ret < 0)
            goto out_cache;

        snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/cache/index%d/level",
                 core_idx, lvl);
        int level = get_hw_resource(filename, /*count=*/false, NULL, NULL);
        if (level < 0)
            goto out_cache;
        core_cache[lvl].level = level;

        char type[PAL_SYSFS_BUF_FILESZ];
        snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/cache/index%d/type",
                 core_idx, lvl);
        READ_FILE_BUFFER(filename, type, /*failure_label=*/out_cache);
        if (!strcmp(type, "Unified\n")) {
            core_cache[lvl].type = UNIFIED;
        } else if (!strcmp(type, "Instruction\n")) {
            core_cache[lvl].type = INSTRUCTION;
        } else if (!strcmp(type, "Data\n")) {
            core_cache[lvl].type = DATA;
        } else {
            ret = -EINVAL;
            goto out_cache;
        }

        SIZE_QUALIFIER_T size_qual;
        snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/cache/index%d/size",
                 core_idx, lvl);
        int size = get_hw_resource(filename, /*count=*/false, NULL, &size_qual);
        if (size < 0)
            goto out_cache;
        core_cache[lvl].size = size;
        core_cache[lvl].size_qualifier = size_qual;

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/cache/index%d/coherency_line_size", core_idx, lvl);
        int coherency_line_size = get_hw_resource(filename, /*count=*/false, NULL, NULL);
        if (coherency_line_size < 0)
            goto out_cache;
        core_cache[lvl].coherency_line_size = coherency_line_size;

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/cache/index%d/number_of_sets", core_idx, lvl);
        int num_sets = get_hw_resource(filename, /*count=*/false, NULL, NULL);
        if (num_sets < 0)
            goto out_cache;
        core_cache[lvl].number_of_sets = num_sets;

        snprintf(filename, sizeof(filename),
            "/sys/devices/system/cpu/cpu%d/cache/index%d/physical_line_partition", core_idx, lvl);
        int physical_line_partition = get_hw_resource(filename, /*count=*/false, NULL, NULL);
        if (physical_line_partition < 0)
            goto out_cache;
        core_cache[lvl].physical_line_partition = physical_line_partition;

    }
    *cache_info = core_cache;
    return 0;

out_cache:
    free(core_cache);
    return ret;
}

/* Get core topology-related info */
static int get_core_topo_info(PAL_TOPO_INFO* topo_info) {
    int ret = get_hw_resource("/sys/devices/system/cpu/online", /*count=*/true,
                              &topo_info->online_logical_cores, NULL);
    if (ret < 0)
        return ret;

    ret = get_hw_resource("/sys/devices/system/cpu/possible", /*count=*/true,
                          &topo_info->possible_logical_cores, NULL);
    if (ret < 0)
        return ret;

    int online_logical_cores = topo_info->online_logical_cores.resource_count;
    int possible_logical_cores = topo_info->possible_logical_cores.resource_count;
    /* TODO: correctly support offline cores */
    if (possible_logical_cores > 0 && possible_logical_cores > online_logical_cores) {
         log_warning("some CPUs seem to be offline; Graphene doesn't take this into account which "
                     "may lead to subpar performance");
    }

    int num_cache_lvl = get_num_cache_level("/sys/devices/system/cpu/cpu0/cache");
    if (num_cache_lvl < 0)
        return num_cache_lvl;
    topo_info->num_cache_index = num_cache_lvl;

    PAL_CORE_TOPO_INFO* core_topology = (PAL_CORE_TOPO_INFO*)malloc(online_logical_cores *
                                                                    sizeof(PAL_CORE_TOPO_INFO));
    if (!core_topology)
        return -ENOMEM;

    int num_sockets = 0;
    int current_max_socket = -1;
    char filename[128];
    for (int idx = 0; idx < online_logical_cores; idx++) {
        /* cpu0 is always online and thus the "online" file is not present. */
        if (idx != 0) {
            snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/online", idx);
            ret = get_hw_resource(filename, /*count=*/false, NULL, NULL);
            if (ret < 0)
                goto out_topology;
            core_topology[idx].is_logical_core_online = ret;
        }

        snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/topology/core_id", idx);
        ret = get_hw_resource(filename, /*count=*/false, NULL, NULL);
        if (ret < 0)
            goto out_topology;
        core_topology[idx].core_id =  ret;

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/topology/core_siblings_list", idx);
        ret = get_hw_resource(filename, /*count=*/true, &core_topology[idx].core_siblings, NULL);
        if (ret < 0)
            goto out_topology;

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list", idx);
        ret = get_hw_resource(filename, /*count=*/true, &core_topology[idx].thread_siblings, NULL);
        if (ret < 0)
            goto out_topology;

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/topology/physical_package_id", idx);
        ret = get_hw_resource(filename, /*count=*/false, NULL, NULL);
        if (ret < 0)
            goto out_topology;
        core_topology[idx].cpu_socket =  ret;
        if (ret > current_max_socket) {
            current_max_socket = ret;
            num_sockets++;
        }

        ret = get_cache_topo_info(num_cache_lvl, idx, &core_topology[idx].cache);
        if (ret < 0)
            goto out_topology;
    }
    topo_info->core_topology = core_topology;
    topo_info->num_sockets = num_sockets;
    topo_info->physical_cores_per_socket = core_topology[0].core_siblings.resource_count /
                                           core_topology[0].thread_siblings.resource_count;
    return 0;

out_topology:
    free(core_topology);
    return ret;
}

/* Get NUMA topology-related info */
static int get_numa_topo_info(PAL_TOPO_INFO* topo_info) {
    int ret = get_hw_resource("/sys/devices/system/node/online", /*count=*/true,
                              &topo_info->nodes, NULL);
    if (ret < 0)
        return ret;

    int num_nodes = topo_info->nodes.resource_count;
    PAL_NUMA_TOPO_INFO* numa_topology = (PAL_NUMA_TOPO_INFO*)malloc(num_nodes *
                                                                    sizeof(PAL_NUMA_TOPO_INFO));
    if (!numa_topology)
        return -ENOMEM;

    char filename[128];
    for (int idx = 0; idx < num_nodes; idx++) {
        snprintf(filename, sizeof(filename), "/sys/devices/system/node/node%d/cpulist", idx);
        ret = get_hw_resource(filename, /*count=*/true, &numa_topology[idx].cpumap, NULL);
        if (ret < 0)
            goto out_topology;

        snprintf(filename, sizeof(filename), "/sys/devices/system/node/node%d/distance", idx);
        ret = get_hw_resource(filename, /*count=*/true, &numa_topology[idx].distance, NULL);
        if (ret < 0)
            goto out_topology;

        /* Since our /sys fs doesn't support writes, set persistent hugepages to their default value
         * of zero */
        numa_topology[idx].hugepages[HUGEPAGES_2M].nr_hugepages = 0;
        numa_topology[idx].hugepages[HUGEPAGES_1G].nr_hugepages = 0;
    }
    topo_info->numa_topology = numa_topology;
    return 0;

out_topology:
    free(numa_topology);
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
