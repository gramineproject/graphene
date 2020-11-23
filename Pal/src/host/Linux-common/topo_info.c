/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation */

/*
 * This file contains the APIs to expose host topology information.
 */

#include "topo_info.h"
#include "api.h"
#include "pal_linux.h"
#include <asm/errno.h>
#include <asm/fcntl.h>

/* Opens a pseudo-file describing HW resources such as online CPUs and counts the number of
 * HW resources present in the file (if count == true) or simply reads the integer stored in the
 * file (if count == false). For example on a single-core machine, calling this function on
 * `/sys/devices/system/cpu/online` with count == true will return 1 and 0 with count == false.
 * Returns UNIX error code on failure.
 * N.B: Understands complex formats like "1,3-5,6" when called with count == true.
 */
int get_hw_resource(const char* filename, bool count) {
    int fd = INLINE_SYSCALL(open, 3, filename, O_RDONLY | O_CLOEXEC, 0);
    if (IS_ERR(fd))
        return -ERRNO(fd);

    char buf[64];
    int ret = INLINE_SYSCALL(read, 3, fd, buf, sizeof(buf) - 1);
    INLINE_SYSCALL(close, 1, fd);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    buf[ret] = '\0'; /* ensure null-terminated buf even in partial read */

    char* end;
    char* ptr = buf;
    int resource_cnt = 0;
    int retval = -ENOENT;
    while (*ptr) {
        while (*ptr == ' ' || *ptr == '\t' || *ptr == ',')
            ptr++;

        int firstint = (int)strtol(ptr, &end, 10);
        if (ptr == end)
            break;

        /* caller wants to read an int stored in the file */
        if (!count) {
            if (*end == '\n' || *end == '\0')
                retval = firstint;
            return retval;
        }

        /* caller wants to count the number of HW resources */
        if (*end == '\0' || *end == ',' || *end == '\n') {
            /* single HW resource index, count as one more */
            resource_cnt++;
        } else if (*end == '-') {
            /* HW resource range, count how many HW resources are in range */
            ptr = end + 1;
            int secondint = (int)strtol(ptr, &end, 10);
            if (secondint > firstint)
                resource_cnt += secondint - firstint + 1; // inclusive (e.g., 0-7, or 8-16)
        }
        ptr = end;
    }

    if (count && resource_cnt > 0)
        retval = resource_cnt;

    return retval;
}

/* Reads up to count bytes from the file into the buf passed.
 * Returns 0 or number of bytes read on success and UNIX error code on failure. */
int read_file_buffer(const char* filename, char* buf, size_t count) {
    int fd = INLINE_SYSCALL(open, 2, filename, O_RDONLY);
    if (IS_ERR(fd))
        return -ERRNO(fd);

    int ret = INLINE_SYSCALL(read, 3, fd, buf, count);
    INLINE_SYSCALL(close, 1, fd);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    return ret;
}

/* Returns number of cache levels present on this system by counting "indexX" dir entries under
 * `/sys/devices/system/cpu/cpuX/cache` on success and UNIX error code on failure. */
static int get_num_cache_level(const char* path) {
    char buf[1024];
    int bpos;
    int nread;
    int num_dirs = 0;
    struct linux_dirent64* dirent64;

    int fd = INLINE_SYSCALL(open, 2, path, O_RDONLY | O_DIRECTORY);
    if (IS_ERR(fd))
        return -ERRNO(fd);

    while (true) {
        nread = INLINE_SYSCALL(getdents64, 3, fd, buf, 1024);
        if (IS_ERR(nread))
            return -ERRNO(nread);

        if (nread == 0)
            break;

        for (bpos = 0; bpos < nread;) {
            dirent64 = (struct linux_dirent64*)(buf + bpos);
            if (dirent64->d_type == DT_DIR && strncmp(dirent64->d_name, "index", 5) == 0)
                num_dirs++;
            bpos += dirent64->d_reclen;
        }
    }

    INLINE_SYSCALL(close, 1, fd);

    return num_dirs ? : -ENOENT;
}

/* Get core topology related info */
int get_core_topo_info(PAL_TOPO_INFO* topo_info) {
    int online_logical_cores = get_hw_resource("/sys/devices/system/cpu/online", /*count=*/true);
    if (online_logical_cores < 0)
        return online_logical_cores;

    int ret = read_file_buffer("/sys/devices/system/cpu/online", topo_info->online_logical_cores,
                               PAL_SYSFS_BUF_FILESZ);
    if (ret < 0)
        return ret;
    topo_info->online_logical_cores[ret] = '\0';

    ret = read_file_buffer("/sys/devices/system/cpu/possible", topo_info->possible_logical_cores,
                           PAL_SYSFS_BUF_FILESZ);
    if (ret < 0)
        return ret;
    topo_info->possible_logical_cores[ret] = '\0';

    int num_cache_lvl = get_num_cache_level("/sys/devices/system/cpu/cpu0/cache");
    if (num_cache_lvl < 0)
        return num_cache_lvl;
    topo_info->num_cache_index = num_cache_lvl;
    PAL_CORE_CACHE_INFO* core_cache;

    PAL_CORE_TOPO_INFO* core_topology = (PAL_CORE_TOPO_INFO*)malloc(online_logical_cores *
                                                                    sizeof(PAL_CORE_TOPO_INFO));
    if (!core_topology)
        return -ENOMEM;

    char filename[128];
    for (int idx = 0; idx < online_logical_cores; idx++) {
        /* cpu0 is always online and thus the "online" file is not present. */
        if (idx != 0) {
            snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/online", idx);
            ret = read_file_buffer(filename, core_topology[idx].is_logical_core_online,
                                   PAL_SYSFS_INT_FILESZ);
            if (ret < 0)
                goto out_topology;
            core_topology[idx].is_logical_core_online[ret] = '\0';
        }

        snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/topology/core_id", idx);
        ret = read_file_buffer(filename, core_topology[idx].core_id, PAL_SYSFS_INT_FILESZ);
        if (ret < 0)
            goto out_topology;
        core_topology[idx].core_id[ret] = '\0';

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/topology/core_siblings", idx);
        ret = read_file_buffer(filename, core_topology[idx].core_siblings, PAL_SYSFS_MAP_FILESZ);
        if (ret < 0)
            goto out_topology;
        core_topology[idx].core_siblings[ret] = '\0';

        snprintf(filename, sizeof(filename),
                 "/sys/devices/system/cpu/cpu%d/topology/thread_siblings", idx);
        ret = read_file_buffer(filename, core_topology[idx].thread_siblings, PAL_SYSFS_MAP_FILESZ);
        if (ret < 0)
            goto out_topology;
        core_topology[idx].thread_siblings[ret] = '\0';

        core_cache = (PAL_CORE_CACHE_INFO*)malloc(num_cache_lvl * sizeof(PAL_CORE_CACHE_INFO));
        if (!core_cache) {
            ret = -ENOMEM;
            goto out_topology;
        }

        for (int lvl = 0; lvl < num_cache_lvl; lvl++) {
            snprintf(filename, sizeof(filename),
                     "/sys/devices/system/cpu/cpu%d/cache/index%d/shared_cpu_map", idx, lvl);
            ret = read_file_buffer(filename, core_cache[lvl].shared_cpu_map, PAL_SYSFS_MAP_FILESZ);
            if (ret < 0)
                goto out_cache;
            core_cache[lvl].shared_cpu_map[ret] = '\0';

            snprintf(filename, sizeof(filename),
                     "/sys/devices/system/cpu/cpu%d/cache/index%d/level", idx, lvl);
            ret = read_file_buffer(filename, core_cache[lvl].level, PAL_SYSFS_INT_FILESZ);
            if (ret < 0)
                goto out_cache;
            core_cache[lvl].level[ret] = '\0';

            snprintf(filename, sizeof(filename),
                     "/sys/devices/system/cpu/cpu%d/cache/index%d/type", idx, lvl);
            ret = read_file_buffer(filename, core_cache[lvl].type, PAL_SYSFS_BUF_FILESZ);
            if (ret < 0)
                goto out_cache;
            core_cache[lvl].type[ret] = '\0';

            snprintf(filename, sizeof(filename),
                     "/sys/devices/system/cpu/cpu%d/cache/index%d/size", idx, lvl);
            ret = read_file_buffer(filename, core_cache[lvl].size, PAL_SYSFS_BUF_FILESZ);
            if (ret < 0)
                goto out_cache;
            core_cache[lvl].size[ret] = '\0';

            snprintf(filename, sizeof(filename),
                     "/sys/devices/system/cpu/cpu%d/cache/index%d/coherency_line_size", idx, lvl);
            ret = read_file_buffer(filename, core_cache[lvl].coherency_line_size,
                                   PAL_SYSFS_INT_FILESZ);
            if (ret < 0)
                goto out_cache;
            core_cache[lvl].coherency_line_size[ret] = '\0';

            snprintf(filename, sizeof(filename),
                     "/sys/devices/system/cpu/cpu%d/cache/index%d/number_of_sets", idx, lvl);
            ret = read_file_buffer(filename, core_cache[lvl].number_of_sets, PAL_SYSFS_INT_FILESZ);
            if (ret < 0)
                goto out_cache;
            core_cache[lvl].number_of_sets[ret] = '\0';

            snprintf(filename, sizeof(filename),
                     "/sys/devices/system/cpu/cpu%d/cache/index%d/physical_line_partition", idx,
                     lvl);
            ret = read_file_buffer(filename, core_cache[lvl].physical_line_partition,
                                   PAL_SYSFS_INT_FILESZ);
            if (ret < 0)
                goto out_cache;
            core_cache[lvl].physical_line_partition[ret] = '\0';
        }
        core_topology[idx].cache = core_cache;
    }
    topo_info->core_topology = core_topology;
    return 0;

out_cache:
    free(core_cache);
out_topology:
    free(core_topology);
    return ret;
}

/* Get NUMA topology related info */
int get_numa_topo_info(PAL_TOPO_INFO* topo_info) {
    int ret = read_file_buffer("/sys/devices/system/node/online", topo_info->online_nodes,
                               PAL_SYSFS_BUF_FILESZ);
    if (ret < 0)
        return ret;
    topo_info->online_nodes[ret] = '\0';

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
        ret = read_file_buffer(filename, numa_topology[idx].cpumap, PAL_SYSFS_MAP_FILESZ);
        if (ret < 0)
            goto out_topology;
        numa_topology[idx].cpumap[ret] = '\0';

        snprintf(filename, sizeof(filename), "/sys/devices/system/node/node%d/distance", idx);
        ret = read_file_buffer(filename, numa_topology[idx].distance, PAL_SYSFS_INT_FILESZ);
        if (ret < 0)
            goto out_topology;
        numa_topology[idx].distance[ret] = '\0';

        /* Set persistent hugepages to zero. /sys fs doesn't provide write permission to modify the
         * field */
        memcpy(numa_topology[idx].hugepages[HUGEPAGES_2M].nr_hugepages, "0\n", 3);
        memcpy(numa_topology[idx].hugepages[HUGEPAGES_1G].nr_hugepages, "0\n", 3);
    }
    topo_info->numa_topology = numa_topology;
    return 0;

out_topology:
    free(numa_topology);
    return ret;
}
