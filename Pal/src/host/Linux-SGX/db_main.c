/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

/*
 * This file contains the main function of the PAL loader, which loads and processes environment,
 * arguments and manifest.
 */

#include <asm/errno.h>
#include <asm/ioctls.h>
#include <asm/mman.h>
#include <stdint.h>
#include <stdnoreturn.h>

#include "api.h"
#include "ecall_types.h"
#include "elf/elf.h"
#include "enclave_pages.h"
#include "enclave_pf.h"
#include "enclave_tf.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_security.h"
#include "protected_files.h"
#include "sysdeps/generic/ldsodefs.h"
#include "toml.h"

#define RTLD_BOOTSTRAP
#define _ENTRY enclave_entry

struct pal_linux_state g_linux_state;
struct pal_sec g_pal_sec;

PAL_SESSION_KEY g_master_key = {0};

/* for internal PAL objects, Graphene first uses pre-allocated g_mem_pool and then falls back to
 * _DkVirtualMemoryAlloc(PAL_ALLOC_INTERNAL); the amount of available PAL internal memory is
 * limited by the variable below */
size_t g_pal_internal_mem_size = 0;

const size_t g_page_size = PRESET_PAGESIZE;

void _DkGetAvailableUserAddressRange(PAL_PTR* start, PAL_PTR* end) {
    *start = (PAL_PTR)g_pal_sec.heap_min;
    *end   = (PAL_PTR)get_enclave_heap_top();

    /* Keep some heap for internal PAL objects allocated at runtime (recall that LibOS does not keep
     * track of PAL memory, so without this limit it could overwrite internal PAL memory). This
     * relies on the fact that our memory management allocates memory from higher addresses to lower
     * addresses (see also enclave_pages.c). */
    *end = SATURATED_P_SUB(*end, g_pal_internal_mem_size, *start);

    if (*end <= *start) {
        log_error("Not enough enclave memory, please increase enclave size!");
        ocall_exit(1, /*is_exitgroup=*/true);
    }
}

#include "dynamic_link.h"
#include "elf-x86_64.h"

static struct link_map g_pal_map;

/*
 * Takes a pointer+size to an untrusted memory region containing a
 * NUL-separated list of strings. It builds an argv-style list in trusted memory
 * with those strings.
 *
 * It is responsible for handling the access to untrusted memory safely
 * (returns NULL on error) and ensures that all strings are properly
 * terminated. The content of the strings is NOT further sanitized.
 *
 * The argv-style list is allocated on the heap and the caller is responsible
 * to free it (For argv and envp we rely on auto free on termination in
 * practice).
 */
static const char** make_argv_list(void* uptr_src, size_t src_size) {
    const char** argv;

    if (src_size == 0) {
        argv = malloc(sizeof(char*));
        if (argv)
            argv[0] = NULL;
        return argv;
    }

    char* data = malloc(src_size);
    if (!data) {
        return NULL;
    }

    if (!sgx_copy_to_enclave(data, src_size, uptr_src, src_size)) {
        goto fail;
    }
    data[src_size - 1] = '\0';

    size_t argc = 0;
    for (size_t i = 0; i < src_size; i++) {
        if (data[i] == '\0') {
            argc++;
        }
    }

    size_t argv_size;
    if (__builtin_mul_overflow(argc + 1, sizeof(char*), &argv_size)) {
        goto fail;
    }
    argv = malloc(argv_size);
    if (!argv) {
        goto fail;
    }
    argv[argc] = NULL;

    size_t data_i = 0;
    for (size_t arg_i = 0; arg_i < argc; arg_i++) {
        argv[arg_i] = &data[data_i];
        while (data[data_i] != '\0') {
            data_i++;
        }
        data_i++;
    }

    return argv;

fail:
    free(data);
    return NULL;
}

static int copy_hw_resource_range(PAL_RES_RANGE_INFO* src, PAL_RES_RANGE_INFO* dest) {
    uint64_t range_cnt = src->range_count;
    PAL_RANGE_INFO* ranges = (PAL_RANGE_INFO*)malloc(range_cnt * sizeof(PAL_RANGE_INFO));
    if (!ranges) {
        log_error("Range allocation failed");
        return -1;
    }

    if (!sgx_copy_to_enclave(ranges, range_cnt * sizeof(PAL_RANGE_INFO), src->ranges,
                             range_cnt * sizeof(PAL_RANGE_INFO))) {
        log_error("Copying ranges into the enclave failed");
        return -1;
    }

    dest->ranges = ranges;
    dest->range_count = range_cnt;
    dest->resource_count = src->resource_count;
    return 0;
}

/* All sanitization functions below do not free memory.  We simply exit on failure. */

/* This function does the following 3 sanitizations for a given resource range:
 * 1. Ensures the resource as well as range count doesn't exceed limits.
 * 2. Ensures that ranges don't overlap like "1-5, 3-4".
 * 3. Ensures the ranges aren't malformed like "1-5, 7-1".
 * Returns -1 error on failure and 0 on success.
 */
static int sanitize_hw_resource_range(PAL_RES_RANGE_INFO res_info, int64_t res_min_limit,
                                      int64_t res_max_limit, int64_t range_min_limit,
                                      int64_t range_max_limit) {
    if (res_info.resource_count > INT64_MAX)
        return -1;
    int64_t resource_count = (int64_t)res_info.resource_count;
    if (!IS_IN_RANGE_INCL(resource_count, res_min_limit, res_max_limit)) {
        log_error("Invalid resource count: %ld", resource_count);
        return -1;
    }

    if (res_info.range_count > INT64_MAX)
        return -1;
    int64_t range_count = (int64_t)res_info.range_count;
    if (!IS_IN_RANGE_INCL(range_count, 1, 1 << 7)) {
        log_error("Invalid range count: %ld\n", range_count);
        return -1;
    }

    if (!res_info.ranges)
        return -1;

    int64_t previous_end = -1;
    for (int64_t i = 0; i < range_count; i++) {
        if (res_info.ranges[i].start > INT64_MAX)
            return -1;
        int64_t start = (int64_t)res_info.ranges[i].start;

        if (res_info.ranges[i].end > INT64_MAX)
            return -1;
        int64_t end = (int64_t)res_info.ranges[i].end;

        /* Ensure start and end fall within the max_limit value */
        if (!IS_IN_RANGE_INCL(start, range_min_limit, range_max_limit)) {
            log_error("Invalid start range: %ld", start);
            return -1;
        }

        if ((start != end) && !IS_IN_RANGE_INCL(end, start + 1, range_max_limit)) {
            log_error("Invalid end range: %ld", end);
            return -1;
        }

        /* check for malformed ranges */
        if (previous_end >= end) {
            log_error("Malformed range: previous_end = %ld, current end = %ld", previous_end, end);
            return -1;
        }
        previous_end = end;
    }

    return 0;
}

static int sanitize_cache_topology_info(PAL_CORE_CACHE_INFO* cache, int64_t cache_lvls,
                                        int64_t num_cores) {
    for (int64_t lvl = 0; lvl < cache_lvls; lvl++) {
        if (cache[lvl].type != CACHE_TYPE_DATA && cache[lvl].type != CACHE_TYPE_INSTRUCTION  &&
            cache[lvl].type != CACHE_TYPE_UNIFIED) {
            return -1;
        }

        int64_t max_limit;
        if (cache[lvl].type == CACHE_TYPE_DATA || cache[lvl].type == CACHE_TYPE_INSTRUCTION) {
            max_limit = 2; /* Taking HT into account */
        } else {
            /* if unified cache then it can range upto total number of cores. */
            max_limit = num_cores;
        }
        int64_t shared_cpu_map = sanitize_hw_resource_range(cache[lvl].shared_cpu_map, 1, max_limit,
                                                            0, num_cores);
        if (shared_cpu_map < 0) {
            log_error("Invalid cache[%ld].shared_cpu_map", lvl);
            return -1;
        }

        if (cache[lvl].level > INT64_MAX)
            return -1;
        int64_t level = (int64_t)cache[lvl].level;
        if (!IS_IN_RANGE_INCL(level, 1, 3))      /* x86 processors have max of 3 cache levels */
            return -1;

        if (cache[lvl].size_multiplier != MULTIPLIER_KB &&
            cache[lvl].size_multiplier != MULTIPLIER_MB &&
            cache[lvl].size_multiplier != MULTIPLIER_GB &&
            cache[lvl].size_multiplier != MULTIPLIER_NONE) {
            return -1;
        }

        int64_t multiplier =1;
        if (cache[lvl].size_multiplier == MULTIPLIER_KB)
            multiplier = 1024;
        else if (cache[lvl].size_multiplier == MULTIPLIER_MB)
            multiplier = 1024 * 1024;
        else if (cache[lvl].size_multiplier == MULTIPLIER_GB)
            multiplier = 1024 * 1024 * 1024;

        if (cache[lvl].size > INT64_MAX)
            return -1;
        int64_t cache_size;
        if (__builtin_mul_overflow(cache[lvl].size, multiplier, &cache_size))
            return -1;

        if (!IS_IN_RANGE_INCL(cache_size, 1, 1 << 30))
            return -1;

        if (cache[lvl].coherency_line_size > INT64_MAX)
            return -1;
        int64_t coherency_line_size = (int64_t)cache[lvl].coherency_line_size;
        if (!IS_IN_RANGE_INCL(coherency_line_size, 1, 1 << 16))
            return -1;

        if (cache[lvl].number_of_sets > INT64_MAX)
            return -1;
        int64_t number_of_sets = (int64_t)cache[lvl].number_of_sets;
        if (!IS_IN_RANGE_INCL(number_of_sets, 1, 1 << 30))
            return -1;

        if (cache[lvl].physical_line_partition > INT64_MAX)
            return -1;
        int64_t physical_line_partition = (int64_t)cache[lvl].physical_line_partition;
        if (!IS_IN_RANGE_INCL(physical_line_partition, 1, 1 << 16))
            return -1;
    }
    return 0;
}

static int sanitize_core_topology_info(PAL_CORE_TOPO_INFO* core_topology, int64_t num_cores,
                                       int64_t cache_lvls) {
    if (num_cores == 0 || cache_lvls == 0)
        return -1;

    for (int64_t idx = 0; idx < num_cores; idx++) {
        if (idx != 0) {     /* core 0 is always online */
            if (core_topology[idx].is_logical_core_online > INT64_MAX)
                return -1;

            int64_t is_core_online = core_topology[idx].is_logical_core_online;
            if (is_core_online != 0 && is_core_online != 1)
                return -1;
        }

        if (core_topology[idx].core_id > INT64_MAX)
            return -1;
        int64_t core_id = (int64_t)core_topology[idx].core_id;
        if (!IS_IN_RANGE_INCL(core_id, 0, num_cores - 1))
            return -1;

        int64_t core_siblings = sanitize_hw_resource_range(core_topology[idx].core_siblings, 1,
                                                           num_cores, 0, num_cores);
        if (core_siblings < 0) {
            log_error("Invalid core_topology[%ld].core_siblings", idx);
            return -1;
        }

        /* Max. SMT siblings currently supported on x86 processors is 4 */
        int64_t thread_siblings = sanitize_hw_resource_range(core_topology[idx].thread_siblings, 1,
                                                             4, 0, num_cores);
        if (thread_siblings < 0) {
            log_error("Invalid core_topology[%ld].thread_siblings", idx);
            return -1;
        }

        if (sanitize_cache_topology_info(core_topology[idx].cache, cache_lvls, num_cores) < 0)
            return -1;
    }
    return 0;
}

static int sanitize_socket_info(PAL_TOPO_INFO topo_info) {
    int ret = 0;
    int64_t prev_socket = -1;

    int64_t num_sockets = (int64_t)topo_info.num_sockets;
    PAL_RES_RANGE_INFO * socket_info =
        (PAL_RES_RANGE_INFO*)calloc(num_sockets, sizeof(PAL_RES_RANGE_INFO ));
    if (!socket_info)
        return -1;

    int64_t num_cores = topo_info.online_logical_cores.resource_count;
    for (int64_t idx = 0; idx < num_cores; idx++) {
        if (topo_info.core_topology[idx].cpu_socket > INT64_MAX)
            return -1;

        int64_t socket = (int64_t)topo_info.core_topology[idx].cpu_socket;
        if (!IS_IN_RANGE_INCL(socket, 0, num_sockets - 1)) {
            ret = -1;
            goto out_socket;
        }

        /* Extract cores that are part of each socket to validate against core_siblings.
         * Note: Although a clever attacker might modify both of these values, idea here is to
         * provide a consistent view of the topology. */
        if (socket != prev_socket) {
            socket_info[socket].range_count++;
            size_t new_sz = sizeof(PAL_RANGE_INFO) * socket_info[socket].range_count;
            size_t old_sz = new_sz - sizeof(PAL_RANGE_INFO);
            socket_info[socket].ranges = realloc_size(socket_info[socket].ranges, old_sz, new_sz);
            if (!socket_info->ranges) {
                ret = -1;
                goto out_socket;
            }

            int64_t range_idx = socket_info[socket].range_count - 1;
            socket_info[socket].ranges[range_idx].start = idx;
            socket_info[socket].ranges[range_idx].end = UINT64_MAX;
            prev_socket = socket;
        } else {
            int64_t range_idx = socket_info[socket].range_count - 1;
            socket_info[socket].ranges[range_idx].end = idx;
        }
    }

    /* core-siblings represent all the cores that are part of a socket. We cross-verify the
     * socket info against this. */
    for (int64_t idx = 0; idx < num_sockets; idx++) {
        if (!socket_info[idx].range_count || !socket_info[idx].ranges) {
            ret = -1;
            goto out_socket;
        }

        uint64_t core_in_socket =  socket_info[idx].ranges[0].start;
        uint64_t core_sibling_cnt = topo_info.core_topology[core_in_socket].core_siblings.range_count;

        if (core_sibling_cnt != socket_info[idx].range_count) {
            ret = -1;
            goto out_socket;
        }

        PAL_RANGE_INFO* core_sibling_ranges =
                                    topo_info.core_topology[core_in_socket].core_siblings.ranges;
        for (uint64_t j = 0; j < core_sibling_cnt; j++) {
            if (socket_info[idx].ranges[j].start != core_sibling_ranges[j].start ||
                socket_info[idx].ranges[j].end != core_sibling_ranges[j].end) {
                ret = -1;
                goto out_socket;
            }
        }
    }

out_socket:
    for (int64_t i = 0 ; i < num_sockets; i++) {
        if (socket_info[i].ranges)
            free(socket_info[i].ranges);
    }
    free(socket_info);
    return ret;
}

static int sanitize_numa_topology_info(PAL_NUMA_TOPO_INFO* numa_topology, int64_t num_nodes,
                                       int64_t num_cores, int64_t possible_cores) {
    int ret = 0;
    int64_t num_cpumask = BITS_TO_INTS(possible_cores);
    unsigned int* bitmap = (unsigned int*)calloc(num_cpumask, sizeof(unsigned int));
    if (!bitmap)
        return -1;

    int64_t total_cores_in_numa = 0;
    for (int64_t idx = 0; idx < num_nodes; idx++) {
        ret = sanitize_hw_resource_range(numa_topology[idx].cpumap, 1, num_cores, 0, num_cores);
        if (ret < 0) {
            log_error("Invalid numa_topology[%ld].cpumap", idx);
            goto out_numa;
        }

        /* Ensure that each NUMA has unique cores */
        for (int64_t i = 0; i < (int64_t)numa_topology[idx].cpumap.range_count; i++) {
            uint64_t start = numa_topology[idx].cpumap.ranges[i].start;
            uint64_t end = numa_topology[idx].cpumap.ranges[i].end;
            for (int64_t j = (int64_t)start; j <= (int64_t)end; j++) {
                int64_t index = j / (sizeof(int) * BITS_IN_BYTE);
                if (index >= num_cpumask) {
                    ret = -1;
                    goto out_numa;
                }
                if (bitmap[index] >> (j % (sizeof(int) * BITS_IN_BYTE)) == 1) {
                    log_error("Invalid numa_topology: Core %ld found in multiple numa nodes", j);
                    ret = -1;
                    goto out_numa;
                }
                bitmap[index] |= 1U << (j % (sizeof(int) * BITS_IN_BYTE));
                total_cores_in_numa++;
            }
        }

        int distances = numa_topology[idx].distance.resource_count;
        if (distances != num_nodes) {
            log_error("Invalid numa_topology[%ld].distance", idx);
            ret = -1;
            goto out_numa;
        }
    }

    if (total_cores_in_numa != num_cores) {
        log_error("Invalid numa_topology: more cores in NUMA than online");
        ret = -1;
        goto out_numa;
    }

out_numa:
    free(bitmap);
    return ret;
}

static int sgx_copy_core_topo_to_enclave(PAL_CORE_TOPO_INFO* src, int64_t online_logical_cores,
                                         int64_t num_cache_index) {
    PAL_CORE_TOPO_INFO* core_topo = (PAL_CORE_TOPO_INFO*)malloc(online_logical_cores *
                                                                    sizeof(PAL_CORE_TOPO_INFO));
    if (!core_topo) {
        log_error("Allocation for core topology failed");
        return -1;
    }

    for (int64_t idx = 0; idx < online_logical_cores; idx++) {
        core_topo[idx].is_logical_core_online = src[idx].is_logical_core_online;
        core_topo[idx].core_id = src[idx].core_id;
        core_topo[idx].cpu_socket = src[idx].cpu_socket;

        int ret  = copy_hw_resource_range(&src[idx].core_siblings, &core_topo[idx].core_siblings);
        if (ret < 0) {
            log_error("Copying core_topo[%ld].core_siblings failed", idx);
            return -1;
        }

        ret  = copy_hw_resource_range(&src[idx].thread_siblings, &core_topo[idx].thread_siblings);
        if (ret < 0) {
            log_error("Copying core_topo[%ld].core_siblings failed", idx);
            return -1;
        }

        /* Allocate enclave memory to store cache info */
        PAL_CORE_CACHE_INFO* cache_info = (PAL_CORE_CACHE_INFO*)malloc(num_cache_index *
                                                                    sizeof(PAL_CORE_CACHE_INFO));
        if (!cache_info) {
            log_error("Allocation for cache_info failed");
            return -1;
        }

        for (int64_t lvl = 0; lvl < num_cache_index; lvl++) {
            cache_info[lvl].level = src[idx].cache[lvl].level;
            cache_info[lvl].type = src[idx].cache[lvl].type;
            cache_info[lvl].size = src[idx].cache[lvl].size;
            cache_info[lvl].size_multiplier = src[idx].cache[lvl].size_multiplier;
            cache_info[lvl].coherency_line_size = src[idx].cache[lvl].coherency_line_size;
            cache_info[lvl].number_of_sets = src[idx].cache[lvl].number_of_sets;
            cache_info[lvl].physical_line_partition = src[idx].cache[lvl].physical_line_partition;

            ret  = copy_hw_resource_range(&src[idx].cache[lvl].shared_cpu_map,
                                          &cache_info[lvl].shared_cpu_map);
            if (ret < 0) {
                log_error("Copying core_topo[%ld].cache[%ld].shared_cpu_map failed", idx, lvl);
                return -1;
            }
        }
        core_topo[idx].cache = cache_info;
    }
    g_pal_sec.topo_info.core_topology = core_topo;

    return 0;
}

static int sgx_copy_numa_topo_to_enclave(PAL_NUMA_TOPO_INFO* src, int64_t num_online_nodes) {
    PAL_NUMA_TOPO_INFO* numa_topo = (PAL_NUMA_TOPO_INFO*)malloc(num_online_nodes *
                                                                sizeof(PAL_NUMA_TOPO_INFO));
    if (!numa_topo) {
        log_error("Allocation for numa topology failed");
        return -1;
    }

    for (int64_t idx = 0; idx < num_online_nodes; idx++) {
        numa_topo[idx].nr_hugepages[HUGEPAGES_2M] = src[idx].nr_hugepages[HUGEPAGES_2M];
        numa_topo[idx].nr_hugepages[HUGEPAGES_1G] = src[idx].nr_hugepages[HUGEPAGES_1G];

        int ret  = copy_hw_resource_range(&src[idx].cpumap, &numa_topo[idx].cpumap);
        if (ret < 0) {
            log_error("Copying numa_topo[%ld].core_siblings failed", idx);
            return -1;
        }

        ret  = copy_hw_resource_range(&src[idx].distance, &numa_topo[idx].distance);
        if (ret < 0) {
            log_error("Copying numa_topo[%ld].core_siblings failed", idx);
            return -1;
        }
    }
    g_pal_sec.topo_info.numa_topology = numa_topo;

    return 0;
}

/* This function doesn't clean up resources on failure, assuming that we terminate right away in
 * such case. */
static int parse_host_topo_info(PAL_TOPO_INFO topo_info) {
    int ret = sanitize_hw_resource_range(topo_info.online_logical_cores, 1, 1 << 16, 0, 1 << 16);
    if (ret < 0) {
        log_error("Invalid sec_info.topo_info.online_logical_cores");
        return -1;
    }
    ret  = copy_hw_resource_range(&topo_info.online_logical_cores,
                                  &g_pal_sec.topo_info.online_logical_cores);
    if (ret < 0) {
        log_error("Copying sec_info.topo_info.online_logical_cores failed");
        return -1;
    }

    ret = sanitize_hw_resource_range(topo_info.possible_logical_cores, 1, 1 << 16, 0, 1 << 16);
    if (ret < 0) {
        log_error("Invalid sec_info.topo_info.possible_logical_cores");
        return -1;
    }
    ret  = copy_hw_resource_range(&topo_info.possible_logical_cores,
                                  &g_pal_sec.topo_info.possible_logical_cores);
    if (ret < 0) {
        log_error("Copying sec_info.topo_info.possible_logical_cores failed");
        return -1;
    }

    ret = sanitize_hw_resource_range(topo_info.nodes, 1, 1 << 16, 0, 1 << 16);
    if (ret < 0) {
        log_error("Invalid sec_info.topo_info.nodes");
        return -1;
    }
    ret = copy_hw_resource_range(&topo_info.nodes, &g_pal_sec.topo_info.nodes);
    if (ret < 0) {
        log_error("Copying sec_info.topo_info.nodes failed");
        return -1;
    }

    if (topo_info.num_cache_index > INT64_MAX)
        return -1;
    int64_t num_cache_index = (int64_t)topo_info.num_cache_index;
    if (!IS_IN_RANGE_INCL(num_cache_index, 1, 1 << 4)) {
        log_error("Invalid sec_info.topo_info.num_cache_index: %ld", num_cache_index);
        return -1;
    }
    g_pal_sec.topo_info.num_cache_index = num_cache_index;

    /* Sanitize core topology information */
    int64_t online_logical_cores = g_pal_sec.topo_info.online_logical_cores.resource_count;
    ret = sanitize_core_topology_info(topo_info.core_topology, online_logical_cores,
                                      num_cache_index);
    if (ret < 0) {
        log_error("Sanitization of core_topology failed");
        return -1;
    }

    /* Allocate enclave memory to store core topology info */
    ret = sgx_copy_core_topo_to_enclave(topo_info.core_topology, online_logical_cores,
                                        num_cache_index);
    if (ret < 0) {
        log_error("Copying core_topology into the enclave failed");
        return -1;
    }

    if (!IS_IN_RANGE_INCL(topo_info.physical_cores_per_socket, 1, 1 << 13)) {
        log_error("Invalid sec_info.physical_cores_per_socket: %ld",
                  topo_info.physical_cores_per_socket);
        return -1;
    }
    g_pal_sec.topo_info.physical_cores_per_socket = topo_info.physical_cores_per_socket;

    if (topo_info.num_sockets > INT64_MAX)
        return -1;
    int64_t num_sockets = (int64_t)topo_info.num_sockets;
    /* Virtual environments such as QEMU may assign each core to a separate socket/package with
     * one or more NUMA nodes. So we check against the number of online logical cores. */
    if (!IS_IN_RANGE_INCL(num_sockets, 1, online_logical_cores)) {
        log_error("Invalid sec_info.topo_info.num_cache_index: %ld", num_cache_index);
        return -1;
    }
    g_pal_sec.topo_info.num_sockets = num_sockets;

    /* Sanitize logical core -> socket mappings */
    ret = sanitize_socket_info(topo_info);
    if (ret < 0) {
        log_error("Sanitization of logical core -> socket mappings failed");
        return -1;
    }

    /* Sanitize numa topology information */
    int64_t possible_cores = g_pal_sec.topo_info.possible_logical_cores.resource_count;
    int64_t num_online_nodes = g_pal_sec.topo_info.nodes.resource_count;
    ret = sanitize_numa_topology_info(topo_info.numa_topology, num_online_nodes,
                                      online_logical_cores, possible_cores);
    if (ret < 0) {
        log_error("Sanitization of numa_topology failed");
        return -1;
    }

    /* Allocate enclave memory to store numa topology info */
    ret = sgx_copy_numa_topo_to_enclave(topo_info.numa_topology, num_online_nodes);
    if (ret < 0) {
        log_error("Copying numa_topology into the enclave failed");
        return -1;
    }

    return 0;
}

extern void* g_enclave_base;
extern void* g_enclave_top;

/* Graphene uses GCC's stack protector that looks for a canary at gs:[0x8], but this function starts
 * with a default canary and then updates it to a random one, so we disable stack protector here */
__attribute_no_stack_protector
noreturn void pal_linux_main(char* uptr_libpal_uri, size_t libpal_uri_len, char* uptr_args,
                             size_t args_size, char* uptr_env, size_t env_size,
                             struct pal_sec* uptr_sec_info) {
    /* Our arguments are coming directly from the urts. We are responsible to check them. */
    int ret;

    /* Relocate PAL itself (note that this is required to run `log_error`) */
    g_pal_map.l_addr = elf_machine_load_address();
    g_pal_map.l_name = "libpal.so"; // to be overriden later
    elf_get_dynamic_info((void*)g_pal_map.l_addr + elf_machine_dynamic(), g_pal_map.l_info,
                         g_pal_map.l_addr);

    ELF_DYNAMIC_RELOCATE(&g_pal_map);

    uint64_t start_time;
    ret = _DkSystemTimeQuery(&start_time);
    if (ret < 0) {
        log_error("_DkSystemTimeQuery() failed: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    /* Initialize alloc_align as early as possible, a lot of PAL APIs depend on this being set. */
    g_pal_state.alloc_align = g_page_size;
    assert(IS_POWER_OF_2(g_pal_state.alloc_align));

    struct pal_sec sec_info;
    if (!sgx_copy_to_enclave(&sec_info, sizeof(sec_info), uptr_sec_info, sizeof(*uptr_sec_info))) {
        log_error("Copying sec_info into the enclave failed");
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    g_pal_sec.heap_min = GET_ENCLAVE_TLS(heap_min);
    g_pal_sec.heap_max = GET_ENCLAVE_TLS(heap_max);

    /* Skip URI_PREFIX_FILE. */
    if (libpal_uri_len < URI_PREFIX_FILE_LEN) {
        log_error("Invalid libpal_uri length (missing \"%s\" prefix?)", URI_PREFIX_FILE);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    libpal_uri_len -= URI_PREFIX_FILE_LEN;
    uptr_libpal_uri += URI_PREFIX_FILE_LEN;

    /* At this point we don't yet have memory manager, so we cannot allocate memory dynamically. */
    static char libpal_path[1024 + 1];
    if (libpal_uri_len >= sizeof(libpal_path)
            || !sgx_copy_to_enclave(libpal_path, sizeof(libpal_path) - 1, uptr_libpal_uri,
                                    libpal_uri_len)) {
        log_error("Copying libpal_path into the enclave failed");
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    libpal_path[libpal_uri_len] = '\0';

    /* Now that we have `libpal_path`, set name for PAL map */
    g_pal_map.l_name = libpal_path;

    /*
     * We can't verify the following arguments from the urts. So we copy
     * them directly but need to be careful when we use them.
     */

    g_pal_sec.stream_fd = sec_info.stream_fd;

    g_pal_sec.qe_targetinfo = sec_info.qe_targetinfo;
#ifdef DEBUG
    g_pal_sec.in_gdb = sec_info.in_gdb;
#endif

    /* For {p,u,g}ids we can at least do some minimal checking. */

    /* pid should be positive when interpreted as signed. */
    if (sec_info.pid > INT32_MAX || sec_info.pid == 0) {
        log_error("Invalid sec_info.pid: %u", sec_info.pid);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    g_pal_sec.pid = sec_info.pid;

    /* -1 is treated as special value for example by chown. */
    if (sec_info.uid == (PAL_IDX)-1 || sec_info.gid == (PAL_IDX)-1) {
        log_error("Invalid sec_info.gid: %u", sec_info.gid);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    g_pal_sec.uid = sec_info.uid;
    g_pal_sec.gid = sec_info.gid;

    /* set up page allocator and slab manager */
    init_slab_mgr(g_page_size);
    init_untrusted_slab_mgr();
    init_enclave_pages();
    init_cpuid();

    /* now we can add a link map for PAL itself */
    setup_pal_map(&g_pal_map);

    /* initialize enclave properties */
    ret = init_enclave();
    if (ret) {
        log_error("Failed to initialize enclave properties: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    if (args_size > MAX_ARGS_SIZE || env_size > MAX_ENV_SIZE) {
        log_error("Invalid args_size (%lu) or env_size (%lu)", args_size, env_size);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    const char** arguments = make_argv_list(uptr_args, args_size);
    if (!arguments) {
        log_error("Creating arguments failed");
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    const char** environments = make_argv_list(uptr_env, env_size);
    if (!environments) {
        log_error("Creating environments failed");
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    g_linux_state.uid = g_pal_sec.uid;
    g_linux_state.gid = g_pal_sec.gid;

    SET_ENCLAVE_TLS(ready_for_exceptions, 1UL);

    /* initialize "Invariant TSC" HW feature for fast and accurate gettime and immediately probe
     * RDTSC instruction inside SGX enclave (via dummy get_tsc) -- it is possible that
     * the CPU supports invariant TSC but doesn't support executing RDTSC inside SGX enclave, in
     * this case the SIGILL exception is generated and leads to emulate_rdtsc_and_print_warning()
     * which unsets invariant TSC, and we end up falling back to the slower ocall_gettime() */
    init_tsc();
    (void)get_tsc(); /* must be after `ready_for_exceptions=1` since it may generate SIGILL */

    /* Now that enclave memory is set up, parse and store host topology info into g_pal_sec struct */
    ret = parse_host_topo_info(sec_info.topo_info);
    if (ret < 0)
        ocall_exit(1, /*is_exitgroup=*/true);

    /* initialize master key (used for pipes' encryption for all enclaves of an application); it
     * will be overwritten below in init_child_process() with inherited-from-parent master key if
     * this enclave is child */
    ret = _DkRandomBitsRead(&g_master_key, sizeof(g_master_key));
    if (ret < 0) {
        log_error("_DkRandomBitsRead failed: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    /* if there is a parent, create parent handle */
    PAL_HANDLE parent = NULL;
    uint64_t instance_id = 0;
    if (g_pal_sec.stream_fd != PAL_IDX_POISON) {
        if ((ret = init_child_process(&parent, &instance_id)) < 0) {
            log_error("Failed to initialize child process: %d", ret);
            ocall_exit(1, /*is_exitgroup=*/true);
        }
    }

    uint64_t manifest_size = GET_ENCLAVE_TLS(manifest_size);
    void* manifest_addr = g_enclave_top - ALIGN_UP_PTR_POW2(manifest_size, g_page_size);

    ret = add_preloaded_range((uintptr_t)manifest_addr, (uintptr_t)manifest_addr + manifest_size,
                              "manifest");
    if (ret < 0) {
        log_error("Failed to initialize manifest preload range: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }

    /* parse manifest */
    char errbuf[256];
    toml_table_t* manifest_root = toml_parse(manifest_addr, errbuf, sizeof(errbuf));
    if (!manifest_root) {
        log_error("PAL failed at parsing the manifest: %s", errbuf);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    g_pal_state.raw_manifest_data = manifest_addr;
    g_pal_state.manifest_root = manifest_root;

    bool preheat_enclave;
    ret = toml_bool_in(g_pal_state.manifest_root, "sgx.preheat_enclave", /*defaultval=*/false,
                       &preheat_enclave);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.preheat_enclave' (the value must be `true` or `false`)");
        ocall_exit(1, true);
    }
    if (preheat_enclave) {
        for (uint8_t* i = g_pal_sec.heap_min; i < (uint8_t*)g_pal_sec.heap_max; i += g_page_size)
            READ_ONCE(*(size_t*)i);
    }

    ret = toml_sizestring_in(g_pal_state.manifest_root, "loader.pal_internal_mem_size",
                             /*defaultval=*/0, &g_pal_internal_mem_size);
    if (ret < 0) {
        log_error("Cannot parse 'loader.pal_internal_mem_size'");
        ocall_exit(1, true);
    }

    if ((ret = init_file_check_policy()) < 0) {
        log_error("Failed to load the file check policy: %d", ret);
        ocall_exit(1, true);
    }

    if ((ret = init_allowed_files()) < 0) {
        log_error("Failed to initialize allowed files: %d", ret);
        ocall_exit(1, true);
    }

    if ((ret = init_trusted_files()) < 0) {
        log_error("Failed to initialize trusted files: %d", ret);
        ocall_exit(1, true);
    }

    if ((ret = init_protected_files()) < 0) {
        log_error("Failed to initialize protected files: %d", ret);
        ocall_exit(1, true);
    }

    /* set up thread handle */
    PAL_HANDLE first_thread = malloc(HANDLE_SIZE(thread));
    if (!first_thread) {
        log_error("Out of memory");
        ocall_exit(1, true);
    }
    init_handle_hdr(HANDLE_HDR(first_thread), PAL_TYPE_THREAD);
    first_thread->thread.tcs = g_enclave_base + GET_ENCLAVE_TLS(tcs_offset);
    /* child threads are assigned TIDs 2,3,...; see pal_start_thread() */
    first_thread->thread.tid = 1;
    g_pal_control.first_thread = first_thread;
    SET_ENCLAVE_TLS(thread, &first_thread->thread);

    uint64_t stack_protector_canary;
    ret = _DkRandomBitsRead(&stack_protector_canary, sizeof(stack_protector_canary));
    if (ret < 0) {
        log_error("_DkRandomBitsRead failed: %d", ret);
        ocall_exit(1, /*is_exitgroup=*/true);
    }
    pal_set_tcb_stack_canary(stack_protector_canary);

    assert(!g_pal_sec.enclave_flags); /* currently only PAL_ENCLAVE_INITIALIZED */
    g_pal_sec.enclave_flags |= PAL_ENCLAVE_INITIALIZED;

    /* call main function */
    pal_main(instance_id, parent, first_thread, arguments, environments);
}
