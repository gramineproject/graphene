/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*!
 * \file
 *
 * This file contains the implementation of `/proc/meminfo` and `/proc/cpuinfo`.
 */

#include "shim_fs.h"
#include "shim_fs_pseudo.h"
#include "stat.h"

int proc_meminfo_get_content(struct shim_dentry* dent, char** content, size_t* size) {
    __UNUSED(dent);

    int len, max = 128;
    char* str = NULL;

    struct {
        const char* fmt;
        unsigned long val;
    } meminfo[] = {
        {
            "MemTotal:      %8lu kB\n",
            g_pal_control->mem_info.mem_total / 1024,
        },
        {
            "MemFree:       %8lu kB\n",
            DkMemoryAvailableQuota() / 1024,
        },
    };

retry:
    max *= 2;
    len = 0;
    free(str);
    str = malloc(max);
    if (!str)
        return -ENOMEM;

    for (size_t i = 0; i < ARRAY_SIZE(meminfo); i++) {
        int ret = snprintf(str + len, max - len, meminfo[i].fmt, meminfo[i].val);

        if (len + ret == max)
            goto retry;

        len += ret;
    }

    struct shim_str_data* data = malloc(sizeof(struct shim_str_data));
    if (!data) {
        free(str);
        return -ENOMEM;
    }

    *content = str;
    *size = len;
    return 0;
}

// FIXME: remove once global realloc is enabled
static void* realloc(void* ptr, size_t old_size, size_t new_size) {
    void* tmp = malloc(new_size);
    if (!tmp) {
        return NULL;
    }

    memcpy(tmp, ptr, old_size);

    free(ptr);

    return tmp;
}

static int print_to_str(char** str, size_t off, size_t* size, const char* fmt, ...) {
    int ret;
    va_list ap;

retry:
    va_start(ap, fmt);
    ret = vsnprintf(*str + off, *size - off, fmt, ap);
    va_end(ap);

    if (ret < 0) {
        return -EINVAL;
    }

    if ((size_t)ret >= *size - off) {
        char* tmp = realloc(*str, *size, *size + 128);
        if (!tmp) {
            return -ENOMEM;
        }
        *size += 128;
        *str = tmp;
        goto retry;
    }

    return ret;
}

int proc_cpuinfo_get_content(struct shim_dentry* dent, char** content, size_t* size) {
    __UNUSED(dent);

    size_t len = 0;
    size_t max = 128;
    char* str = malloc(max);
    if (!str) {
        return -ENOMEM;
    }

#define ADD_INFO(fmt, ...)                                           \
    do {                                                             \
        int ret = print_to_str(&str, len, &max, fmt, ##__VA_ARGS__); \
        if (ret < 0) {                                               \
            free(str);                                               \
            return ret;                                              \
        }                                                            \
        len += ret;                                                  \
    } while (0)

    for (size_t n = 0; n < g_pal_control->cpu_info.online_logical_cores; n++) {
        /* Below strings must match exactly the strings retrieved from /proc/cpuinfo
         * (see Linux's arch/x86/kernel/cpu/proc.c) */
        ADD_INFO("processor\t: %lu\n", n);
        ADD_INFO("vendor_id\t: %s\n", g_pal_control->cpu_info.cpu_vendor);
        ADD_INFO("cpu family\t: %lu\n", g_pal_control->cpu_info.cpu_family);
        ADD_INFO("model\t\t: %lu\n", g_pal_control->cpu_info.cpu_model);
        ADD_INFO("model name\t: %s\n", g_pal_control->cpu_info.cpu_brand);
        ADD_INFO("stepping\t: %lu\n", g_pal_control->cpu_info.cpu_stepping);
        ADD_INFO("physical id\t: %d\n", g_pal_control->cpu_info.cpu_socket[n]);
        ADD_INFO("core id\t\t: %lu\n", n);
        ADD_INFO("cpu cores\t: %lu\n", g_pal_control->cpu_info.physical_cores_per_socket);
        double bogomips = g_pal_control->cpu_info.cpu_bogomips;
        // Apparently graphene snprintf cannot into floats.
        ADD_INFO("bogomips\t: %lu.%02lu\n", (unsigned long)bogomips,
                 (unsigned long)(bogomips * 100.0 + 0.5) % 100);
        ADD_INFO("\n");
    }
#undef ADD_INFO

    struct shim_str_data* data = calloc(1, sizeof(struct shim_str_data));
    if (!data) {
        free(str);
        return -ENOMEM;
    }

    *content = str;
    *size = len;
    return 0;
}
