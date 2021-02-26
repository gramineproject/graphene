/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * This file defines glibc-dependent function for profiling (sgx_profile_report_host_elfs).
 * The function uses dl_iterate_phdr() to retrieve a list of host libraries.
 *
 * It is implemented in separate file, because PAL headers and glibc headers conflict with each
 * other.
 */

#ifdef DEBUG

#define _GNU_SOURCE
#include <link.h>
#include <stdlib.h>
#include <string.h>

/* Function prototypes. Declared also in sgx_internal.h, but we cannot include it here due to header
 * conflict. */
void sgx_profile_report_urts_elfs(void);
void sgx_profile_report_elf(const char* filename, void* addr);

static int callback(struct dl_phdr_info* info,
                    __attribute__((unused)) size_t size,
                    __attribute__((unused)) void* data) {

    sgx_profile_report_elf(info->dlpi_name, (void*)info->dlpi_addr);
    return 0;
}

void sgx_profile_report_urts_elfs(void) {
    dl_iterate_phdr(&callback, NULL);
}

#endif
