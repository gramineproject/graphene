/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com> */

/* sgx_rtld.h
 *
 * Internal debug maps, used for SGX to communicate with debugger. We maintain it so that it is in a
 * consistent state any time the process is stopped (any add/delete is an atomic modification of one
 * pointer).
 */

#ifndef SGX_RTLD_H
#define SGX_RTLD_H

struct debug_section {
    char* name;
    void* addr;

    struct debug_section* next;
};

struct debug_map {
    char* file_name;
    void* text_addr;
    struct debug_section* section;

    struct debug_map* _Atomic next;
};

/* Pointer to list head, defined outside the enclave (in g_pal_enclave). */
extern struct debug_map* _Atomic* g_debug_map;

#endif /* SGX_RTLD_H */
