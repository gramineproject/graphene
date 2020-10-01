/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com> */

/*
 * Internal debug maps, used for SGX to communicate with debugger. We maintain it so that it is in a
 * consistent state any time the process is stopped (any add/delete is an atomic modification of one
 * pointer).
 *
 * The debug map is maintained inside the enclave, and the debugger is notified using
 * ocall_update_debugger().
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

#endif /* SGX_RTLD_H */
