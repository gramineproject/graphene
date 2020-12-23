/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Internal debug maps, used to communicate with GDB.
 *
 * Note that this is a separate module (and not part of libpal) because in case of SGX it is used in
 * the outer pal-sgx process, not in libpal itself.
 */

#ifndef PAL_DEBUG_MAP_H
#define PAL_DEBUG_MAP_H

#include <stdint.h>

struct debug_map {
    char* name;
    void* addr;

    struct debug_map* _Atomic next;
};

extern struct debug_map* _Atomic g_debug_map;

/* GDB will set a breakpoint on this function. */
void debug_map_update_debugger(void);

int debug_map_add(const char* name, void* addr);
int debug_map_remove(void* addr);

#endif
