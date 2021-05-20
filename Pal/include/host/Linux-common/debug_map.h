/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Internal debug maps, used to communicate with GDB.
 *
 * This functionality is placed in Linux-common to support setups in which the debug maps are
 * maintained in an "outer" binary instead of the main PAL binary.
 */

#ifndef DEBUG_MAP_H
#define DEBUG_MAP_H

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

#endif /* DEBUG_MAP_H */
