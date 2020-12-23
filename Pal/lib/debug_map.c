/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

#include "debug_map.h"

#include <asm/errno.h>

#include "spinlock.h"

struct debug_map* _Atomic g_debug_map = NULL;

/* Lock for modifying g_debug_map on our end. Even though the list can be read at any
 * time, we need to prevent concurrent modification. */
static spinlock_t g_debug_map_lock = INIT_SPINLOCK_UNLOCKED;

static struct debug_map* debug_map_new(const char* name, void* addr) {
    struct debug_map* map;

    if (!(map = malloc(sizeof(*map))))
        return NULL;

    if (!(map->name = strdup(name))) {
        free(map);
        return NULL;
    }

    map->addr = addr;
    map->next = NULL;
    return map;
}

/* This function is hooked by our gdb integration script and should be left as is. */
__attribute__((__noinline__)) void debug_map_update_debugger(void) {
    __asm__ volatile(""); // Required in addition to __noinline__ to prevent deleting this function.
                          // See GCC docs.
}

int debug_map_add(const char* name, void* addr) {
    struct debug_map* map = debug_map_new(name, addr);
    if (!map)
        return -ENOMEM;

    spinlock_lock(&g_debug_map_lock);

    map->next = g_debug_map;
    g_debug_map = map;

    spinlock_unlock(&g_debug_map_lock);

    debug_map_update_debugger();

    return 0;
}

int debug_map_remove(void* addr) {
    spinlock_lock(&g_debug_map_lock);

    struct debug_map* prev = NULL;
    struct debug_map* map = g_debug_map;
    while (map) {
        if (map->addr == addr)
            break;
        prev = map;
        map = map->next;
    }
    if (!map) {
        spinlock_unlock(&g_debug_map_lock);
        return -EINVAL;
    }
    if (prev) {
        prev->next = map->next;
    } else {
        g_debug_map = map->next;
    }

    spinlock_unlock(&g_debug_map_lock);

    debug_map_update_debugger();

    free(map->name);
    free(map);

    return 0;
}
