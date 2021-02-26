/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains code for registering libraries to GDB.
 */

#include "pal.h"
#include "pal_error.h"
#include "shim_checkpoint.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_ipc.h"
#include "shim_tcb.h"
#include "shim_vma.h"

#ifndef DEBUG

void clean_link_map_list(void) {
    /* do nothing */
}

void remove_r_debug(void* addr) {
    __UNUSED(addr);
    /* do nothing */
}

void append_r_debug(const char* uri, void* addr) {
    __UNUSED(uri);
    __UNUSED(addr);
    /* do nothing */
}

#else /* !DEBUG */

struct gdb_link_map {
    void* l_addr;
    char* l_name;
    struct gdb_link_map *l_next, *l_prev;
};

/* XXX: What lock protects this?  vma_list_lock? */
static struct gdb_link_map* link_map_list = NULL;

void clean_link_map_list(void) {
    if (!link_map_list)
        return;

    if (link_map_list->l_prev)
        link_map_list->l_prev->l_next = NULL;

    struct gdb_link_map* m = link_map_list;
    for (; m; m = m->l_next) {
        DkDebugMapRemove(m->l_addr);
        free(m);
    }

    link_map_list = NULL;
}

void remove_r_debug(void* addr) {
    struct gdb_link_map* m = link_map_list;

    for (; m; m = m->l_next)
        if (m->l_addr == addr)
            break;

    if (!m)
        return;

    log_debug("removing a library for gdb: %s\n", m->l_name);

    if (m->l_prev) {
        m->l_prev->l_next = m->l_next;
    } else {
        link_map_list = m->l_next;
    }

    if (m->l_next) {
        m->l_next->l_prev = m->l_prev;
    }

    DkDebugMapRemove(addr);
    free(m);
}

void append_r_debug(const char* uri, void* addr) {
    struct gdb_link_map* new = malloc(sizeof(struct gdb_link_map));
    if (!new)
        return;

    char* new_uri = strdup(uri);
    if (!new_uri) {
        free(new);
        return;
    }

    new->l_addr = addr;
    new->l_name = new_uri;

    struct gdb_link_map* prev  = NULL;
    struct gdb_link_map** tail = &link_map_list;

    while (*tail) {
        prev = *tail;
        tail = &(*tail)->l_next;
    }

    log_debug("adding a library for gdb: %s\n", uri);

    new->l_prev = prev;
    new->l_next = NULL;
    *tail       = new;

    DkDebugMapAdd(uri, addr);
}

BEGIN_CP_FUNC(gdb_map) {
    __UNUSED(obj);
    __UNUSED(size);
    __UNUSED(objp);
    struct gdb_link_map* m    = link_map_list;
    struct gdb_link_map* newm = NULL;

    while (m) {
        size_t off = ADD_CP_OFFSET(sizeof(struct gdb_link_map));
        newm       = (struct gdb_link_map*)(base + off);

        *newm = *m;
        newm->l_prev = newm->l_next = NULL;

        size_t len   = strlen(newm->l_name);
        newm->l_name = (char*)(base + ADD_CP_OFFSET(len + 1));
        memcpy(newm->l_name, m->l_name, len + 1);

        ADD_CP_FUNC_ENTRY(off);
        m = m->l_next;
    }
}
END_CP_FUNC(gdb_map)

BEGIN_RS_FUNC(gdb_map) {
    __UNUSED(offset);
    struct gdb_link_map* map = (void*)(base + GET_CP_FUNC_ENTRY());

    CP_REBASE(map->l_name);
    CP_REBASE(map->l_prev);
    CP_REBASE(map->l_next);

    struct gdb_link_map* prev  = NULL;
    struct gdb_link_map** tail = &link_map_list;

    while (*tail) {
        prev = *tail;
        tail = &(*tail)->l_next;
    }

    map->l_prev = prev;
    *tail       = map;

    DkDebugMapAdd(map->l_name, map->l_addr);

    DEBUG_RS("base=%p,name=%s", map->l_addr, map->l_name);
}
END_RS_FUNC(gdb_map)

#endif
