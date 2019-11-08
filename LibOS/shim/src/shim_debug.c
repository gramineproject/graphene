/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_debug.c
 *
 * This file contains codes for registering libraries to GDB.
 */

#include <pal.h>
#include <pal_error.h>
#include <shim_checkpoint.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_ipc.h>
#include <shim_tcb.h>
#include <shim_vma.h>

#ifndef DEBUG

void clean_link_map_list(void) {
    /* do nothing */
}

void remove_r_debug(void* addr) {
    __UNUSED(addr);
    /* do nothing */
}

void append_r_debug(const char* uri, void* addr, void* dyn_addr) {
    __UNUSED(uri);
    __UNUSED(addr);
    __UNUSED(dyn_addr);
    /* do nothing */
}

#else /* !DEBUG */

struct gdb_link_map {
    void* l_addr;
    char* l_name;
    void* l_ld;
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
        DkDebugDetachBinary(m->l_addr);
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

    debug("remove a library for gdb: %s\n", m->l_name);

    if (m->l_prev)
        m->l_prev->l_next = m->l_next;
    if (m->l_next)
        m->l_next->l_prev = m->l_prev;

    DkDebugDetachBinary(addr);
}

void append_r_debug(const char* uri, void* addr, void* dyn_addr) {
    struct gdb_link_map* new = malloc(sizeof(struct gdb_link_map));
    if (!new)
        return;

    int uri_len   = strlen(uri);
    char* new_uri = malloc(uri_len + 1);
    if (!new_uri) {
        free(new);
        return;
    }
    memcpy(new_uri, uri, uri_len + 1);

    new->l_addr = addr;
    new->l_ld   = dyn_addr;
    new->l_name = new_uri;

    struct gdb_link_map* prev  = NULL;
    struct gdb_link_map** tail = &link_map_list;

    while (*tail) {
        prev = *tail;
        tail = &(*tail)->l_next;
    }

    debug("add a library for gdb: %s\n", uri);

    new->l_prev = prev;
    new->l_next = NULL;
    *tail       = new;

    DkDebugAttachBinary(uri, addr);
}

BEGIN_CP_FUNC(gdb_map) {
    __UNUSED(obj);
    __UNUSED(size);
    __UNUSED(objp);
    struct gdb_link_map* m    = link_map_list;
    struct gdb_link_map* newm = NULL;

    while (m) {
        ptr_t off = ADD_CP_OFFSET(sizeof(struct gdb_link_map));
        newm      = (struct gdb_link_map*)(base + off);

        memcpy(newm, m, sizeof(struct gdb_link_map));
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

    DkDebugAttachBinary(map->l_name, map->l_addr);

    DEBUG_RS("base=%p,name=%s", map->l_addr, map->l_name);
}
END_RS_FUNC(gdb_map)

#endif
