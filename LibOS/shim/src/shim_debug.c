/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_debug.c
 *
 * This file contains codes for registering libraries to GDB.
 */

#include <shim_internal.h>
#include <shim_tls.h>
#include <shim_handle.h>
#include <shim_vma.h>
#include <shim_checkpoint.h>
#include <shim_fs.h>
#include <shim_ipc.h>

#include <pal.h>
#include <pal_error.h>

#include <fcntl.h>

struct gdb_link_map
{
    void * l_addr;
    char * l_name;
    void * l_ld;
    struct gdb_link_map *l_next, *l_prev;
};

struct gdb_r_debug
{
    int r_version;
    struct gdb_link_map *r_map;
    uintptr_t r_brk;
    enum
    {
        RT_CONSISTENT,
        RT_ADD,
        RT_DELETE,
    } r_state;
    uintptr_t r_ldbase;
};

struct gdb_r_debug __libc_r_debug;

extern struct gdb_r_debug _r_debug;
extern void _dl_debug_state_trigger (void);

static struct gdb_link_map * link_map_list = NULL;

static inline char * translate_file_path (const char * path)
{
    struct shim_dentry * dent = NULL;

    int ret = path_lookupat(NULL, path, 0, &dent);
    if (ret < 0)
        return NULL;

    struct shim_mount * fs = dent->fs;

    if (!fs->d_ops->open)
        return NULL;

    char * new_uri = NULL;
    struct shim_handle * hdl = get_new_handle();
    if (!hdl)
        return NULL;

    set_handle_fs(hdl, fs);
    hdl->dentry = dent;

    ret = fs->d_ops->open(hdl, dent, O_RDONLY);
    if (ret < 0)
        goto out;

    new_uri = qstrtostr(&hdl->uri, false);
out:
    put_handle(hdl);
    return new_uri;
}

void __libc_dl_debug_state (void)
{
    /* first make sure libc map list matches the shadow map list */
    if (link_map_list) {
        struct gdb_link_map *m = link_map_list, *n;
        for ( ; m ; m = m->l_next) {
            for (n = __libc_r_debug.r_map ; n ; n = n->l_next)
                if (m->l_addr == n->l_addr)
                    break;
            if (!n) {
                if (m->l_prev)
                    m->l_prev->l_next = m->l_next;
                if (m->l_next)
                    m->l_next->l_prev = m->l_prev;
                if (m == link_map_list)
                    link_map_list = m->l_next;
            }
        }
    }

    /* now find the end of the shadow map list, where we are adding to */
    struct gdb_link_map *prev = NULL;
    struct gdb_link_map **tail = &_r_debug.r_map;

    while (*tail) {
        prev = *tail;
        tail = &(*tail)->l_next;
    }

    /* add new maps to the shadow map list */
    struct gdb_link_map **t = tail;
    struct gdb_link_map *m = __libc_r_debug.r_map;

    for ( ; m ; m = m->l_next) {
        struct gdb_link_map *re = _r_debug.r_map;
        while (re && re->l_addr != m->l_addr)
            re = re->l_next;

        if (re)
            continue;

        char * uri = translate_file_path(m->l_name);
        if (!uri)
            continue;
        debug("add a library for gdb: %s\n", uri);

        struct gdb_link_map * new = malloc(sizeof(struct gdb_link_map));

        new->l_addr = m->l_addr;
        new->l_ld = m->l_ld;
        new->l_name = uri;
        new->l_prev = prev;
        prev = *t = new;
        new->l_next = NULL;
        t = &new->l_next;
    }

    if (!link_map_list)
        link_map_list = *tail;

    _r_debug.r_state = __libc_r_debug.r_state;
    _dl_debug_state_trigger();
}

void clean_link_map_list (void)
{
    if (!link_map_list)
        return;

    _r_debug.r_state = RT_DELETE;
    _dl_debug_state_trigger();

    if (link_map_list->l_prev)
        link_map_list->l_prev->l_next = NULL;
    if (_r_debug.r_map == link_map_list)
        _r_debug.r_map = NULL;

    struct gdb_link_map * m = link_map_list;
    for ( ; m ; m = m->l_next)
        free(m);

    link_map_list = NULL;

    _r_debug.r_state = RT_CONSISTENT;
    _dl_debug_state_trigger();

}

void remove_r_debug (void * addr)
{
    struct gdb_link_map * m = _r_debug.r_map;

    for ( ; m && m != link_map_list ; m = m->l_next)
        if (m->l_addr == addr)
            break;

    if (!m || m == link_map_list)
        return;

    _r_debug.r_state = RT_DELETE;
    _dl_debug_state_trigger();

    debug("remove a library for gdb: %s\n", m->l_name);

    if (m->l_prev)
        m->l_prev->l_next = m->l_next;
    if (m->l_next)
        m->l_next->l_prev = m->l_prev;
    if (_r_debug.r_map == m)
        _r_debug.r_map = m->l_next;

    _r_debug.r_state = RT_CONSISTENT;
    _dl_debug_state_trigger();
}

void append_r_debug (const char * uri, void * addr, void * dyn_addr)
{
    struct gdb_link_map * new = malloc(sizeof(struct gdb_link_map));

    int uri_len = strlen(uri);
    char * new_uri = malloc(uri_len + 1);
    memcpy(new_uri, uri, uri_len + 1);

    new->l_addr = addr;
    new->l_ld = dyn_addr;
    new->l_name = new_uri;

    struct gdb_link_map *prev = NULL;
    struct gdb_link_map **tail = &_r_debug.r_map;

    while (*tail && *tail != link_map_list) {
        prev = *tail;
        tail = &(*tail)->l_next;
    }

    _r_debug.r_state = RT_ADD;
    _dl_debug_state_trigger();

    debug("add a library for gdb: %s\n", new->l_name);

    new->l_prev = prev;
    new->l_next = link_map_list;
    *tail = new;
    if (link_map_list)
        link_map_list->l_prev = new;

    _r_debug.r_state = RT_CONSISTENT;
    _dl_debug_state_trigger();
}

DEFINE_MIGRATE_FUNC(gdb_map)

MIGRATE_FUNC_BODY(gdb_map)
{
    struct gdb_link_map *m = link_map_list;
    struct gdb_link_map *newm = NULL;

    while (m) {
        ADD_OFFSET(sizeof(struct gdb_link_map));
        ADD_FUNC_ENTRY(*offset);

        if (!dry) {
            newm = (struct gdb_link_map *) (base + *offset);
            memcpy(newm, m, sizeof(struct gdb_link_map));
            newm->l_prev = newm->l_next = NULL;
        }

        ADD_OFFSET(strlen(m->l_name) + 1);

        if (!dry) {
            newm->l_name = (char *) (base + *offset);
            memcpy(newm->l_name, m->l_name, strlen(m->l_name) + 1);
        }

        m = m->l_next;
    }
}
END_MIGRATE_FUNC

RESUME_FUNC_BODY(gdb_map)
{
    uint64_t off = GET_FUNC_ENTRY();

    _r_debug.r_state = RT_ADD;
    _dl_debug_state_trigger ();

    struct gdb_link_map *map = (struct gdb_link_map *) (base + off);

    RESUME_REBASE(map->l_name);
    RESUME_REBASE(map->l_prev);
    RESUME_REBASE(map->l_next);

    struct gdb_link_map *prev = NULL;
    struct gdb_link_map **tail = &link_map_list;

    while (*tail) {
        prev = *tail;
        tail = &(*tail)->l_next;
    }

    map->l_prev = prev;
    *tail = map;

    tail = &_r_debug.r_map;
    while (*tail && *tail != link_map_list) {
        prev = *tail;
        tail = &(*tail)->l_next;
    }

    *tail = link_map_list;
    link_map_list->l_prev = prev;

#ifdef DEBUG_RESUME
    debug("gdb: %s loaded at %p\n", map->l_name, map->l_addr);
#endif

    _r_debug.r_state = RT_CONSISTENT;
    _dl_debug_state_trigger ();
}
END_RESUME_FUNC
