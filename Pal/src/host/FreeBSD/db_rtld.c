/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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
 * db_rtld.c
 *
 * This file contains utilities to load ELF binaries into the memory
 * and link them against each other.
 * The source code in this file is imported and modified from the GNU C
 * Library.
 */

#include "pal_defs.h"
#include "pal_freebsd_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_freebsd.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "pal_security.h"
#include "pal_rtld.h"
#include "api.h"

#include <sysdeps/generic/ldsodefs.h>
#include <elf/elf.h>
#include <dlfcn.h>

#include "elf-x86_64.h"

/* This structure communicates dl state to the debugger.  The debugger
   normally finds it via the DT_DEBUG entry in the dynamic section, but in
   a statically-linked program there is no dynamic section for the debugger
   to examine and it looks for this particular symbol name.  */
struct r_debug pal_r_debug =
        { 1, NULL, &pal_r_debug_state, RT_CONSISTENT, };

extern __typeof(pal_r_debug) r_debug
    __attribute ((alias ("pal_r_debug")));

/* This function exists solely to have a breakpoint set on it by the
   debugger.  The debugger is supposed to find this function's address by
   examining the r_brk member of struct r_debug, but GDB 4.15 in fact looks
   for this particular symbol name in the PT_INTERP file.  */

/* The special symbol name is set as breakpoint in gdb */
void __attribute__((noinline))
pal_r_debug_state (struct r_debug * rd, struct link_gdb_map * map)
{
    if (pal_sec.r_debug_state)
        pal_sec.r_debug_state(rd, map);

    asm volatile ("" ::: "memory");
}

extern __typeof(pal_r_debug_state) r_debug_state
    __attribute ((alias ("pal_r_debug_state")));

void _DkDebugAddMap (struct link_map * map)
{
    struct r_debug * dbg = pal_sec.r_debug ? : &pal_r_debug;
    int len = map->l_name ? strlen(map->l_name) + 1 : 0;

    struct link_map ** prev = &dbg->r_map, * last = NULL,
                    * tmp = *prev;
    while (tmp) {
        if (tmp->l_addr == map->l_addr &&
            tmp->l_ld == map->l_ld &&
            !memcmp(tmp->l_name, map->l_name, len))
            return;

        last = tmp;
        tmp = *(prev = &last->l_next);
    }

    struct link_gdb_map * m = malloc(sizeof(struct link_gdb_map) + len);
    if (!m)
        return;

    if (len) {
        m->l_name = (char *) m + sizeof(struct link_gdb_map);
        memcpy((void *) m->l_name, map->l_name, len);
    } else {
        m->l_name = NULL;
    }

    m->l_addr = map->l_addr;
    m->l_ld   = map->l_real_ld;

    dbg->r_state = RT_ADD;
    pal_r_debug_state(dbg, m);

    *prev = (struct link_map *) m;
    m->l_prev = last;
    m->l_next = NULL;

    dbg->r_state = RT_CONSISTENT;
    pal_r_debug_state(dbg, NULL);
}

void _DkDebugDelMap (struct link_map * map)
{
    struct r_debug * dbg = pal_sec.r_debug ? : &pal_r_debug;
    int len = map->l_name ? strlen(map->l_name) + 1 : 0;

    struct link_gdb_map ** prev = (void *) &dbg->r_map;
    struct link_gdb_map * last = NULL;
    struct link_gdb_map * t = (void *) dbg->r_map, * m = NULL;

    while (t) {
        if (t->l_addr == map->l_addr &&
            t->l_ld == map->l_ld &&
            !memcmp(t->l_name, map->l_name, len)) {
            m = t;
            break;
        }

        last = t;
        prev = (void *) last->l_next;
        t = *prev;
    }

    if (!m)
        return;

    dbg->r_state = RT_DELETE;
    pal_r_debug_state(dbg, m);

    if (last)
        last->l_next = m->l_next;
    else
        dbg->r_map = m->l_next;

    if (m->l_next)
        m->l_next->l_prev = (void *) last;

    free(m);

    dbg->r_state = RT_CONSISTENT;
    pal_r_debug_state(dbg, NULL);
}

extern void setup_elf_hash (struct link_map *map);

void setup_pal_map (struct link_map * pal_map)
{
    const ElfW(Ehdr) * header = (void *) pal_map->l_addr;

    pal_map->l_real_ld = pal_map->l_ld = (void *) elf_machine_dynamic();
    pal_map->l_type = OBJECT_RTLD;
    pal_map->l_entry = header->e_entry;
    pal_map->l_phdr  = (void *) (pal_map->l_addr + header->e_phoff);
    pal_map->l_phnum = header->e_phnum;
    setup_elf_hash(pal_map);

    _DkDebugAddMap(pal_map);
    pal_map->l_prev = pal_map->l_next = NULL;
    loaded_maps = pal_map;
}
ElfW(Addr) resolve_rtld (const char * sym_name)
{
    /* We are not using this, because in Linux we can rely on
       rtld_map to directly lookup symbols */
    return 0;
}
