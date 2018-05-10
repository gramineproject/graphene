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
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "pal_security.h"
#include "pal_rtld.h"
#include "api.h"

extern struct gdb_link_map * attached_gdb_maps;

/* This structure communicates dl state to the debugger.  The debugger
   normally finds it via the DT_DEBUG entry in the dynamic section, but in
   a statically-linked program there is no dynamic section for the debugger
   to examine and it looks for this particular symbol name.  */
struct r_debug pal_r_debug =
        { 1, NULL, (ElfW(Addr)) &pal_dl_debug_state, RT_CONSISTENT, 0 };

extern __typeof(pal_r_debug) _r_debug
    __attribute ((alias ("pal_r_debug")));

/* This function exists solely to have a breakpoint set on it by the
   debugger.  The debugger is supposed to find this function's address by
   examining the r_brk member of struct r_debug, but GDB 4.15 in fact looks
   for this particular symbol name in the PT_INTERP file.  */

/* The special symbol name is set as breakpoint in gdb */
void __attribute__((noinline)) pal_dl_debug_state (void)
{
    if (pal_sec._dl_debug_state)
        pal_sec._dl_debug_state();
}

extern __typeof(pal_dl_debug_state) _dl_debug_state
    __attribute ((alias ("pal_dl_debug_state")));

void _DkDebugAddMap (struct gdb_link_map * map)
{
#ifdef DEBUG
    struct r_debug * dbg = pal_sec._r_debug ? : &pal_r_debug;
    dbg->r_state = RT_ADD;
    pal_dl_debug_state();
    dbg->r_map = attached_gdb_maps;
    dbg->r_state = RT_CONSISTENT;
    pal_dl_debug_state();
#endif
}

void _DkDebugDelMap (struct gdb_link_map * map)
{
#ifdef DEBUG
    struct r_debug * dbg = pal_sec._r_debug ? : &pal_r_debug;
    dbg->r_state = RT_DELETE;
    pal_dl_debug_state();
    dbg->r_map = attached_gdb_maps;
    dbg->r_state = RT_CONSISTENT;
    pal_dl_debug_state();
#endif
}

#if USE_VDSO_GETTIME == 1
void setup_vdso_map (void * addr)
{
    const ElfW(Ehdr) * header = (ElfW(Ehdr) *) addr;
    struct link_map vdso_map;

    memset(&vdso_map, 0, sizeof(struct link_map));
    vdso_map.binary_name = "vdso";
    vdso_map.base_addr   = addr;
    vdso_map.entry       = (void *) header->e_entry;
    vdso_map.phdr_addr   = (void *) addr + header->e_phoff;
    vdso_map.phdr_num    = header->e_phnum;

    load_link_map(&vdso_map, NULL, addr, MAP_RTLD);

#if USE_CLOCK_GETTIME == 1
     linux_state.vdso_clock_gettime
            = find_symbol(&vdso_map, "__vdso_clock_gettime");
#else
     linux_state.vdso_gettimeofday
            = find_symbol(&vdso_map, "__vdso_gettimeofday");
#endif
}
#endif

ElfW(Addr) resolve_rtld (const char * sym_name)
{
    /* We are not using this, because in Linux we can rely on
       rtld_map to directly lookup symbols */
    return 0;
}
