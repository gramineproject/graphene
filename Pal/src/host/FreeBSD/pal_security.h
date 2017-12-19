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

#ifndef PAL_SECURITY_H
#define PAL_SECURITY_H

#include "pal.h"

#define PATH_MAX    80
#define PIPE_MAX    32

struct link_gdb_map;

/* Rendezvous structure used by the run-time dynamic linker to communicate
   details of shared object loading to the debugger.  If the executable's
   dynamic section has a DT_DEBUG element, the run-time linker sets that
   element's value to the address where this structure can be found.  */
struct r_debug {
    int r_version;           /* Version number for this protocol.  */

    struct link_map * r_map; /* Head of the chain of loaded objects.  */

    /* This is the address of a function internal to the run-time linker,
       that will always be called when the linker begins to map in a
       library or unmap it, and again when the mapping change is complete.
       The debugger can set a breakpoint at this address if it wants to
       notice shared object mapping changes.  */
    void (*r_brk) (struct r_debug *, struct link_gdb_map *);
    enum {
        /* This state value describes the mapping change taking place when
           the `r_brk' address is called.  */
        RT_CONSISTENT,  /* Mapping change is complete.  */
        RT_ADD,         /* Beginning to add a new object.  */
        RT_DELETE       /* Beginning to remove an object mapping.  */
    } r_state;
};

void pal_r_debug_state (struct r_debug *, struct link_gdb_map *);

/* This structure communicates dl state to the debugger.  The debugger
   normally finds it via the DT_DEBUG entry in the dynamic section, but in
   a statically-linked program there is no dynamic section for the debugger
   to examine and it looks for this particular symbol name.  */
extern struct r_debug pal_r_debug;

extern struct pal_sec {
    unsigned int        domain_id;
    char                pipe_prefix[PIPE_MAX];
    void *              user_addr_base;
    int                 rand_gen;
    unsigned short      mcast_port;
    void                (*r_debug_state) (struct r_debug *,
                                          struct link_gdb_map *);
    struct r_debug *    r_debug;
} pal_sec;

#define GRAPHENE_TEMPDIR        "/tmp/graphene"
#define GRAPHENE_PIPEDIR        GRAPHENE_TEMPDIR "/pipes"

#define PROC_INIT_FD    255

#define GRAPHENE_MCAST_GROUP "239.0.0.1"

#endif /* PAL_SECURITY_H */
