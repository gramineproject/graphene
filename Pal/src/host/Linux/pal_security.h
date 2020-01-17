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

#include <linux/limits.h>
#include <sysdeps/generic/ldsodefs.h>

#include "pal.h"

/* Rendezvous structure used by the run-time dynamic linker to communicate
   details of shared object loading to the debugger.  If the executable's
   dynamic section has a DT_DEBUG element, the run-time linker sets that
   element's value to the address where this structure can be found.  */
struct r_debug {
    int r_version; /* Version number for this protocol.  */

    struct link_map* r_map; /* Head of the chain of loaded objects.  */

    /* This is the address of a function internal to the run-time linker,
       that will always be called when the linker begins to map in a
       library or unmap it, and again when the mapping change is complete.
       The debugger can set a breakpoint at this address if it wants to
       notice shared object mapping changes.  */
    ElfW(Addr) r_brk;
    enum {
        /* This state value describes the mapping change taking place when
           the `r_brk' address is called.  */
        RT_CONSISTENT, /* Mapping change is complete.  */
        RT_ADD,        /* Beginning to add a new object.  */
        RT_DELETE      /* Beginning to remove an object mapping.  */
    } r_state;

    ElfW(Addr) r_ldbase; /* Base address the linker is loaded at.  */
};

void pal_dl_debug_state(void);

/* This structure communicates dl state to the debugger.  The debugger
   normally finds it via the DT_DEBUG entry in the dynamic section, but in
   a statically-linked program there is no dynamic section for the debugger
   to examine and it looks for this particular symbol name.  */
extern struct r_debug pal_r_debug;
symbol_version_default(pal_r_debug, _r_debug, PAL);

extern struct pal_sec {
    /* system variables */
    unsigned int process_id;
    int random_device;

    /* pipes and sockets */
    unsigned long pipe_prefix_id;

    /* for debugger */
    void (*_dl_debug_state)(void);
    struct r_debug* _r_debug;
} pal_sec;

#define PROC_INIT_FD 255

#define RANDGEN_DEVICE "/dev/urandom"

#endif /* PAL_SECURITY_H */
