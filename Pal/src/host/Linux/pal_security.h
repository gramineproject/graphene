/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#ifndef PAL_SECURITY_H
#define PAL_SECURITY_H

#include <linux/limits.h>

#include "pal.h"
#include "sysdeps/generic/ldsodefs.h"

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

extern struct pal_sec {
    /* system variables */
    unsigned int process_id;
    int random_device;

    /* for debugger */
    void (*_dl_debug_state)(void);
    struct r_debug* _r_debug;
} g_pal_sec;

#define RANDGEN_DEVICE "/dev/urandom"

#endif /* PAL_SECURITY_H */
