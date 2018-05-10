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
#include "pal_rtld.h"

void pal_dl_debug_state (void);

/* This structure communicates dl state to the debugger.  The debugger
   normally finds it via the DT_DEBUG entry in the dynamic section, but in
   a statically-linked program there is no dynamic section for the debugger
   to examine and it looks for this particular symbol name.  */
extern struct r_debug pal_r_debug;

extern struct pal_sec {
    /* system variables */
    unsigned int    process_id;
    int             random_device;

    /* pipes and sockets */
    unsigned long   pipe_prefix_id;
    unsigned short  mcast_port;

    /* for debugger */
    void (*_dl_debug_state) (void);
    struct r_debug * _r_debug;
} pal_sec;

#define PROC_INIT_FD    255

#define RANDGEN_DEVICE          "/dev/urandom"

#endif /* PAL_SECURITY_H */
