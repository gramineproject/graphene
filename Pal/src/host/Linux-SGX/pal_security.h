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
#include "sgx_arch.h"

typedef char PAL_SEC_STR[255];

struct pal_sec {
    /* host credentials */
    PAL_NUM         instance_id;
    PAL_IDX         ppid, pid, uid, gid;

    /* file name of enclave image */
    PAL_PTR         enclave_addr;
    PAL_SEC_STR     enclave_image;

    /* enclave information */
    sgx_arch_hash_t         mrenclave;
    sgx_arch_hash_t         mrsigner;
    sgx_arch_attributes_t   enclave_attributes;

    /* remaining heap usable by application */
    PAL_PTR         heap_min, heap_max;

    /* executable name, addr and size */
    PAL_SEC_STR     exec_name;
    PAL_IDX         exec_fd;
    PAL_PTR         exec_addr;
    PAL_NUM         exec_size;

    /* manifest name, addr and size */
    PAL_SEC_STR     manifest_name;
    PAL_IDX         manifest_fd;
    PAL_PTR         manifest_addr;
    PAL_NUM         manifest_size;

    /* need three proc fds if it has a parent */
    PAL_IDX         proc_fds[3];

    /* additional information */
    PAL_SEC_STR     pipe_prefix;
    PAL_IDX         mcast_port, mcast_srv, mcast_cli;

#ifdef DEBUG
    PAL_BOL         in_gdb;
#endif

#if PRINT_ENCLAVE_STAT == 1
    PAL_NUM         start_time;
#endif
};

#ifdef IN_ENCLAVE
extern struct pal_sec pal_sec;
#endif

#define GRAPHENE_TEMPDIR        "/tmp/graphene"
#define GRAPHENE_PIPEDIR        GRAPHENE_TEMPDIR "/pipes"

#define PROC_INIT_FD    255

#define MCAST_GROUP "239.0.0.1"

#endif /* PAL_SECURITY_H */
