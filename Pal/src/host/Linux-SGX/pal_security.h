/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#ifndef PAL_SECURITY_H
#define PAL_SECURITY_H

#include "pal.h"
#include "sgx_arch.h"

typedef char PAL_SEC_STR[255];

struct pal_sec {
    /* host credentials */
    PAL_NUM         instance_id;
    PAL_IDX         ppid, pid, uid, gid;

    /* enclave information */
    sgx_target_info_t  qe_targetinfo;
    sgx_measurement_t  mr_enclave;
    sgx_measurement_t  mr_signer;
    sgx_attributes_t   enclave_attributes;

    /* remaining heap usable by application and whether to zero it on demand/during init */
    PAL_PTR         heap_min, heap_max;
    PAL_BOL         zero_heap_on_demand;

    /* executable name, addr and size */
    PAL_SEC_STR     exec_name;
    PAL_PTR         exec_addr;
    PAL_NUM         exec_size;

    PAL_SEC_STR     manifest_name;

    /* child's stream FD created and sent over by parent */
    PAL_IDX         stream_fd;

    /* additional information */
    PAL_SEC_STR     pipe_prefix;

    /* Need to pass in the number of cores */
    PAL_NUM         num_cpus;

#ifdef DEBUG
    PAL_BOL         in_gdb;
#endif

#if PRINT_ENCLAVE_STAT == 1
    PAL_NUM         start_time;
#endif
};

#ifdef IN_ENCLAVE
extern struct pal_sec g_pal_sec;
#endif

#define GRAPHENE_TEMPDIR        "/tmp/graphene"
#define GRAPHENE_PIPEDIR        (GRAPHENE_TEMPDIR "/pipes")

#endif /* PAL_SECURITY_H */
