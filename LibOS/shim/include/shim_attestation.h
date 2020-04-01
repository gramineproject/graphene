/* Copyright (C) 2020 Intel Labs
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

/*!
 * \file
 *
 * Definitions of types and functions for LibOS attestation pseudo-FS (currently only SGX).
 */

#ifndef _SHIM_ATTESTATION_H_
#define _SHIM_ATTESTATION_H_

#include <stdint.h>

#pragma pack(push, 1)

#define __sgx_mem_aligned __attribute__((aligned(512)))

#define SGX_HASH_SIZE 32
#define SGX_MAC_SIZE  16

typedef struct _sgx_measurement_t {
    uint8_t m[SGX_HASH_SIZE];
} sgx_measurement_t;

typedef uint8_t sgx_mac_t[SGX_MAC_SIZE];

typedef struct _sgx_attributes_t {
    uint64_t flags;
    uint64_t xfrm;
} sgx_attributes_t;

#define SGX_CPUSVN_SIZE      16
#define SGX_CONFIGID_SIZE    64
#define SGX_KEYID_SIZE       32
#define SGX_REPORT_DATA_SIZE 64

typedef struct _sgx_cpu_svn_t {
    uint8_t svn[SGX_CPUSVN_SIZE];
} sgx_cpu_svn_t;

typedef uint32_t sgx_misc_select_t;
typedef uint16_t sgx_prod_id_t;
typedef uint16_t sgx_isv_svn_t;
typedef uint16_t sgx_config_svn_t;
typedef uint8_t  sgx_config_id_t[SGX_CONFIGID_SIZE];

#define SGX_ISVEXT_PROD_ID_SIZE 16
#define SGX_ISV_FAMILY_ID_SIZE  16

typedef uint8_t sgx_isvext_prod_id_t[SGX_ISVEXT_PROD_ID_SIZE];
typedef uint8_t sgx_isvfamily_id_t[SGX_ISV_FAMILY_ID_SIZE];

typedef struct _sgx_key_id_t {
    uint8_t id[SGX_KEYID_SIZE];
} sgx_key_id_t;

typedef struct _sgx_report_data_t {
    uint8_t d[SGX_REPORT_DATA_SIZE];
} sgx_report_data_t;

typedef struct _report_body_t {
    sgx_cpu_svn_t        cpu_svn;
    sgx_misc_select_t    misc_select;
    uint8_t              reserved1[12];
    sgx_isvext_prod_id_t isv_ext_prod_id;
    sgx_attributes_t     attributes;
    sgx_measurement_t    mr_enclave;
    uint8_t              reserved2[32];
    sgx_measurement_t    mr_signer;
    uint8_t              reserved3[32];
    sgx_config_id_t      config_id;
    sgx_prod_id_t        isv_prod_id;
    sgx_isv_svn_t        isv_svn;
    sgx_config_svn_t     config_svn;
    uint8_t              reserved4[42];
    sgx_isvfamily_id_t   isv_family_id;
    sgx_report_data_t    report_data;
} sgx_report_body_t;

typedef struct _report_t {
    sgx_report_body_t body;
    sgx_key_id_t      key_id;
    sgx_mac_t         mac;
} sgx_report_t;

typedef struct _target_info_t {
    sgx_measurement_t mr_enclave;
    sgx_attributes_t  attributes;
    uint8_t           reserved1[2];
    sgx_config_svn_t  config_svn;
    sgx_misc_select_t misc_select;
    uint8_t           reserved2[8];
    sgx_config_id_t   config_id;
    uint8_t           reserved3[384];
} sgx_target_info_t;
static_assert(sizeof(sgx_target_info_t) == 512, "incorrect struct size");

/* typical SGX quotes are around 1K in size, overapproximate to 2K */
#define SGX_QUOTE_MAX_SIZE 2048

#pragma pack(pop)

#define ENCLU ".byte 0x0f, 0x01, 0xd7"
#define EREPORT     0

/*!
 * \brief Low-level wrapper around EREPORT instruction leaf.
 *
 * Caller is responsible for parameter alignment: 512B for \p targetinfo, 128B for \p reportdata,
 * and 512B for \p report.
 */
static inline int sgx_report(const sgx_target_info_t* targetinfo,
                             const void* reportdata, sgx_report_t* report) {
    __asm__ volatile(
        ENCLU "\n"
        :: "a"(EREPORT), "b"(targetinfo), "c"(reportdata), "d"(report)
        : "memory");
    return 0;
}

#endif
