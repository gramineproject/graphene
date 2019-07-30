/* Copyright (C) 2017, University of North Carolina at Chapel Hill
   and Fortanix, Inc.
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

#ifndef SGX_ATTEST_H
#define SGX_ATTEST_H

#include "sgx_arch.h"

#include <stdint.h>

typedef struct {
    uint16_t version;
    uint16_t sigtype;
    uint32_t gid;
    uint16_t isvsvn_qe;
    uint16_t isvsvn_pce;
    uint8_t  reserved[4];
    uint8_t  base[32];
} __attribute__((packed)) sgx_quote_body_t;

typedef struct {
    sgx_quote_body_t       body;
    sgx_arch_report_body_t report_body;
    uint32_t               sig_len;
} __attribute__((packed)) sgx_quote_t;

#define SGX_QUOTE_MAX_SIZE   (2048)

typedef uint8_t sgx_spid_t[16];
typedef uint8_t sgx_quote_nonce_t[16];

#define IAS_TEST_REPORT_URL \
    "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v3/report"

int init_trusted_platform(void);

int sgx_verify_platform(sgx_spid_t* spid, sgx_quote_nonce_t* nonce,
                        sgx_arch_report_data_t* report_data, bool linkable);

#endif /* SGX_ATTEST_H */
