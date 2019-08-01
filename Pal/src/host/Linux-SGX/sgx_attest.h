/* Copyright (C) 2017, University of North Carolina at Chapel Hill.

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

typedef uint8_t sgx_spid_t[16];
typedef uint8_t sgx_quote_nonce_t[16];

enum {
    SGX_UNLINKABLE_SIGNATURE,
    SGX_LINKABLE_SIGNATURE
};

#define SGX_QUOTE_MAX_SIZE   (2048)

#define IAS_TEST_REPORT_URL \
    "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v3/report"

int init_trusted_platform(void);

typedef struct {
    sgx_arch_report_t qe_report;
    sgx_quote_t*      quote;
    size_t            quote_len;
    char*             ias_report;
    size_t            ias_report_len;
    uint8_t*          ias_sig;
    size_t            ias_sig_len;
    char*             ias_certs;
    size_t            ias_certs_len;
} sgx_attestation_t;

int sgx_verify_platform(sgx_spid_t* spid, sgx_quote_nonce_t* nonce,
                        sgx_arch_report_data_t* report_data, bool linkable,
                        sgx_attestation_t** ret_attestation,
                        char** ret_ias_status, char** ret_ias_timestamp);

#define HTTPS_REQUEST_MAX_LENGTH   (256)

#endif /* SGX_ATTEST_H */
