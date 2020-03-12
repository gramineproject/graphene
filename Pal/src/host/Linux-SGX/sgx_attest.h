/* Copyright (C) 2017, Texas A&M University.

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

#include <stdint.h>

#include "sgx_arch.h"

typedef struct {
    uint16_t version;
    uint16_t sigtype;
    uint32_t gid;
    uint16_t isvsvn_qe;
    uint16_t isvsvn_pce;
    uint8_t reserved[4];
    uint8_t base[32];
} __attribute__((packed)) sgx_quote_body_t;

typedef struct {
    sgx_quote_body_t body;
    sgx_report_body_t report_body;
    uint32_t sig_len;
} __attribute__((packed)) sgx_quote_t;

typedef uint8_t sgx_spid_t[16];
typedef uint8_t sgx_quote_nonce_t[16];

enum {
    SGX_UNLINKABLE_SIGNATURE,
    SGX_LINKABLE_SIGNATURE
};

#define SGX_QUOTE_MAX_SIZE 2048

/*!
 * \brief Obtain SGX Quote from the Quoting Enclave (communicate via AESM).
 *
 * First create my enclave report (sgx_report_t) with target info of the Quoting Enclave, and
 * then call out of the enclave to request the corresponding Quote from the Quoting Enclave.
 * Communication is done via AESM service, in the form of protobuf request/response messages.
 *
 * \param spid[in]         Software provider ID (SPID).
 * \param nonce[in]        16B nonce to be included in the quote for freshness.
 * \param report_data[in]  64B bytestring to be included in the report and the quote.
 * \param linkable[in]     Quote type (linkable vs unlinkable).
 * \param quote[out]       Quote returned by the Quoting Enclave.
 * \param quote_len[out]   Length of the quote returned by the Quoting Enclave.
 * \return                 0 on success, negative PAL error code otherwise.
 */
int sgx_get_quote(const sgx_spid_t* spid, const sgx_quote_nonce_t* nonce,
                  const sgx_report_data_t* report_data, bool linkable,
                  char** quote, size_t* quote_len);

#define IAS_REPORT_URL "https://api.trustedservices.intel.com/sgx/dev/attestation/v3/report"

int init_trusted_platform(void);

typedef struct {
    sgx_report_t qe_report;
    sgx_quote_t* quote;
    size_t       quote_len;
    char*        ias_report;
    size_t       ias_report_len;
    uint8_t*     ias_sig;
    size_t       ias_sig_len;
    char*        ias_certs;
    size_t       ias_certs_len;
} __attribute__((packed)) sgx_attestation_t;

int sgx_verify_platform(sgx_spid_t* spid, const char* subkey, sgx_quote_nonce_t* nonce,
                        sgx_report_data_t* report_data, bool linkable,
                        bool accept_group_out_of_date, bool accept_configuration_needed,
                        sgx_attestation_t* ret_attestation, char** ret_ias_status,
                        char** ret_ias_timestamp);

#define HTTPS_REQUEST_MAX_LENGTH 256

#endif /* SGX_ATTEST_H */
