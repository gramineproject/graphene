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

#pragma pack(push, 1)

typedef uint8_t sgx_epid_group_id_t[4];

typedef struct _sgx_basename_t {
    uint8_t name[32];
} sgx_basename_t;

typedef struct _sgx_quote_t {
    uint16_t version;
    uint16_t sign_type;
    sgx_epid_group_id_t epid_group_id;
    sgx_isv_svn_t qe_svn;
    sgx_isv_svn_t pce_svn;
    uint32_t xeid;
    sgx_basename_t basename;
    sgx_report_body_t report_body;
    uint32_t signature_len;
    uint8_t signature[];
} sgx_quote_t;

#define SGX_QUOTE_BODY_SIZE (offsetof(sgx_quote_t, signature_len))

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
 * First create enclave report (sgx_report_t) with target info of the Quoting Enclave, and
 * then call out of the enclave to request the corresponding Quote from the Quoting Enclave.
 * Communication is done via AESM service, in the form of protobuf request/response messages.
 *
 * \param[in]  spid         Software provider ID (SPID).
 * \param[in]  nonce        16B nonce to be included in the quote for freshness.
 * \param[in]  report_data  64B bytestring to be included in the report and the quote.
 * \param[in]  linkable     Quote type (linkable vs unlinkable).
 * \param[out] quote        Quote returned by the Quoting Enclave (allocated via malloc() in this
 *                          function; the caller gets the ownership of the quote).
 * \param[out] quote_len    Length of the quote returned by the Quoting Enclave.
 * \return                  0 on success, negative PAL error code otherwise.
 */
int sgx_get_quote(const sgx_spid_t* spid, const sgx_quote_nonce_t* nonce,
                  const sgx_report_data_t* report_data, bool linkable,
                  char** quote, size_t* quote_len);

#pragma pack(pop)

#endif /* SGX_ATTEST_H */
