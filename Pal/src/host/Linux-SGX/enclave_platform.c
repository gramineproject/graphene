/* Copyright (C) 2019, Texas A&M University.

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

#include <pal_linux.h>
#include <pal_linux_error.h>
#include <pal_internal.h>
#include <pal_debug.h>
#include <pal_security.h>
#include <pal_crypto.h>
#include <api.h>

/**
 * Obtain enclave report (sgx_report_t) and call out of the enclave to interact with IAS. Returns
 * the IAS report (#ias_report) and meta-data (HTTP headers, #ias_header).
 *
 * @param spid
 * @param subkey
 * @param nonce
 * @param report_data
 * @param linkable
 * @param ias_report
 * @param ias_report_len
 * @param ias_header
 * @param ias_header_len
 * @return 0 on success, < 0 otherwise.
 */
int sgx_get_attestation(sgx_spid_t* spid, const char* subkey, sgx_quote_nonce_t* nonce,
                        sgx_report_data_t* report_data, bool linkable,
                        char** ias_report, size_t* ias_report_len, char** ias_header, size_t* ias_header_len) {

    SGX_DBG(DBG_S, "Request quote:\n");
    SGX_DBG(DBG_S, "  spid:  %s\n", ALLOCA_BYTES2HEXSTR(*spid));
    SGX_DBG(DBG_S, "  type:  %s\n", linkable ? "linkable" : "unlinkable");
    SGX_DBG(DBG_S, "  nonce: %s\n", ALLOCA_BYTES2HEXSTR(*nonce));

    __sgx_mem_aligned sgx_report_t report;
    __sgx_mem_aligned sgx_target_info_t targetinfo = pal_sec.qe_targetinfo;

    int ret = sgx_report(&targetinfo, report_data, &report);
    if (ret) {
        SGX_DBG(DBG_E, "Failed to get report for attestation\n");
        return -PAL_ERROR_DENIED;
    }

    ret = ocall_get_attestation(spid, subkey, linkable, &report, nonce, ias_report, ias_report_len,
                                ias_header, ias_header_len);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to get attestation\n");
        return unix_to_pal_error(ERRNO(ret));
    }

    return 0;
}

/**
 * Obtain enclave report (sgx_report_t) and call out of the enclave to interact with quoting enclave
 * via AESMD. Returns the #quote.
 *
 * @param spid[in]
 * @param nonce[in]
 * @param report_data[in]
 * @param linkable[in]
 * @param quote[out]
 * @param quote_len[out]
 * @return 0 on success, < 0 otherwise.
 */
int sgx_get_quote(const sgx_spid_t* spid, sgx_quote_nonce_t* nonce, sgx_report_data_t* report_data,
                  bool linkable, uint8_t** quote, size_t* quote_len) {
    __sgx_mem_aligned sgx_report_t report;
    __sgx_mem_aligned sgx_target_info_t targetinfo = pal_sec.qe_targetinfo;
    __sgx_mem_aligned sgx_report_data_t _report_data = *report_data;

    int ret = sgx_report(&targetinfo, &_report_data, &report);
    if (ret) {
        SGX_DBG(DBG_E, "Failed to get enclave report\n");
        return -PAL_ERROR_DENIED;
    }

    ret = ocall_get_quote(spid, linkable, &report, nonce, (char**) quote, quote_len);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to get quote\n");
        return unix_to_pal_error(ERRNO(ret));
    }

    return 0;
}
