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

#include <pal_internal.h>
#include <pal_linux.h>
#include <pal_linux_error.h>
#include <pal_security.h>

int sgx_get_quote(const sgx_spid_t* spid, const sgx_quote_nonce_t* nonce,
                  const sgx_report_data_t* report_data, bool linkable,
                  char** quote, size_t* quote_len) {
    /* must align all arguments to sgx_report() so that EREPORT doesn't complain */
    __sgx_mem_aligned sgx_report_t report;
    __sgx_mem_aligned sgx_target_info_t targetinfo = pal_sec.qe_targetinfo;
    __sgx_mem_aligned sgx_report_data_t _report_data = *report_data;

    int ret = sgx_report(&targetinfo, &_report_data, &report);
    if (ret) {
        SGX_DBG(DBG_E, "Failed to get enclave report\n");
        return -PAL_ERROR_DENIED;
    }

    ret = ocall_get_quote(spid, linkable, &report, nonce, quote, quote_len);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Failed to get quote\n");
        return unix_to_pal_error(ERRNO(ret));
    }
    return 0;
 }
