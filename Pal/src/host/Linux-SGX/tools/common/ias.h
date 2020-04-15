/* Copyright (C) 2018-2020 Invisible Things Lab
                           Rafal Wojdyla <omeg@invisiblethingslab.com>
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

#ifndef _IAS_H
#define _IAS_H

#include <stddef.h>
#include <stdint.h>

/*! Context used in ias_*() calls. */
struct ias_context_t;

/*!
 * \brief Create and initialize context used for IAS communication.
 *
 * \param[in] ias_api_key    API key for IAS access.
 * \param[in] ias_verify_url URL for IAS attestation verification API.
 * \param[in] ias_sigrl_url  URL for IAS "Retrieve SigRL" API.
 * \return Context to be used in further ias_* calls or NULL on failure.
 *
 * \details Should be called once, before handling any request.
 */
struct ias_context_t* ias_init(const char* ias_api_key, const char* ias_verify_url,
                               const char* ias_sigrl_url);

/*!
 * \brief Clean up and free context used for IAS communication.
 *
 * \param[in] context IAS context returned by ias_init().
 * \details Should be called once, after serving last request.
 */
void ias_cleanup(struct ias_context_t* context);

/*!
 * \brief Get the signature revocation list for a given EPID group.
 *
 * \param[in]  context    IAS context returned by ias_init().
 * \param[in]  gid        EPID group ID to get SigRL for.
 * \param[out] sigrl_size Size of the SigRL (may be 0).
 * \param[out] sigrl      SigRL data, needs to be freed by the caller.
 * \return 0 on success, -1 otherwise.
 */
int ias_get_sigrl(struct ias_context_t* context, uint8_t gid[4], size_t* sigrl_size, void** sigrl);

/*!
 * \brief Send quote to IAS for verification.
 *
 * \param[in] context       IAS context returned by ias_init().
 * \param[in] quote         Binary quote data blob.
 * \param[in] quote_size    Size of \a quote.
 * \param[in] nonce         (Optional) Nonce string to send with the IAS request (max 32 chars).
 * \param[in] report_path   (Optional) File to save IAS report to.
 * \param[in] sig_path      (Optional) File to save IAS report's signature to.
 * \param[in] cert_path     (Optional) File to save IAS certificate to.
 * \param[in] advisory_path (Optional) File to save IAS security advisories to.
 * \return 0 on success, -1 otherwise.
 *
 *  This version of the function is convenient for command-line utilities. To get raw IAS contents,
 *  use ias_verify_quote_raw().
 *
 * \details Sends quote to the "Verify Attestation Evidence" IAS endpoint.
 */
int ias_verify_quote(struct ias_context_t* context, const void* quote, size_t quote_size,
                     const char* nonce, const char* report_path, const char* sig_path,
                     const char* cert_path, const char* advisory_path);

/*!
 * \brief Send quote to IAS for verification (same as ias_verify_quote() but not saving to files).
 *
 * \param[in] context            IAS context returned by ias_init().
 * \param[in] quote              Binary quote data blob.
 * \param[in] quote_size         Size of \a quote.
 * \param[in] nonce              (Optional) Nonce string to send with the IAS request (max 32 chars).
 * \param[out] report_data_ptr   (Optional) Pointer to allocated IAS report.
 * \param[out] sig_data_ptr      (Optional) Pointer to allocated IAS report's signature.
 * \param[out] cert_data_ptr     (Optional) Pointer to allocated IAS certificate.
 * \param[out] advisory_data_ptr (Optional) Pointer to allocated IAS security advisories.
 * \return 0 on success, -1 otherwise.
 *
 *  This version of the function is convenient for library usage. This function allocates buffers
 *  for IAS contents and passes them to caller via \a report_data_ptr, \a sig_data_ptr,
 *  \a cert_data_ptr and \a advisory_data_ptr. The caller is responsible for freeing them.
 *  To save IAS contents to files, use ias_verify_quote().
 *
 * \details Sends quote to the "Verify Attestation Evidence" IAS endpoint.
 */
int ias_verify_quote_raw(struct ias_context_t* context, const void* quote, size_t quote_size,
                         const char* nonce, char** report_data_ptr, char** sig_data_ptr,
                         char** cert_data_ptr, char** advisory_data_ptr);
#endif /* _IAS_H */
