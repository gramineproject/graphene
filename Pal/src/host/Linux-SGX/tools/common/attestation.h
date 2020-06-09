/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2018-2020 Invisible Things Lab
 *                         Rafal Wojdyla <omeg@invisiblethingslab.com>
 */

#ifndef ATTESTATION_H
#define ATTESTATION_H

#include <stdbool.h>
#include <stdint.h>

#include "sgx_arch.h"

/*!
 *  \brief Display internal SGX quote structure.
 *
 *  \param[in] quote_data Buffer with quote data. This can be a full quote (sgx_quote_t)
 *                        or a quote from IAS attestation report (which is missing signature
 *                        fields).
 *  \param[in] quote_size Size of \a quote_data in bytes.
 */
void display_quote(const void* quote_data, size_t quote_size);

/*!
 *  \brief Display internal SGX report body structure (sgx_report_body_t).
 *
 *  \param[in] body Buffer with report body data.
 */
void display_report_body(const sgx_report_body_t* body);

/*!
 *  \brief Verify IAS attestation report. Also verify that the quote contained in IAS report
 *         is valid and matches expected values.
 *
 *  \param[in] ias_report         IAS attestation verification report.
 *  \param[in] ias_report_size    Size of \a ias_report in bytes.
 *  \param[in] ias_sig_b64        IAS report signature (base64-encoded as returned by IAS).
 *  \param[in] ias_sig_b64_size   Size of \a ias_sig_b64 in bytes.
 *  \param[in] allow_outdated_tcb Treat IAS status GROUP_OUT_OF_DATE as OK.
 *  \param[in] nonce              (Optional) Nonce that's expected in the report.
 *  \param[in] mr_signer          (Optional) Expected mr_signer quote field.
 *  \param[in] mr_enclave         (Optional) Expected mr_enclave quote field.
 *  \param[in] isv_prod_id        (Optional) Expected isv_prod_id quote field.
 *  \param[in] isv_svn            (Optional) Expected isv_svn quote field.
 *  \param[in] report_data        (Optional) Expected report_data quote field.
 *  \param[in] ias_pub_key_pem    (Optional) IAS public RSA key (PEM format, NULL-terminated).
 *                                If not specified, a hardcoded Intel's key is used.
 *  \param[in] expected_as_str    If true, then all expected SGX fields are treated as hex and
 *                                decimal strings. Otherwise, they are treated as raw bytes.
 *
 *  If \a expected_as_str is true, then \a mr_signer, \a mr_enclave and \a report_data are treated
 *  as hex strings, and \a isv_prod_id and a isv_svn are treated as decimal strings. This is
 *  convenient for command-line utilities.
 *
 *  \return 0 on successful verification, negative value on error.
 */
int verify_ias_report(const uint8_t* ias_report, size_t ias_report_size, uint8_t* ias_sig_b64,
                      size_t ias_sig_b64_size, bool allow_outdated_tcb, const char* nonce,
                      const char* mrsigner, const char* mrenclave, const char* isv_prod_id,
                      const char* isv_svn, const char* report_data, const char* ias_pub_key_pem,
                      bool expected_as_str);

/*!
 *  \brief Verify that the provided SGX quote contains expected values.
 *
 *  \param[in] quote_data      Quote to verify.
 *  \param[in] quote_size      Size of \a quote_data in bytes.
 *  \param[in] mr_signer       (Optional) Expected mr_signer quote field.
 *  \param[in] mr_enclave      (Optional) Expected mr_enclave quote field.
 *  \param[in] isv_prod_id     (Optional) Expected isv_prod_id quote field.
 *  \param[in] isv_svn         (Optional) Expected isv_svn quote field.
 *  \param[in] report_data     (Optional) Expected report_data quote field.
 *  \param[in] expected_as_str If true, then all expected SGX fields are treated as hex and
 *                             decimal strings. Otherwise, they are treated as raw bytes.
 *
 *  If \a expected_as_str is true, then \a mr_signer, \a mr_enclave and \a report_data are treated
 *  as hex strings, and \a isv_prod_id and a isv_svn are treated as decimal strings. This is
 *  convenient for command-line utilities.
 *
 *  \return 0 on successful verification, negative value on error.
 */
int verify_quote(const void* quote_data, size_t quote_size, const char* mr_signer,
                 const char* mr_enclave, const char* isv_prod_id, const char* isv_svn,
                 const char* report_data, bool expected_as_str);

#endif /* ATTESTATION_H */
