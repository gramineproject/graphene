/* Copyright (C) 2018-2020 Intel Labs
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

#include <stdint.h>
#include <mbedtls/x509_crt.h>

#define RA_TLS_EPID_API_KEY "RA_TLS_EPID_API_KEY"

#define RA_TLS_ALLOW_OUTDATED_TCB "RA_TLS_ALLOW_OUTDATED_TCB"

#define RA_TLS_MRSIGNER    "RA_TLS_MRSIGNER"
#define RA_TLS_MRENCLAVE   "RA_TLS_MRENCLAVE"
#define RA_TLS_ISV_PROD_ID "RA_TLS_ISV_PROD_ID"
#define RA_TLS_ISV_SVN     "RA_TLS_ISV_SVN"

#define RA_TLS_IAS_PUB_KEY_PEM "RA_TLS_IAS_PUB_KEY_PEM"
#define RA_TLS_IAS_REPORT_URL   "RA_TLS_IAS_REPORT_URL"
#define RA_TLS_IAS_SIGRL_URL    "RA_TLS_IAS_SIGRL_URL"

#define RA_TLS_CERT_TIMESTAMP_NOT_BEFORE "RA_TLS_CERT_TIMESTAMP_NOT_BEFORE"
#define RA_TLS_CERT_TIMESTAMP_NOT_AFTER  "RA_TLS_CERT_TIMESTAMP_NOT_AFTER"

#define SHA256_DIGEST_SIZE 32
#define RSA_PUB_3072_KEY_LEN 3072
#define RSA_PUB_3072_KEY_DER_LEN 422
#define RSA_PUB_EXPONENT 65537
#define PUB_KEY_SIZE_MAX 512
#define IAS_REQUEST_NONCE_LEN 32

#define OID(N) {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, (N)}
static const uint8_t quote_oid[] = OID(0x06);
static const size_t quote_oid_len = sizeof(quote_oid);
#define QUOTE_MAX_SIZE 8192

/*!
 * \brief mbedTLS-suitable verification callback for EPID-based (IAS) or ECDSA-based (DCAP)
 * quote verification.
 *
 * This callback must be registered via mbedtls_ssl_conf_verify(). All parameters required for
 * the SGX quote, IAS attestation report verification, and/or DCAP quote verification  must be
 * passed in the corresponding RA-TLS environment variables.
 *
 * \param[in] data   Unused (required due to mbedTLS callback function signature).
 * \param[in] crt    Self-signed RA-TLS certificate with SGX quote embedded.
 * \param[in] depth  Unused (required due to mbedTLS callback function signature).
 * \param[in] flags  Unused (required due to mbedTLS callback function signature).
 *
 * \return           0 on success, specific mbedTLS error code (negative int) otherwise.
 */
__attribute__((weak)) int ra_tls_verify_callback(void* data, mbedtls_x509_crt* crt, int depth,
                                                 uint32_t* flags);

/*!
 * \brief Generic verification callback for EPID-based (IAS) or ECDSA-based (DCAP) quote
 * verification.
 *
 * This function must be called from a non-mbedTLS verification callback, e.g., from a user-defined
 * OpenSSL callback for SSL_CTX_set_cert_verify_callback(). All parameters required for the SGX
 * quote, IAS attestation report verification, and/or DCAP quote verification must be passed in the
 * corresponding RA-TLS environment variables.
 *
 * \param[in] der_crt       Self-signed RA-TLS certificate with SGX quote embedded in DER format.
 * \param[in] der_crt_size  Size of the RA-TLS certificate.
 *
 * \return                  0 on success, specific mbedTLS error code (negative int) otherwise.
 */
__attribute__((weak)) int ra_tls_verify_callback_der(uint8_t *der_crt, size_t der_crt_size);

/*!
 * \brief mbedTLS-suitable function to generate a key and a corresponding RA-TLS certificate.
 *
 * The function first generates a random RSA keypair with PKCS#1 v1.5 encoding. Then it calculates
 * the SHA256 hash over the generated public key and retrieves an SGX quote with report_data equal
 * to the calculated hash (this ties the generated certificate key to the SGX quote). Finally, it
 * generates the X.509 self-signed certificate with this key and the SGX quote embedded.
 *
 * \param[out] key   Populated with a generated RSA keypair.
 * \param[out] crt   Populated with a self-signed RA-TLS certificate with SGX quote embedded.
 *
 * \return           0 on success, specific mbedTLS error code (negative int) otherwise.
 */
__attribute__((weak)) int ra_tls_create_key_and_crt(mbedtls_pk_context* key, mbedtls_x509_crt* crt);

/*!
 * \brief Generic function to generate a key and a corresponding RA-TLS certificate (DER format).
 *
 * The function behaves the same as ra_tls_create_key_and_crt() but generates key and certificate
 * in the DER format.
 *
 * \param[out]    der_key       Buffer populated with a generated RSA keypair in DER format.
 * \param[in,out] der_key_size  Caller specifies size of buffer; actual size of key on return.
 * \param[out]    der_crt       Buffer populated with a self-signed RA-TLS certificate.
 * \param[in,out] der_crt_size  Caller specifies size of buffer; actual size of cert on return.
 *
 * \return                      0 on success, specific mbedTLS error code (negative int) otherwise.
 */
__attribute__((weak)) int ra_tls_create_key_and_crt_der(uint8_t* der_key, size_t* der_key_size,
                                                        uint8_t* der_crt, size_t* der_crt_size);
