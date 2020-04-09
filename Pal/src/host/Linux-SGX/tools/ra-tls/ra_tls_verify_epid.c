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

/*!
 * \file
 *
 * This file contains the implementation of verification callbacks for TLS libraries. The callbacks
 * verify the correctness of a self-signed RA-TLS certificate with an SGX quote embedded in it. The
 * callbacks access Intel Attestation Service (IAS) for EPID-based attestation as part of the
 * verification process. A callback ra_tls_verify_callback() can be used directly in mbedTLS, and
 * a more generic version ra_tls_verify_callback_der() should be used for other TLS libraries.
 *
 * This file is part of the RA-TLS verification library which is typically linked into client
 * applications. This library is *not* thread-safe.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

#include "attestation.h"
#include "ias.h"
#include "ra_tls.h"
#include "sgx_arch.h"
#include "sgx_attest.h"
#include "util.h"

#include "ra_tls_verify_common.c"

/** Default base URL for IAS API endpoints. Remove "/dev" for production environment. */
#define IAS_URL_BASE "https://api.trustedservices.intel.com/sgx/dev"

/** Default URL for IAS "verify attestation evidence" API endpoint. */
#define IAS_URL_REPORT IAS_URL_BASE "/attestation/v3/report"

/** Default URL for IAS "Retrieve SigRL" API endpoint. EPID group id is added at the end. */
#define IAS_URL_SIGRL IAS_URL_BASE "/attestation/v3/sigrl"

static char* g_api_key         = NULL;
static char* g_report_url      = NULL;
static char* g_sigrl_url       = NULL;

static int init_api_key(void) {
    if (g_api_key) {
        /* already initialized */
        return 0;
    }

    char* envvar_key = getenv(RA_TLS_EPID_API_KEY);
    if (!envvar_key)
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;

    size_t envvar_key_size = strlen(envvar_key) + 1;
    g_api_key = malloc(envvar_key_size);
    if (!g_api_key)
        return MBEDTLS_ERR_X509_ALLOC_FAILED;

    memcpy(g_api_key, envvar_key, envvar_key_size);
    return 0;
}

static int init_report_url(void) {
    if (g_report_url) {
        /* already initialized */
        return 0;
    }

    char* envvar_url = getenv(RA_TLS_IAS_REPORT_URL);
    if (!envvar_url) {
        /* use default report URL */
        g_report_url = IAS_URL_REPORT;
        return 0;
    }

    size_t envvar_url_size = strlen(envvar_url) + 1;
    g_report_url = malloc(envvar_url_size);
    if (!g_report_url)
        return MBEDTLS_ERR_X509_ALLOC_FAILED;

    memcpy(g_report_url, envvar_url, envvar_url_size);
    return 0;
}

static int init_sigrl_url(void) {
    if (g_sigrl_url) {
        /* already initialized */
        return 0;
    }

    char* envvar_url = getenv(RA_TLS_IAS_SIGRL_URL);
    if (!envvar_url) {
        /* use default signature revocation list URL */
        g_sigrl_url = IAS_URL_SIGRL;
        return 0;
    }

    size_t envvar_url_size = strlen(envvar_url) + 1;
    g_sigrl_url = malloc(envvar_url_size);
    if (!g_sigrl_url)
        return MBEDTLS_ERR_X509_ALLOC_FAILED;

    memcpy(g_sigrl_url, envvar_url, envvar_url_size);
    return 0;
}

static int generate_nonce(char* buf, size_t size) {
    if (size != IAS_REQUEST_NONCE_LEN + 1) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    char random_data[IAS_REQUEST_NONCE_LEN / 2];

    FILE* f = fopen("/dev/urandom", "r");
    if (!f)
        return MBEDTLS_ERR_X509_FILE_IO_ERROR;

    size_t nmemb = fread(&random_data, sizeof(random_data), 1, f);
    if (nmemb != 1) {
        fclose(f);
        return MBEDTLS_ERR_X509_FILE_IO_ERROR;
    }

    fclose(f);

    if (hexdump_mem_to_buffer(&random_data, sizeof(random_data), buf, size) < 0) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    return 0;
}

static int getenv_ias_pub_key_pem(const char** ias_pub_key_pem) {
    /* may be NULL (and then a hard-coded public key of IAS is used) */
    *ias_pub_key_pem = getenv(RA_TLS_IAS_PUB_KEY_PEM);
    return 0;
}

int ra_tls_verify_callback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
    (void)data;

    int ret;
    struct ias_context_t* ias = NULL;

    char* report_data   = NULL;
    char* sig_data      = NULL;
    char* cert_data     = NULL;
    char* advisory_data = NULL;

    size_t report_data_size   = 0;
    size_t sig_data_size      = 0;
    size_t cert_data_size     = 0;
    size_t advisory_data_size = 0;

    if (depth != 0) {
        /* only interested in peer cert (at the end of cert chain): it contains RA-TLS info */
        return 0;
    }

    if (flags) {
        /* mbedTLS sets flags to signal that the cert is not to be trusted (e.g., it is not
         * correctly signed by a trusted CA; since RA-TLS uses self-signed certs, we don't care
         * what mbedTLS thinks and ignore internal cert verification logic of mbedTLS */
        *flags = 0;
    }

    ret = init_api_key();
    if (ret < 0)
        goto out;

    ret = init_report_url();
    if (ret < 0)
        goto out;

    ret = init_sigrl_url();
    if (ret < 0)
        goto out;

    /* extract SGX quote from "quote" OID extension from crt */
    sgx_quote_t* quote;
    size_t quote_size;
    ret = find_oid(crt->v3_ext.p, crt->v3_ext.len, quote_oid, quote_oid_len, (uint8_t**)&quote,
                   &quote_size);
    if (ret < 0)
        goto out;

    if (quote_size < sizeof(*quote)) {
        ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        goto out;
    }

    /* compare public key's hash from cert against quote's report_data */
    ret = cmp_crt_pk_against_quote_report_data(crt, quote);
    if (ret < 0)
        goto out;

    /* initialize the IAS context, send the quote to the IAS and receive IAS attestation report */
    ias = ias_init(g_api_key, g_report_url, g_sigrl_url);
    if (!ias) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    char nonce[IAS_REQUEST_NONCE_LEN + 1];
    ret = generate_nonce(nonce, sizeof(nonce));
    if (ret < 0)
        goto out;

    ret = ias_verify_quote_raw(ias, quote, quote_size, nonce, &report_data, &report_data_size,
                               &sig_data, &sig_data_size, &cert_data, &cert_data_size,
                               &advisory_data, &advisory_data_size);
    if (ret < 0) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    if (!report_data || !report_data_size || !sig_data || !sig_data_size) {
        /* received IAS attestation report doesn't contain report and/or signature */
        ret = MBEDTLS_ERR_X509_INVALID_FORMAT;
        goto out;
    }

    /* verify_ias_report() expects report_data and sig_data without the ending '\0' */
    assert(report_data[report_data_size - 1] == '\0');
    report_data_size--;
    assert(sig_data[sig_data_size - 1] == '\0');
    sig_data_size--;

    /* TODO: obtain cert revocation lists via ias_get_sigrl(); currently they are not used during
     *       IAS attestation report verification, so we don't obtain them */

    /* verify all components of the received IAS attestation report */
    bool allow_outdated_tcb;
    ret = getenv_allow_outdated_tcb(&allow_outdated_tcb);
    if (ret < 0) {
        ret = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        goto out;
    }

    const char* mrsigner_hex;
    const char* mrenclave_hex;
    const char* isv_prod_id_dec;
    const char* isv_svn_dec;
    ret = getenv_enclave_measurements(&mrsigner_hex, &mrenclave_hex, &isv_prod_id_dec,
                                      &isv_svn_dec);
    if (ret < 0) {
        ret = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        goto out;
    }

    sgx_measurement_t expected_mrsigner;
    if (mrsigner_hex) {
        if (parse_hex(mrsigner_hex, &expected_mrsigner, sizeof(expected_mrsigner)) != 0) {
            ret = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
            goto out;
        }
    }

    sgx_measurement_t expected_mrenclave;
    if (mrenclave_hex) {
        if (parse_hex(mrenclave_hex, &expected_mrenclave, sizeof(expected_mrenclave)) != 0) {
            ret = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
            goto out;
        }
    }

    sgx_prod_id_t expected_isv_prod_id;
    if (isv_prod_id_dec) {
        expected_isv_prod_id = strtoul(isv_prod_id_dec, NULL, 10);
    }

    sgx_isv_svn_t expected_isv_svn;
    if (isv_svn_dec) {
        expected_isv_svn = strtoul(isv_svn_dec, NULL, 10);
    }

    const char* ias_pub_key_pem;
    ret = getenv_ias_pub_key_pem(&ias_pub_key_pem);
    if (ret < 0) {
        ret = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        goto out;
    }

    char* user_report_data = (char*)quote->report_body.report_data.d;

    ret = verify_ias_report((uint8_t*)report_data, report_data_size,
                            (uint8_t*)sig_data, sig_data_size,
                            allow_outdated_tcb, nonce,
                            mrsigner_hex ? (char*)&expected_mrsigner : NULL,
                            mrenclave_hex ? (char*)&expected_mrenclave : NULL,
                            isv_prod_id_dec ? (char*)&expected_isv_prod_id : NULL,
                            isv_svn_dec ? (char*)&expected_isv_svn : NULL,
                            user_report_data, ias_pub_key_pem, /*expected_as_str=*/false);
    if (ret < 0) {
        ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        goto out;
    }

    ret = 0;
out:
    if (ias)
        ias_cleanup(ias);

    free(report_data);
    free(sig_data);
    free(cert_data);
    free(advisory_data);

    return ret;
}
