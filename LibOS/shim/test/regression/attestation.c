/* Attestation API test. Only works for SGX PAL. */

#define _GNU_SOURCE             /* for memmem() */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mbedtls/base64.h>
#include <mbedtls/cmac.h>
#include <mbedtls/pk.h>
#include <mbedtls/pk_internal.h>
#include <mbedtls/x509_crt.h>

#include "sgx_api.h"
#include "sgx_arch.h"
#include "sgx_attest.h"

#include "quote/generated-cacert.h"

enum { SUCCESS = 0, FAILURE = -1 };

/**
 * Verify the signature on 'report'. If verification succeeds, it means the enclave which produced
 * 'report' runs on same platform as the enclave executing this function.
 *
 * @return 0 if signature verification succeeds, -1 otherwise.
 */
static int verify_report_mac(sgx_report_t* report) {
    // Setup key request structure.
    sgx_key_request_t key_request __attribute__((aligned(512)));
    memset(&key_request, 0, sizeof(key_request));
    key_request.key_name = REPORT_KEY;
    memcpy(&key_request.key_id, &report->key_id, sizeof(key_request.key_id));

    uint8_t key[128/8] __attribute__((aligned(16)));
    memset(key, 0, sizeof(key));

    // Retrieve key via EGETKEY instruction leaf.
    sgx_getkey(&key_request, (sgx_key_128bit_t*)key);

    // Calculate message authentication code (MAC) over report body.
    sgx_mac_t mac = {0, };

    const mbedtls_cipher_info_t* cipher_info =
        mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);

    const int bits_per_byte  = 8;
    // Signature calculated over first 384 bytes of report structure.
    const size_t report_body_size_bytes = 384;
    int rc = mbedtls_cipher_cmac(cipher_info, key, sizeof(key) * bits_per_byte,
                                 (const unsigned char*)report, report_body_size_bytes,
                                 (uint8_t*)&mac);
    if (rc)
        abort();

    // Compare calculated MAC to MAC sent with report.
    int ret = memcmp(&mac, report->mac, sizeof(mac));

    return ret == 0 ? 0 : -1;
}

char report_data_str[] = "I heart SGX!";

/**
 * Exercise local attestation interface. Perform the following steps in order:
 *
 * 1. Read ../my_target_info
 * 2. Write data from ../my_target_info to ../target_info
 * 3. Write some custom data to ../report_data
 * 4. Read ../report
 * 5. Verify data read from ../report. Since we used the current enclave's target_info_t, we should be able to verify the report.
 */
static int test_local_attestation(void) {
    sgx_target_info_t target_info;
    int fd = open("/sys/sgx_attestation/my_target_info", O_RDONLY);
    if (fd < 0)
        return FAILURE;
    int rc = read(fd, &target_info, sizeof(target_info));
    if (rc != sizeof(target_info))
        return FAILURE;
    close(fd);

    fd = open("/sys/sgx_attestation/target_info", O_WRONLY);
    if (fd < 0)
        return FAILURE;
    rc = write(fd, &target_info, sizeof(target_info));
    if (rc != sizeof(target_info))
        return FAILURE;
    close(fd);

    sgx_report_data_t report_data = {0,};
    memcpy((void*)&report_data, (void*)report_data_str, sizeof(report_data_str));
    fd = open("/sys/sgx_attestation/report_data", O_WRONLY);
    if (fd < 0)
        return FAILURE;
    rc = write(fd, &report_data, sizeof(report_data));
    if (rc != sizeof(report_data))
        return FAILURE;
    close(fd);

    sgx_report_t report;
    fd = open("/sys/sgx_attestation/report", O_RDONLY);
    if (fd < 0)
        return FAILURE;
    rc = read(fd, &report, sizeof(report));
    if (rc != sizeof(report))
        return FAILURE;
    close(fd);

    return verify_report_mac(&report) == 0 ? SUCCESS : FAILURE;
}

/* This currently does not include 'quote', 'ias_report' and 'ias_header'. Since the quote interface
 * does not implement any caching, we do not want to have 10^6 interaction with the quoting enclave
 * as this would simply take too long. */
const char* paths[] = {
    "report",
    "report_data",
    "my_target_info",
    "target_info",
};

const char* path_prefix = "/sys/sgx_attestation";

/**
 * Repeatedly open()/close() pseudo-files to hopefully uncover resource leaks.
 */
static void resource_leak(void) {
    for (int j = 0; j < sizeof(paths) / sizeof(&paths[0]); j++) {
        for (int i=0; i < 1000000; i++) {
            char fn[64];
            snprintf(fn, sizeof(fn), "%s/%s", path_prefix, paths[j]);
            int fd = open(fn, O_RDONLY);
            if (fd < 0)
                abort();
            close(fd);
        }
    }
}

/**
 * Verfifies if #sign_cert was signed by #ias_sign_ca_cert_der.
 *
 * @param sign_cert     PEM-encoded, \0-terminated certificate.
 * @param sign_cert_len Length of #sign_cert including \0.
 * @return 0 if #sign_cert was signed by #ias_sign_ca_cert_der, -1 otherwise.
 */
static
int verify_ias_certificate_chain(const char* sign_cert, size_t sign_cert_len) {
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt_init(&cacert);
    int ret;

    ret = mbedtls_x509_crt_parse(&cacert, g_intel_sgx_root_ca_cert_der,
                                 sizeof(g_intel_sgx_root_ca_cert_der));
    if (ret != 0)
        abort();

    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    ret = mbedtls_x509_crt_parse(&cert, (const unsigned char*)sign_cert, sign_cert_len);
    if (ret != 0)
        abort();

    uint32_t flags;
    ret = mbedtls_x509_crt_verify(&cert, &cacert, NULL, NULL, &flags, NULL, NULL);

    mbedtls_x509_crt_free(&cert);
    mbedtls_x509_crt_free(&cacert);

    return ret == 0 ? 0 : -1;
}

/**
 * Verify that #signature was computed over #report with key in #sign_cert.
 *
 * @param report        Intel Attestation Service report.
 * @param report_len    Length of #report.
 * @param signature     The signature for #report.
 * @param sign_cert     PEM-encoded zero-terminated certificate.
 * @param sign_cert_len Length of #sign_cert including terminating \0.
 * @return 0 if signature verification succeeds, -1 otherwise.
 */
static
int verify_ias_report_signature(const char* report, size_t report_len,
                                const unsigned char signature[32], const char* sign_cert,
                                size_t sign_cert_len) {
    if (sign_cert[sign_cert_len-1] != '\0')
        return -EINVAL;

    // Create certificate structure
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);

    int ret = mbedtls_x509_crt_parse(&cert, (const unsigned char*)sign_cert, sign_cert_len);
    if (ret != 0)
        abort();

    // Extract RSA public key
    if (cert.pk.pk_info->type != MBEDTLS_PK_RSA)
        return FAILURE;
    mbedtls_rsa_context* rsa = (mbedtls_rsa_context*)cert.pk.pk_ctx;

    // Compute signature
    uint8_t sha256[32];
    ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char*)report,
                     report_len, sha256);
    if (ret != 0)
        abort();

    // Verify signature
    ret = mbedtls_rsa_pkcs1_verify(rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 0,
                                   sha256, signature);

    mbedtls_x509_crt_free(&cert);

    return ret;
}

/**
 * URL-decode the input string. This is a quick hack and likely fails in corner cases. Ideally, we
 * would use an existing function like, e.g., libcurl's curl_unescape(). But libcurl.so creates a
 * ton(!) of dependencies on other libraries.
 *
 * @return \0-terminated unescaped string. Caller must free().
 */
char* unescape(const char* in, size_t len) {
    if (len == 0)
        return NULL;

    /* Worst case, nothing is replaced and we need one more byte to store the terminating \0. */
    char* const out = malloc(len+1);
    char* p = out;
    for (int i = 0; i < len; i++) {
        if (in[i] == '%' && i+2 < len && isxdigit(in[i+1]) && isxdigit(in[i+2])) {
            char hexstr[3];
            char *ptr;
            hexstr[0] = in[i+1];
            hexstr[1] = in[i+2];
            hexstr[2] = 0;
            unsigned long hex = strtoul(hexstr, &ptr, 16);
            if (hex > UCHAR_MAX)
                abort();
            *p = (char) hex;
            i += 2;
        } else {
            *p = in[i];
        }
        p++;
    }
    *p = 0;
    return out;
}

/**
 *
 * @return 0 on success, < 0 otherwise.
 */
static int extract_quote_from_ias_report(const char* report, int report_len, sgx_quote_t* quote) {
    (void) report_len;

    const char* json_string = "\"isvEnclaveQuoteBody\":\"";
    char* p_begin = strstr((const char*)report, json_string);
    if (p_begin == NULL)
        return -EINVAL;
    p_begin += strlen(json_string);
    const char* p_end = strchr(p_begin, '"');
    if (p_end == NULL)
        return -EINVAL;

    const int quote_base64_len = p_end - p_begin;
    uint8_t* quote_bin = malloc(quote_base64_len);
    size_t quote_bin_len = quote_base64_len;

    int ret = mbedtls_base64_decode(quote_bin, quote_base64_len,
                                    &quote_bin_len,
                                    (unsigned char*)p_begin, quote_base64_len);
    if (ret < 0)
        return -EINVAL;

    assert(quote_bin_len <= sizeof(sgx_quote_t));
    memset(quote, 0, sizeof(sgx_quote_t));
    memcpy(quote, quote_bin, quote_bin_len);
    free(quote_bin);
    return 0;
}

/**
 * @return 0 if report_data field matches expected value (#report_data_str), -1 otherwise.
 */
static int verify_report_data(const char* report, int len) {
    sgx_quote_t quote;
    int ret;
    ret = extract_quote_from_ias_report(report, len, &quote);
    if (ret < 0)
        return -1;

    uint8_t report_data[sizeof(sgx_report_data_t)] = {0,};
    strcpy((char*)report_data, report_data_str);
    ret = memcmp(quote.report_body.report_data.d, report_data, sizeof(report_data));
    return ret == 0 ? 0 : -1;
}

/**
 * Execute one full interaction with Intel Attestation Service. Write ../report_data, read
 * ../ias_report and ../ias_header. Verify authenticity of IAS report. Note that this is not a full
 * remote attestation flow, since we are not inspecting any of the enclave/platform properties
 * reflected in the attestation material.
 */
static int test_remote_attestation(void) {
    sgx_report_data_t report_data = {0,};
    memcpy((void*)&report_data, (void*)report_data_str, sizeof(report_data_str));
    int fd = open("/sys/sgx_attestation/report_data", O_WRONLY);
    if (fd < 0)
        return FAILURE;

    int rc = write(fd, &report_data, sizeof(report_data));
    if (rc != sizeof(report_data))
        return FAILURE;
    close(fd);

    fd = open("/sys/sgx_attestation/ias_report", O_RDONLY);
    if (fd < 0)
        return FAILURE;

    char ias_report[8*1024];
    int  ias_report_len = read(fd, ias_report, sizeof(ias_report));
    if (ias_report_len <= 0)
        return FAILURE;
    close(fd);
    printf("IAS Report\n%.*s\n", ias_report_len, ias_report);

    fd = open("/sys/sgx_attestation/ias_header", O_RDONLY);
    if (fd < 0)
        return FAILURE;

    char ias_header[8*1024];
    int  ias_header_len = read(fd, ias_header, sizeof(ias_header));
    if (ias_header_len <= 0)
        return FAILURE;
    close(fd);
    printf("IAS Header\n%.*s\n", ias_header_len, ias_header);

    // Extract and verify signing certificate.
    const char* header = "X-IASReport-Signing-Certificate: ";
    char* ias_sign_chain = memmem(ias_header, ias_header_len, header, strlen(header));
    if (ias_sign_chain == NULL)
        return FAILURE;
    ias_sign_chain += strlen(header);
    char* ias_sign_chain_end = memmem(ias_sign_chain, ias_header_len - (ias_sign_chain - ias_header),
                                     "\r\n", strlen("\r\n"));
    if (ias_sign_chain_end == NULL)
        return FAILURE;
    size_t ias_sign_chain_len = ias_sign_chain_end - ias_sign_chain;

    char* ias_sign_chain_unescaped = unescape(ias_sign_chain, ias_sign_chain_len);
    if (ias_sign_chain_unescaped == NULL)
        return FAILURE;

    const char* pem_header = "-----BEGIN CERTIFICATE-----\n";
    const char* pem_footer = "-----END CERTIFICATE-----\n";
    // The signing chain has 2 certificates. We are only interested in the leaf certificate.
    char* leaf_cert = memmem(ias_sign_chain_unescaped, strlen(ias_sign_chain_unescaped),
                             pem_header, strlen(pem_header));
    if (leaf_cert == NULL)
        return FAILURE;
    const char* leaf_cert_end = memmem(ias_sign_chain_unescaped, strlen(ias_sign_chain_unescaped),
                                       pem_footer, strlen(pem_footer));
    if (leaf_cert_end == NULL)
        return FAILURE;
    size_t leaf_cert_len = leaf_cert_end - leaf_cert + strlen(pem_footer);
    // Slap on a terminating null since verify_ias_certificate_chain() expects its input to be
    // zero-terminated.
    leaf_cert[leaf_cert_len-1] = '\0';

    rc = verify_ias_certificate_chain(leaf_cert, leaf_cert_len);
    if (rc)
        return FAILURE;

    // Extract and verify IAS report signature.
    const char* signature_header = "X-IASReport-Signature: ";
    char* begin = memmem(ias_header, ias_header_len, signature_header, strlen(signature_header));
    begin += strlen(signature_header);
    char* end  = memmem(begin, ias_header_len - (begin - ias_header), "\r\n", strlen("\r\n"));
    size_t signature_len = end - begin;

    size_t decoded_len;
    uint8_t signature[256];
    int ret = mbedtls_base64_decode(signature, sizeof(signature),
                                    &decoded_len, (unsigned char*)begin, signature_len);
    if (ret)
        return FAILURE;

    rc = verify_ias_report_signature(ias_report, ias_report_len, signature, leaf_cert, leaf_cert_len);
    if (rc)
        return FAILURE;

    free(ias_sign_chain_unescaped);
    ias_sign_chain_unescaped = NULL;

    rc = verify_report_data(ias_report, ias_report_len);
    if (rc)
        return FAILURE;

    return SUCCESS;
}

/**
 * @return 0 on success, < 0 otherwise.
 */
static int test_quote_interface(void) {
    sgx_report_data_t report_data = {0,};
    memcpy((void*)&report_data, (void*)report_data_str, sizeof(report_data_str));
    int fd = open("/sys/sgx_attestation/report_data", O_WRONLY);
    if (fd < 0)
        return FAILURE;
    int rc = write(fd, &report_data, sizeof(report_data));
    if (rc != sizeof(report_data))
        return FAILURE;
    close(fd);

    char path[255];
    snprintf(path, sizeof(path), "%s/%s", path_prefix, "quote");
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return FAILURE;
    uint8_t quote[2048];
    rc = read(fd, quote, sizeof(quote));
    close(fd);

    rc = memcmp(((sgx_quote_t*)quote)->report_body.report_data.d, report_data.d, sizeof(report_data));
    return rc == 0 ? SUCCESS : FAILURE;
}

int main(int argc, char** argv) {
    resource_leak();

    printf("Verify local attestation... %s\n",
           test_local_attestation() == SUCCESS ? "SUCCESS" : "FAIL");

    printf("Verify remote attestation... %s\n",
           test_remote_attestation() == SUCCESS ? "SUCCESS" : "FAIL");

    printf("Verify quote interface... %s\n",
           test_quote_interface() == SUCCESS ? "SUCCESS" : "FAIL");

    return 0;
}
