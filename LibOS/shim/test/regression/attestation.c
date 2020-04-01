/* Attestation API test. Only works for SGX PAL. */

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

#include "sgx_api.h"
#include "sgx_arch.h"
#include "sgx_attest.h"

char report_data_str[] = "I heart SGX!";

enum { SUCCESS = 0, FAILURE = -1 };

ssize_t rw_file(int fd, char* buf, size_t bytes, bool write_flag) {
    ssize_t rv = 0;
    ssize_t ret;

    while (bytes > rv) {
        if (write_flag)
            ret = write(fd, buf + rv, bytes - rv);
        else
            ret = read(fd, buf + rv, bytes - rv);

        if (ret > 0) {
            rv += ret;
        } else if (ret == 0) {
            /* end of file */
            if (rv == 0)
                fprintf(stderr, "%s failed: unexpected end of file\n", write_flag ? "write" : "read");
            break;
        } else {
            if (ret < 0 && (errno == EAGAIN || errno == EINTR)) {
                continue;
            } else {
                fprintf(stderr, "%s failed: %s\n", write_flag ? "write" : "read", strerror(errno));
                return ret;
            }
        }
    }

    return rv;
}

/*!
 * \brief Verify the signature on `report`.
 *
 * If verification succeeds, it means the enclave which produced `report` runs on same platform
 * as the enclave executing this function.
 *
 * \return 0 if signature verification succeeds, -1 otherwise.
 */
static int verify_report_mac(sgx_report_t* report) {
    int ret;

    /* setup key request structure */
    __sgx_mem_aligned sgx_key_request_t key_request;
    memset(&key_request, 0, sizeof(key_request));
    key_request.key_name = REPORT_KEY;
    memcpy(&key_request.key_id, &report->key_id, sizeof(key_request.key_id));

    /* retrieve key via EGETKEY instruction leaf */
    __sgx_mem_aligned uint8_t key[128/8];
    memset(key, 0, sizeof(key));
    sgx_getkey(&key_request, (sgx_key_128bit_t*)key);

    /* calculate message authentication code (MAC) over report body;
     * signature is calculated over part of report BEFORE the key_id field */
    sgx_mac_t mac = {0};
    const int bits_per_byte = 8;
    const mbedtls_cipher_info_t* cipher_info =
        mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    ret = mbedtls_cipher_cmac(cipher_info, key, sizeof(key) * bits_per_byte,
                              (const unsigned char*)report, offsetof(sgx_report_t, key_id),
                              (uint8_t*)&mac);
    if (ret) {
        fprintf(stderr, "MAC calculation over report body failed: %d (mbedtls error code)\n", ret);
        return FAILURE;
    }

    /* compare calculated MAC against MAC sent with report */
    ret = memcmp(&mac, report->mac, sizeof(mac));
    if (ret) {
        fprintf(stderr, "MAC comparison failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

/*!
 * \brief Test local attestation interface.
 *
 * Perform the following steps in order:
 *   1. read `my_target_info` file
 *   2. write data from `my_target_info` to `target_info` file
 *   3. write some custom data to `report_data` file
 *   4. read `report` file
 *   5. verify data read from `report`
 *
 * \return 0 if the test succeeds, -1 otherwise.
 */
static int test_local_attestation(void) {
    int ret;
    int fd;
    ssize_t bytes;

    /* 1. read `my_target_info` file */
    fd = open("/dev/attestation/my_target_info", O_RDONLY);
    if (fd < 0) {
        perror("opening /dev/attestation/my_target_info failed");
        return FAILURE;
    }

    sgx_target_info_t target_info;
    bytes = rw_file(fd, (char*)&target_info, sizeof(target_info), /*write=*/false);
    if (bytes != sizeof(target_info)) {
        /* error is already printed by rw_file() */
        close(fd);
        return FAILURE;
    }

    ret = close(fd);
    if (ret < 0) {
        perror("closing /dev/attestation/my_target_info failed");
        return FAILURE;
    }

    /* 2. write data from `my_target_info` to `target_info` file */
    fd = open("/dev/attestation/target_info", O_WRONLY);
    if (fd < 0) {
        perror("opening /dev/attestation/target_info failed");
        return FAILURE;
    }

    bytes = rw_file(fd, (char*)&target_info, sizeof(target_info), /*write=*/true);
    if (bytes != sizeof(target_info)) {
        /* error is already printed by rw_file() */
        close(fd);
        return FAILURE;
    }

    ret = close(fd);
    if (ret < 0) {
        perror("closing /dev/attestation/target_info failed");
        return FAILURE;
    }

    /* 3. write some custom data to `report_data` file */
    sgx_report_data_t report_data = {0};
    memcpy((void*)&report_data, (void*)report_data_str, sizeof(report_data_str));

    fd = open("/dev/attestation/report_data", O_WRONLY);
    if (fd < 0) {
        perror("opening /dev/attestation/report_data failed");
        return FAILURE;
    }

    bytes = rw_file(fd, (char*)&report_data, sizeof(report_data), /*write=*/true);
    if (bytes != sizeof(report_data)) {
        /* error is already printed by rw_file() */
        close(fd);
        return FAILURE;
    }

    ret = close(fd);
    if (ret < 0) {
        perror("closing /dev/attestation/report_data failed");
        return FAILURE;
    }

    /* 4. read `report` file */
    sgx_report_t report;
    fd = open("/dev/attestation/report", O_RDONLY);
    if (fd < 0) {
        perror("opening /dev/attestation/report failed");
        return FAILURE;
    }

    bytes = rw_file(fd, (char*)&report, sizeof(report), /*write=*/false);
    if (bytes != sizeof(report)) {
        /* error is already printed by rw_file() */
        close(fd);
        return FAILURE;
    }

    ret = close(fd);
    if (ret < 0) {
        perror("closing /dev/attestation/report failed");
        return FAILURE;
    }

    /* 5. verify data read from `report` */
    return verify_report_mac(&report);
}

/* This currently does not include 'quote'. Since the quote interface does not implement caching,
 * we do not want to have 10^5 interactions with the quoting service (would take too long). */
static const char* paths[] = {
    "/dev/attestation/report_data",
    "/dev/attestation/target_info",
    "/dev/attestation/my_target_info",
    "/dev/attestation/report",
};

/*!
 * \brief Test resource leaks in the attestation pseudo filesysem.
 *
 * Perform the following steps 100,000 times:
 *   1. open one of the /dev/attestation files
 *   2. close this file
 *
 * \return 0 if the test succeeds, -1 otherwise.
 */
static int test_resource_leak(void) {
    /* repeatedly open()/close() pseudo-files to hopefully uncover resource leaks */
    for (int j = 0; j < sizeof(paths) / sizeof(&paths[0]); j++) {
        for (int i = 0; i < 100000; i++) {
            int fd = open(paths[j], O_RDONLY);
            if (fd < 0) {
                fprintf(stderr, "opening %s failed: %s\n", paths[j], strerror(errno));
                return FAILURE;
            }

            int ret = close(fd);
            if (ret < 0) {
                fprintf(stderr, "closing %s failed: %s\n", paths[j], strerror(errno));
                return FAILURE;
            }
        }
    }
    return SUCCESS;
}

/*!
 * \brief Test quote interface (currently SGX quote obtained from the Quoting Enclave).
 *
 * Perform the following steps 1 million times:
 *   1. open one of the /dev/attestation files
 *   2. close this file
 *
 * \return 0 if the test succeeds, -1 otherwise.
 */
static int test_quote_interface(void) {
    int ret;
    int fd;
    ssize_t bytes;

    /* 1. write some custom data to `report_data` file */
    fd = open("/dev/attestation/report_data", O_WRONLY);
    if (fd < 0) {
        perror("opening /dev/attestation/report_data failed");
        return FAILURE;
    }

    sgx_report_data_t report_data = {0};
    memcpy((void*)&report_data, (void*)report_data_str, sizeof(report_data_str));

    bytes = rw_file(fd, (char*)&report_data, sizeof(report_data), /*write=*/true);
    if (bytes != sizeof(report_data)) {
        /* error is already printed by rw_file() */
        close(fd);
        return FAILURE;
    }

    ret = close(fd);
    if (ret < 0) {
        perror("closing /dev/attestation/report_data failed");
        return FAILURE;
    }

    /* 2. read `quote` file */
    fd = open("/dev/attestation/quote", O_RDONLY);
    if (fd < 0) {
        perror("opening /dev/attestation/quote failed");
        return FAILURE;
    }

    uint8_t quote[SGX_QUOTE_MAX_SIZE];
    bytes = rw_file(fd, (char*)&quote, sizeof(quote), /*write=*/false);
    if (bytes < 0 || bytes > sizeof(quote)) {
        /* error is already printed by rw_file() */
        close(fd);
        return FAILURE;
    }

    ret = close(fd);
    if (ret < 0) {
        perror("closing /dev/attestation/quote failed");
        return FAILURE;
    }

    /* 5. verify report_data read from `quote` */
    if (bytes < sizeof(sgx_quote_t)) {
        fprintf(stderr, "obtained SGX quote is too small: %ld (must be at least %ld)\n",
                bytes, sizeof(sgx_quote_t));
        return FAILURE;
    }


    sgx_quote_t* typed_quote = (sgx_quote_t*)quote;
    ret = memcmp(typed_quote->report_body.report_data.d, report_data.d,
                 sizeof(report_data));
    if (ret) {
        fprintf(stderr, "comparison of report_data in SGX quote failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

int main(int argc, char** argv) {
    if (argc == 1) {
        /* for debugging, we skip this test by adding any command-line arg */
        printf("Test resource leaks in attestation filesystem... %s\n",
                test_resource_leak() == SUCCESS ? "SUCCESS" : "FAIL");
    }

    printf("Test local attestation... %s\n",
           test_local_attestation() == SUCCESS ? "SUCCESS" : "FAIL");
    printf("Test quote interface... %s\n",
           test_quote_interface() == SUCCESS ? "SUCCESS" : "FAIL");
    return 0;
}
