/* Attestation API test. Only works for SGX PAL. */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mbedtls/base64.h"
#include "mbedtls/cmac.h"

#include "sgx_api.h"
#include "sgx_arch.h"
#include "sgx_attest.h"

uint8_t g_quote[SGX_QUOTE_MAX_SIZE];

char user_report_data_str[] = "This is user-provided report data";

enum { SUCCESS = 0, FAILURE = -1 };

ssize_t (*rw_file_f)(const char* path, char* buf, size_t bytes, bool do_write);

static ssize_t rw_file_posix(const char* path, char* buf, size_t bytes, bool do_write) {
    ssize_t rv = 0;
    ssize_t ret = 0;

    int fd = open(path, do_write ? O_WRONLY : O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "opening %s failed\n", path);
        return fd;
    }

    while (bytes > rv) {
        if (do_write)
            ret = write(fd, buf + rv, bytes - rv);
        else
            ret = read(fd, buf + rv, bytes - rv);

        if (ret > 0) {
            rv += ret;
        } else if (ret == 0) {
            /* end of file */
            if (rv == 0)
                fprintf(stderr, "%s failed: unexpected end of file\n", do_write ? "write" : "read");
            break;
        } else {
            if (ret < 0 && (errno == EAGAIN || errno == EINTR)) {
                continue;
            } else {
                fprintf(stderr, "%s failed: %s\n", do_write ? "write" : "read", strerror(errno));
                goto out;
            }
        }
    }

out:
    if (ret < 0) {
        /* error path */
        close(fd);
        return ret;
    }

    ret = close(fd);
    if (ret < 0) {
        fprintf(stderr, "closing %s failed\n", path);
        return ret;
    }
    return rv;
}

static ssize_t rw_file_stdio(const char* path, char* buf, size_t bytes, bool do_write) {
    size_t rv = 0;
    size_t ret = 0;

    FILE* f = fopen(path, do_write ? "wb" : "rb");
    if (!f) {
        fprintf(stderr, "opening %s failed\n", path);
        return -1;
    }

    while (bytes > rv) {
        if (do_write)
            ret = fwrite(buf + rv, /*size=*/1, /*nmemb=*/bytes - rv, f);
        else
            ret = fread(buf + rv, /*size=*/1, /*nmemb=*/bytes - rv, f);

        if (ret > 0) {
            rv += ret;
        } else {
            if (feof(f)) {
                if (rv) {
                    /* read some bytes from file, success */
                    break;
                }
                assert(rv == 0);
                fprintf(stderr, "%s failed: unexpected end of file\n", do_write ? "write" : "read");
                fclose(f);
                return -1;
            }

            assert(ferror(f));

            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }

            fprintf(stderr, "%s failed: %s\n", do_write ? "write" : "read", strerror(errno));
            fclose(f);
            return -1;
        }
    }

    int close_ret = fclose(f);
    if (close_ret) {
        fprintf(stderr, "closing %s failed\n", path);
        return -1;
    }
    return rv;
}

/*!
 * \brief Verify the signature on `report`.
 *
 * If verification succeeds, it means the enclave which produced `report` runs on same platform
 * as the enclave executing this function.
 *
 * \return 0 if signature verification succeeded, -1 otherwise.
 */
static int verify_report_mac(sgx_report_t* report) {
    int ret;

    /* setup key request structure */
    __sgx_mem_aligned sgx_key_request_t key_request;
    memset(&key_request, 0, sizeof(key_request));
    key_request.key_name = REPORT_KEY;
    memcpy(&key_request.key_id, &report->key_id, sizeof(key_request.key_id));

    /* retrieve key via EGETKEY instruction leaf */
    __sgx_mem_aligned uint8_t key[128 / 8];
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
 *   3. write some custom data to `user_report_data` file
 *   4. read `report` file
 *   5. verify data read from `report`
 *
 * \return 0 if the test succeeded, -1 otherwise.
 */
static int test_local_attestation(void) {
    ssize_t bytes;

    /* 1. read `my_target_info` file */
    sgx_target_info_t target_info;
    bytes = rw_file_f("/dev/attestation/my_target_info", (char*)&target_info, sizeof(target_info),
                      /*do_write=*/false);
    if (bytes != sizeof(target_info)) {
        /* error is already printed by rw_file_f() */
        return FAILURE;
    }

    /* 2. write data from `my_target_info` to `target_info` file */
    bytes = rw_file_f("/dev/attestation/target_info", (char*)&target_info, sizeof(target_info),
                      /*do_write=*/true);
    if (bytes != sizeof(target_info)) {
        /* error is already printed by rw_file_f() */
        return FAILURE;
    }

    /* 3. write some custom data to `user_report_data` file */
    sgx_report_data_t user_report_data = {0};
    static_assert(sizeof(user_report_data) >= sizeof(user_report_data_str),
                  "insufficient size of user_report_data");

    memcpy((void*)&user_report_data, (void*)user_report_data_str, sizeof(user_report_data_str));

    bytes = rw_file_f("/dev/attestation/user_report_data", (char*)&user_report_data,
                      sizeof(user_report_data), /*do_write=*/true);
    if (bytes != sizeof(user_report_data)) {
        /* error is already printed by rw_file_f() */
        return FAILURE;
    }

    /* 4. read `report` file */
    sgx_report_t report;
    bytes = rw_file_f("/dev/attestation/report", (char*)&report, sizeof(report),
                      /*do_write=*/false);
    if (bytes != sizeof(report)) {
        /* error is already printed by rw_file_f() */
        return FAILURE;
    }

    /* 5. verify data read from `report` */
    return verify_report_mac(&report);
}

/* This currently does not include 'quote'. Since the quote interface does not implement caching,
 * we do not want to have 10^5 interactions with the quoting service (would take too long). */
static const char* paths[] = {
    "/dev/attestation/user_report_data",
    "/dev/attestation/target_info",
    "/dev/attestation/my_target_info",
    "/dev/attestation/report",
    "/dev/attestation/protected_files_key",
};

/*!
 * \brief Test resource leaks in the attestation pseudo filesystem.
 *
 * Perform the following steps 100,000 times:
 *   1. open one of the /dev/attestation files
 *   2. close this file
 *
 * \return 0 if the test succeeded, -1 otherwise.
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
 * Perform the following steps in order:
 *   1. write some custom data to `user_report_data` file
 *   2. read `quote` file
 *   3. verify report data read from `quote`
 *
 * \return 0 if the test succeeds, -1 otherwise.
 */
static int test_quote_interface(void) {
    ssize_t bytes;

    /* 1. write some custom data to `user_report_data` file */
    sgx_report_data_t user_report_data = {0};
    static_assert(sizeof(user_report_data) >= sizeof(user_report_data_str),
                  "insufficient size of user_report_data");

    memcpy((void*)&user_report_data, (void*)user_report_data_str, sizeof(user_report_data_str));

    bytes = rw_file_f("/dev/attestation/user_report_data", (char*)&user_report_data,
                      sizeof(user_report_data), /*do_write=*/true);
    if (bytes != sizeof(user_report_data)) {
        /* error is already printed by rw_file_f() */
        return FAILURE;
    }

    /* 2. read `quote` file */
    bytes = rw_file_f("/dev/attestation/quote", (char*)&g_quote, sizeof(g_quote),
                      /*do_write=*/false);
    if (bytes < 0) {
        /* error is already printed by rw_file_f() */
        return FAILURE;
    }

    /* 3. verify report data read from `quote` */
    if (bytes < sizeof(sgx_quote_t)) {
        fprintf(stderr, "obtained SGX quote is too small: %ldB (must be at least %ldB)\n", bytes,
                sizeof(sgx_quote_t));
        return FAILURE;
    }

    sgx_quote_t* typed_quote = (sgx_quote_t*)g_quote;

    if (typed_quote->version != /*EPID*/2 && typed_quote->version != /*DCAP*/3) {
        fprintf(stderr, "version of SGX quote is not EPID (2) and not ECDSA/DCAP (3)\n");
        return FAILURE;
    }

    int ret = memcmp(typed_quote->report_body.report_data.d, user_report_data.d,
                     sizeof(user_report_data));
    if (ret) {
        fprintf(stderr, "comparison of report data in SGX quote failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

int main(int argc, char** argv) {
    rw_file_f = rw_file_posix;
    if (argc > 1) {
        /* simple trick to test stdio-style interface to pseudo-files in our tests */
        rw_file_f = rw_file_stdio;
    }

    printf("Test local attestation... %s\n",
           test_local_attestation() == SUCCESS ? "SUCCESS" : "FAIL");
    printf("Test quote interface... %s\n",
           test_quote_interface() == SUCCESS ? "SUCCESS" : "FAIL");
    printf("Test resource leaks in attestation filesystem... %s\n",
           test_resource_leak() == SUCCESS ? "SUCCESS" : "FAIL");
    return 0;
}
