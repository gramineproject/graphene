/* Attestation API test. */

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mbedtls/cmac.h>

#include "assert.h"
#include "sgx_api.h"
#include "sgx_arch.h"

/* #define ENCLU ".byte 0x0f, 0x01, 0xd7" */
/* #define EGETKEY     1 */

#define PRINT_HEX(s) do { print_str_hex((char*)s, sizeof(s)); } while (0);

static void print_str_hex(const char* s, size_t len) {
    int i;
    for (i = 0; i < len; i++) {
        printf("%x%x", ((0xF0 & s[i]) >> 4), (0xF & s[i]));
    }
}

static void print_report(sgx_report_t* r) {
    printf("  cpu_svn:     "); PRINT_HEX(r->body.cpu_svn.svn); printf("\n");
    printf("  mr_enclave:  "); PRINT_HEX(r->body.mr_enclave.m); printf("\n");
    printf("  mr_signer:   "); PRINT_HEX(r->body.mr_signer.m); printf("\n");
    printf("  attr.flags:  %016lx\n", r->body.attributes.flags);
    printf("  attr.xfrm:   %016lx\n", r->body.attributes.xfrm);
    printf("  isv_prod_id: %02x\n",   r->body.isv_prod_id);
    printf("  isv_svn:     %02x\n",   r->body.isv_svn);
    printf("  report_data: "); PRINT_HEX(r->body.report_data.d); printf("\n");
    printf("  key_id:      "); PRINT_HEX(r->key_id.id); printf("\n");
    printf("  mac:         "); PRINT_HEX(r->mac); printf("\n");
}

/**
 * @return 0 on success, -1 otherwise.
 */
static int verify_report_mac(sgx_report_t* report) {
    // Retrieve EREPORT key
    sgx_key_request_t key_request __attribute__((aligned(512)));
    memset(&key_request, 0, sizeof(key_request));
    key_request.key_name = REPORT_KEY;
    memcpy(&key_request.key_id, &report->key_id, sizeof(key_request.key_id));

    uint8_t key[128/8] __attribute__((aligned(16)));
    memset(key, 0, sizeof(key));

    sgx_getkey(&key_request, (sgx_key_128bit_t*) key);

    // Calculate MAC over report body
    sgx_mac_t our_mac = {0, };

    const mbedtls_cipher_info_t* cipher_info =
        mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);

    int rc = mbedtls_cipher_cmac (cipher_info, key, sizeof(key) * 8, report, 384, &our_mac);

    // Compare our MAC to MAC sent with report
    int ret = memcmp(&our_mac, report->mac, sizeof(our_mac));

    return ret == 0 ? 0 : -1;
}

char report_data_str[] = "I heart SGX!";

/**
 * Exercise local attestation.
 *
 * 1. Read /proc/my_target_info
 * 2. Write content from /proc/my_target_info to /proc/target_info
 * 3. Write report_data_str to /proc/report_data
 * 4. Read /proc/report
 * 5. Verify data read from /proc/report. Since we used the current enclave's target_info_t, we should be able to verify the report.
 */
static void local_attestation(void) {
    sgx_target_info_t target_info;
    int fd = open("/proc/sgx_attestation/my_target_info", O_RDONLY);
    assert(fd > 0);
    int rc = read(fd, &target_info, sizeof(target_info));
    assert(rc == sizeof(target_info));
    close(fd);

    fd = open("/proc/sgx_attestation/target_info", O_WRONLY);
    assert(fd > 0);
    rc = write(fd, &target_info, sizeof(target_info));
    assert(rc == sizeof(target_info));
    close(fd);

    sgx_report_data_t report_data = {0,};
    memcpy((void*)&report_data, (void*) report_data_str, sizeof(report_data_str));
    fd = open("/proc/sgx_attestation/report_data", O_WRONLY);
    assert(fd > 0);
    rc = write(fd, &report_data, sizeof(report_data));
    assert(rc == sizeof(report_data));
    close(fd);

    sgx_report_t report;
    fd = open("/proc/sgx_attestation/report", O_RDONLY);
    assert(fd > 0);
    rc = read(fd, &report, sizeof(report));
    close(fd);

    if (verify_report_mac(&report) == 0) {
        printf("%s success\n", __FUNCTION__);
    } else {
        printf("%s failed\n", __FUNCTION__);
    }
}

const char* paths[] = {
    "report",
    "report_data",
    "my_target_info",
    "target_info",
    /* "ias_report", */
    /* "quote" */
};

const char* path_prefix = "/proc/sgx_attestation";

/**
 * Repeatedly open()/close() pseudo-files to hopefully uncover resource leaks.
 */
static void resource_leak(void) {
    for (int i=0; i < 1000000; i++) {
        for (int j = 0; j < sizeof(paths) / sizeof(&paths[0]); j++) {
            char fn[64];
            snprintf(fn, sizeof(fn), "%s/%s", path_prefix, paths[j]);
            int fd = open(fn, O_RDONLY);
            if (fd == -1) abort();
            close(fd);
        }
    }
}

/**
 * Exercise remote attestation.
 *
 * Write /proc/report_data; read /proc/ias_report; verify IAS report
 */
static void remote_attestation(void) {
    // TODO
}

int main(int argc, char** argv) {
    resource_leak();
    local_attestation();
    remote_attestation();
#if 0
    {
        const int fd = open("/proc/sgx_attestation/ias_report", O_RDONLY);
        if (fd < 0) abort();
        char ias_report[8*1024];
        int rc = read(fd, ias_report, sizeof(ias_report));
        close(fd);
        printf("IAS Report\n%.*s", rc, ias_report);
    }
#endif
    return 0;
}
