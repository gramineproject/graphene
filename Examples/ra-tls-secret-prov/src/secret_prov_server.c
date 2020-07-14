/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "secret_prov.h"

#define EXPECTED_STRING "MORE"
#define SECRET_STRING1 "This is a secret string!"
#define SECRET_STRING2 "42" /* answer to ultimate question of life, universe, and everything */

static pthread_mutex_t g_print_lock;

static void hexdump_mem(const void* data, size_t size) {
    uint8_t* ptr = (uint8_t*)data;
    for (size_t i = 0; i < size; i++)
        printf("%02x", ptr[i]);
    printf("\n");
}

/* our own callback to verify SGX measurements during TLS handshake */
static int verify_measurements_callback(const char* mrenclave, const char* mrsigner,
                                        const char* isv_prod_id, const char* isv_svn) {
    assert(mrenclave && mrsigner && isv_prod_id && isv_svn);

    pthread_mutex_lock(&g_print_lock);
    puts("Received the following measurements from the client:");
    printf("  - MRENCLAVE:   "); hexdump_mem(mrenclave, 32);
    printf("  - MRSIGNER:    "); hexdump_mem(mrsigner, 32);
    printf("  - ISV_PROD_ID: %hu\n", *((uint16_t*)isv_prod_id));
    printf("  - ISV_SVN:     %hu\n", *((uint16_t*)isv_svn));
    puts("[ WARNING: In reality, you would want to compare against expected values! ]");
    pthread_mutex_unlock(&g_print_lock);

    return 0;
}

/* this callback is called in a new thread associated with a client; be careful to make this code
 * thread-local and/or thread-safe */
static int communicate_with_client_callback(struct ra_tls_ctx* ctx) {
    int ret;

    /* if we reached this callback, the first secret was sent successfully */
    printf("--- Sent secret1 = '%s' ---\n", SECRET_STRING1);

    /* let's send another secret (just to show communication with secret-awaiting client) */
    int bytes;
    uint8_t buf[128] = {0};

    bytes = secret_provision_read(ctx, buf, sizeof(EXPECTED_STRING));
    if (bytes < 0) {
        if (bytes == -ECONNRESET) {
            /* client doesn't want another secret, shutdown communication gracefully */
            ret = 0;
            goto out;
        }

        fprintf(stderr, "[error] secret_provision_read() returned %d\n", bytes);
        ret = -EINVAL;
        goto out;
    }

    assert(bytes == sizeof(EXPECTED_STRING));
    if (memcmp(buf, EXPECTED_STRING, bytes)) {
        fprintf(stderr, "[error] client sent '%s' but expected '%s'\n", buf, EXPECTED_STRING);
        ret = -EINVAL;
        goto out;
    }

    bytes = secret_provision_write(ctx, (uint8_t*)SECRET_STRING2, sizeof(SECRET_STRING2));
    if (bytes < 0) {
        fprintf(stderr, "[error] secret_provision_write() returned %d\n", bytes);
        ret = -EINVAL;
        goto out;
    }

    printf("--- Sent secret2 = '%s' ---\n", SECRET_STRING2);
    ret = 0;
out:
    secret_provision_close(ctx);
    return ret;
}

int main(int argc, char** argv) {
    int ret;

    ret = pthread_mutex_init(&g_print_lock, NULL);
    if (ret < 0)
        return ret;

    puts("--- Starting the Secret Provisioning server on port 4433 ---");
    ret = secret_provision_start_server((uint8_t*)SECRET_STRING1, sizeof(SECRET_STRING1), "4433",
                                        "certs/server2-sha256.crt", "certs/server2.key",
                                        verify_measurements_callback,
                                        communicate_with_client_callback);
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_start_server() returned %d\n", ret);
        return 1;
    }

    pthread_mutex_destroy(&g_print_lock);
    return 0;
}
