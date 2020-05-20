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
 * This file contains the implementation of secret provisioning library based on RA-TLS for
 * enclavized application. It contains functions to create a self-signed RA-TLS certificate
 * with an SGX quote embedded in it (using ra_tls_create_key_and_crt()), send it to one of
 * the verifier/secret provisioning servers, and receive secrets in response.
 *
 * This file is part of the secret-provisioning client-side library which is typically linked
 * into the SGX application that needs to receive secrets. This library is *not* thread-safe.
 */

#define _XOPEN_SOURCE 700
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/config.h"

#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

#include "ra_tls.h"
#include "secret_prov.h"

/* these are globals because the user may continue using the SSL session even after invoking
 * secret_provision_start() (in the user-supplied callback) */
static mbedtls_ctr_drbg_context g_ctr_drbg;
static mbedtls_entropy_context g_entropy;
static mbedtls_ssl_config g_conf;
static mbedtls_x509_crt g_verifier_ca_chain;
static mbedtls_net_context g_verifier_fd;
static mbedtls_ssl_context g_ssl;
static mbedtls_pk_context g_my_ratls_key;
static mbedtls_x509_crt g_my_ratls_cert;

static uint8_t* provisioned_secret   = NULL;
static size_t provisioned_secret_len = 0;

int secret_provision_get(uint8_t** out_secret, size_t* out_secret_len) {
    if (!out_secret || !out_secret_len)
        return -EINVAL;

    *out_secret     = provisioned_secret;
    *out_secret_len = provisioned_secret_len;
    return 0;
}

void secret_provision_destroy(void) {
    if (provisioned_secret && provisioned_secret_len)
        memset(provisioned_secret, 0, provisioned_secret_len);
    free(provisioned_secret);
    provisioned_secret     = NULL;
    provisioned_secret_len = 0;
}

int secret_provision_start(const char* in_servers, const char* in_ca_chain_path, void** out_ssl) {
    int ret;

    char* servers       = NULL;
    char* ca_chain_path = NULL;

    char* connected_addr = NULL;
    char* connected_port = NULL;

    mbedtls_ctr_drbg_init(&g_ctr_drbg);
    mbedtls_entropy_init(&g_entropy);
    mbedtls_x509_crt_init(&g_verifier_ca_chain);

    mbedtls_pk_init(&g_my_ratls_key);
    mbedtls_x509_crt_init(&g_my_ratls_cert);

    mbedtls_net_init(&g_verifier_fd);
    mbedtls_ssl_config_init(&g_conf);
    mbedtls_ssl_init(&g_ssl);

    const char* pers = "secret-provisioning";
    ret = mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func, &g_entropy,
                                (const uint8_t*)pers, strlen(pers));
    if (ret < 0) {
        goto out;
    }

    if (!in_ca_chain_path) {
        in_ca_chain_path = getenv(SECRET_PROVISION_CA_CHAIN_PATH);
        if (!in_ca_chain_path)
            return -EINVAL;
    }

    ca_chain_path = strdup(in_ca_chain_path);
    if (!ca_chain_path) {
        ret = -ENOMEM;
        goto out;
    }

    if (!in_servers) {
        in_servers = getenv(SECRET_PROVISION_SERVERS);
        if (!in_servers)
            in_servers = DEFAULT_SERVERS;
    }

    servers = strdup(in_servers);
    if (!servers) {
        ret = -ENOMEM;
        goto out;
    }

    char* saveptr1;
    char* saveptr2;
    char* str1;
	for (str1 = servers; /*no condition*/; str1 = NULL) {
        ret = -ECONNREFUSED;
        char* token = strtok_r(str1, ",; ", &saveptr1);
        if (!token)
            break;

        connected_addr = strtok_r(token, ":", &saveptr2);
        if (!connected_addr)
            continue;

        connected_port = strtok_r(NULL, ":", &saveptr2);
        if (!connected_port)
            continue;

        ret = mbedtls_net_connect(&g_verifier_fd, connected_addr, connected_port,
                                  MBEDTLS_NET_PROTO_TCP);
        if (!ret)
            break;
    }

    if (ret < 0) {
        goto out;
    }

    ret = mbedtls_ssl_config_defaults(&g_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret < 0) {
        goto out;
    }

    ret = mbedtls_x509_crt_parse_file(&g_verifier_ca_chain, ca_chain_path);
    if (ret != 0) {
        goto out;
    }

    mbedtls_ssl_conf_authmode(&g_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&g_conf, &g_verifier_ca_chain, NULL);

    if (!ra_tls_create_key_and_crt) {
        ret = -EINVAL;
        goto out;
    }

    ret = ra_tls_create_key_and_crt(&g_my_ratls_key, &g_my_ratls_cert);
    if (ret < 0) {
        goto out;
    }

    mbedtls_ssl_conf_rng(&g_conf, mbedtls_ctr_drbg_random, &g_ctr_drbg);

    ret = mbedtls_ssl_conf_own_cert(&g_conf, &g_my_ratls_cert, &g_my_ratls_key);
    if (ret < 0) {
        goto out;
    }

    ret = mbedtls_ssl_setup(&g_ssl, &g_conf);
    if (ret < 0) {
        goto out;
    }

    ret = mbedtls_ssl_set_hostname(&g_ssl, connected_addr);
    if (ret < 0) {
        goto out;
    }

    mbedtls_ssl_set_bio(&g_ssl, &g_verifier_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    ret = -1;
    while (ret < 0) {
        ret = mbedtls_ssl_handshake(&g_ssl);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (ret < 0) {
            goto out;
        }
    }

    uint32_t flags = mbedtls_ssl_get_verify_result(&g_ssl);
    if (flags != 0) {
        ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        goto out;
    }

    uint8_t buf[128];
    size_t len;

    len = sprintf((char*)buf, SECRET_PROVISION_REQUEST);

    ret = secret_provision_write(&g_ssl, buf, len);
    if (ret < 0) {
        goto out;
    }

    memset(buf, 0, sizeof(buf));
    len = SECRET_PROVISION_RESPONSE_LEN + sizeof(provisioned_secret_len);

    ret = secret_provision_read(&g_ssl, buf, len);
    if (ret < 0) {
        goto out;
    }

    if (memcmp(buf, SECRET_PROVISION_RESPONSE, SECRET_PROVISION_RESPONSE_LEN)) {
        ret = -EINVAL;
        goto out;
    }

    memcpy(&provisioned_secret_len, buf + SECRET_PROVISION_RESPONSE_LEN,
           sizeof(provisioned_secret_len));
    if (provisioned_secret_len > INT_MAX) {
        ret = -EINVAL;
        goto out;
    }

    provisioned_secret = malloc(provisioned_secret_len);
    if (!provisioned_secret) {
        ret = -ENOMEM;
        goto out;
    }

    ret = secret_provision_read(&g_ssl, provisioned_secret, provisioned_secret_len);
    if (ret < 0) {
        goto out;
    }

    if (out_ssl) {
        *out_ssl = &g_ssl;
    } else {
        secret_provision_close(&g_ssl);
    }

    ret = 0;
out:
    if (ret < 0) {
        secret_provision_destroy();
    }

    if (ret < 0 || !out_ssl) {
        mbedtls_x509_crt_free(&g_my_ratls_cert);
        mbedtls_pk_free(&g_my_ratls_key);
        mbedtls_net_free(&g_verifier_fd);
        mbedtls_ssl_free(&g_ssl);
        mbedtls_ssl_config_free(&g_conf);
        mbedtls_x509_crt_free(&g_verifier_ca_chain);
        mbedtls_ctr_drbg_free(&g_ctr_drbg);
        mbedtls_entropy_free(&g_entropy);
    }

    free(servers);
    free(ca_chain_path);

    return ret;
}

__attribute__((constructor)) static void secret_provision_constructor(void) {
    char* e = getenv(SECRET_PROVISION_CONSTRUCTOR);
    if (!e)
        return;

    if (!strcmp(e, "1") || !strcmp(e, "true") || !strcmp(e, "TRUE")) {
        /* user wants to provision secret before application runs */
        uint8_t* secret   = NULL;
        size_t secret_len = 0;

        setenv(SECRET_PROVISION_SECRET_STRING, "CANNOT RETRIEVE SECRET", /*overwrite=*/1);

        int ret = secret_provision_start(/*in_servers=*/NULL, /*in_ca_chain_path=*/NULL,
                                         /*out_ssl=*/NULL);
        if (!ret) {
            /* succeessfully retrieved the secret, put it in an envvar if fits */
            ret = secret_provision_get(&secret, &secret_len);
            if (!ret && secret && secret_len > 0 && secret_len <= PATH_MAX) {
                /* secret fits in an envvar, copy it in envvar */
                secret[secret_len - 1] = '\0';
                setenv(SECRET_PROVISION_SECRET_STRING, (const char*)secret, /*overwrite=*/1);
            } else {
                setenv(SECRET_PROVISION_SECRET_STRING, "CANNOT REPRESENT SECRET AS STRING",
                       /*overwrite=*/1);
            }
            secret_provision_destroy();
        }
    }
}
