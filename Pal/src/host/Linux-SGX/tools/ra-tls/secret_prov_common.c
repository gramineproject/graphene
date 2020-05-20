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
 * This file contains common utilities for secret provisioning library.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/config.h"

#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

#include "secret_prov.h"

int secret_provision_write(void* ssl, const uint8_t* buf, size_t len) {
    int ret;
    mbedtls_ssl_context* _ssl = (mbedtls_ssl_context*)ssl;

    if (!_ssl || len > INT_MAX)
        return -EINVAL;

    size_t written = 0;
    while (written < len) {
        ret = mbedtls_ssl_write(_ssl, buf + written, len - written);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (ret < 0) {
            /* use well-known error code for a typical case when remote party closes connection */
            return ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ? -ECONNRESET : ret;
        }
        written += (size_t)ret;
    }
    assert(written == len);
    return (int)written;
}

int secret_provision_read(void* ssl, uint8_t* buf, size_t len) {
    int ret;
    mbedtls_ssl_context* _ssl = (mbedtls_ssl_context*)ssl;

    if (!_ssl || len > INT_MAX)
        return -EINVAL;

    size_t read = 0;
    while (read < len) {
        ret = mbedtls_ssl_read(_ssl, buf + read, len - read);
        if (!ret)
            return -ECONNRESET;
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (ret < 0) {
            /* use well-known error code for a typical case when remote party closes connection */
            return ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ? -ECONNRESET : ret;
        }
        read += (size_t)ret;
    }

    assert(read == len);
    return (int)read;
}

int secret_provision_close(void* ssl) {
    mbedtls_ssl_context* _ssl = (mbedtls_ssl_context*)ssl;

    if (!_ssl)
        return 0;

    int ret = -1;
    while (ret < 0) {
        ret = mbedtls_ssl_close_notify(_ssl);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (ret < 0) {
            /* use well-known error code for a typical case when remote party closes connection */
            return ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ? -ECONNRESET : ret;
        }
    }
    return 0;
}
