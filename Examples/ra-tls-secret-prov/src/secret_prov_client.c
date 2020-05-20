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

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "secret_prov.h"

int main(int argc, char** argv) {
    int ret;
    int bytes;
    void* ssl_session = NULL;

    uint8_t* secret1   = NULL;
    size_t secret1_len = 0;
    uint64_t secret2   = 0;

    if (!secret_provision_start) {
        puts("No secret provision library (libsecret_prov_attest.so) detected, exiting.");
        return 1;
    }

    char* secret_prov_constructor_str = getenv(SECRET_PROVISION_CONSTRUCTOR);
    if (!secret_prov_constructor_str) {
        /* secret provisioning was not run as part of initialization, run it now */
        ret = secret_provision_start("dummyserver:80;localhost:4433;anotherdummy:4433",
                                     "certs/test-ca-sha256.crt", &ssl_session);
        if (ret < 0) {
            fprintf(stderr, "[error] secret_provision_start() returned %d\n", ret);
            goto out;
        }

        /* let's ask for another secret (just to show communication with secret-prov server) */
        bytes = secret_provision_write(ssl_session, "MORE", strlen("MORE"));
        if (bytes < 0) {
            fprintf(stderr, "[error] secret_provision_write() returned %d\n", bytes);
            goto out;
        }

        /* the secret we expect in return is a 64-bit unsigned integer */
        uint8_t buf[128] = {0};
        bytes = secret_provision_read(ssl_session, buf, sizeof(secret2));
        if (bytes < 0) {
            fprintf(stderr, "[error] secret_provision_read() returned %d\n", bytes);
            goto out;
        }

        assert(bytes == sizeof(secret2));
        memcpy(&secret2, buf, bytes);
    }

    ret = secret_provision_get(&secret1, &secret1_len);
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_get() returned %d\n", ret);
        goto out;
    }

    assert(secret1_len);
    secret1[secret1_len - 1] = '\0';

    printf("--- Received secret1 = '%s', secret2 = %lu ---\n", secret1, secret2);
    ret = 0;
out:
    secret_provision_destroy();
    secret_provision_close(ssl_session);
    return ret;
}
