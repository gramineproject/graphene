/* Copyright (C) 2017 Fortanix, Inc.

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

#include <errno.h>
#include <limits.h>

#include "api.h"
#include "assert.h"
#include "mbedtls_adapter.h"
#include "pal.h"
#include "pal_crypto.h"
#include "pal_debug.h"
#include "pal_error.h"

#define BITS_PER_BYTE 8

/* This is declared in pal_internal.h, but that can't be included here. */
size_t _DkRandomBitsRead(void* buffer, size_t size);

/* Wrapper to provide mbedtls the RNG interface it expects. It passes an
 * extra context parameter, and expects a return value of 0 for success
 * and nonzero for failure. */
static int RandomWrapper(void* private, unsigned char* data, size_t size) {
    __UNUSED(private);
    return _DkRandomBitsRead(data, size);
}

int lib_DhInit(LIB_DH_CONTEXT* context) {
    int ret;
    mbedtls_dhm_init(context);

    /* Configure parameters. Note that custom Diffie-Hellman parameters
     * are considered more secure, but require more data be exchanged
     * between the two parties to establish the parameters, so we haven't
     * implemented that yet. */
    ret = mbedtls_mpi_read_string(&context->P, 16 /* radix */, MBEDTLS_DHM_RFC3526_MODP_2048_P);
    if (ret != 0) {
        pal_printf("D-H initialization failed: %d\n", ret);
        return mbedtls_to_pal_error(ret);
    }

    ret = mbedtls_mpi_read_string(&context->G, 16 /* radix */, MBEDTLS_DHM_RFC3526_MODP_2048_G);
    if (ret != 0) {
        pal_printf("D-H initialization failed: %d\n", ret);
        return mbedtls_to_pal_error(ret);
    }

    context->len = mbedtls_mpi_size(&context->P);

    return 0;
}

int lib_DhCreatePublic(LIB_DH_CONTEXT* context, uint8_t* public, uint64_t* public_size) {
    int ret;

    if (*public_size != DH_SIZE)
        return -PAL_ERROR_INVAL;

    /* The RNG here is used to generate secret exponent X. */
    ret = mbedtls_dhm_make_public(context, context->len, public, *public_size, RandomWrapper, NULL);
    if (ret != 0)
        return mbedtls_to_pal_error(ret);

    /* mbedtls writes leading zeros in the big-endian output to pad to
     * public_size, so leave caller's public_size unchanged */
    return 0;
}

int lib_DhCalcSecret(LIB_DH_CONTEXT* context, uint8_t* peer, uint64_t peer_size, uint8_t* secret,
                     uint64_t* secret_size) {
    int ret;

    if (*secret_size != DH_SIZE)
        return -PAL_ERROR_INVAL;

    ret = mbedtls_dhm_read_public(context, peer, peer_size);
    if (ret != 0)
        return mbedtls_to_pal_error(ret);

    /* The RNG here is used for blinding against timing attacks if X is
     * reused and not used otherwise. mbedtls recommends always passing
     * in an RNG. */
    ret = mbedtls_dhm_calc_secret(context, secret, *secret_size, secret_size, RandomWrapper, NULL);
    return mbedtls_to_pal_error(ret);
}

void lib_DhFinal(LIB_DH_CONTEXT* context) {
    /* This call zeros out context for us. */
    mbedtls_dhm_free(context);
}
