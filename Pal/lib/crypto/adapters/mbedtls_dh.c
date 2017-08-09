/* Copyright (C) 2017 Fortanix, Inc.

   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include <errno.h>
#include <limits.h>
#include "pal.h"
#include "pal_crypto.h"
#include "pal_debug.h"
#include "../lib/assert.h"

#define BITS_PER_BYTE 8

/* This is declared in pal_internal.h, but that can't be included here. */
int _DkRandomBitsRead(void *buffer, int size);

/* Wrapper to provide mbedtls the RNG interface it expects. It passes an
 * extra context parameter, and expects a return value of 0 for success
 * and nonzero for failure. */
static int RandomWrapper(void *private, unsigned char *data, size_t size)
{
    return _DkRandomBitsRead(data, size) != size;
}

int DkDhInit(PAL_DH_CONTEXT *context)
{
    int ret;
    mbedtls_dhm_init(context);

    /* Configure parameters. Note that custom Diffie-Hellman parameters
     * are considered more secure, but require more data be exchanged
     * between the two parties to establish the parameters, so we haven't
     * implemented that yet. */
    ret = mbedtls_mpi_read_string(&context->P, 16 /* radix */,
                                  MBEDTLS_DHM_RFC3526_MODP_2048_P);
    if (ret != 0) {
        pal_printf("D-H initialization failed: %d\n", ret);
        return ret;
    }

    ret = mbedtls_mpi_read_string(&context->G, 16 /* radix */,
                                  MBEDTLS_DHM_RFC3526_MODP_2048_G);
    if (ret != 0) {
        pal_printf("D-H initialization failed: %d\n", ret);
        return ret;
    }

    context->len = mbedtls_mpi_size(&context->P);

    return 0;
}

int DkDhCreatePublic(PAL_DH_CONTEXT *context, uint8_t *public,
                     PAL_NUM *public_size)
{
    int ret;

    if (*public_size != DH_SIZE)
        return -EINVAL;

    /* The RNG here is used to generate secret exponent X. */
    ret = mbedtls_dhm_make_public(context, context->len, public, *public_size,
                                  RandomWrapper, NULL);
    if (ret != 0)
        return ret;

    /* mbedtls writes leading zeros in the big-endian output to pad to
     * public_size, so leave caller's public_size unchanged */
    return 0;
}

int DkDhCalcSecret(PAL_DH_CONTEXT *context, uint8_t *peer, PAL_NUM peer_size,
                   uint8_t *secret, PAL_NUM *secret_size)
{
    int ret;

    if (*secret_size != DH_SIZE)
        return -EINVAL;

    ret = mbedtls_dhm_read_public(context, peer, peer_size);
    if (ret != 0)
        return ret;

    /* The RNG here is used for blinding against timing attacks if X is
     * reused and not used otherwise. mbedtls recommends always passing
     * in an RNG. */
    return mbedtls_dhm_calc_secret(context, secret, *secret_size, secret_size,
                                   RandomWrapper, NULL);
}

void DkDhFinal(PAL_DH_CONTEXT *context)
{
    /* This call zeros out context for us. */
    mbedtls_dhm_free(context);
}

int DkAESCMAC(const uint8_t *key, PAL_NUM key_len, const uint8_t *input,
              PAL_NUM input_len, uint8_t *mac, PAL_NUM mac_len) {
    mbedtls_cipher_type_t cipher;

    switch (key_len) {
    case 16:
        cipher = MBEDTLS_CIPHER_AES_128_ECB;
        break;
    case 24:
        cipher = MBEDTLS_CIPHER_AES_192_ECB;
        break;
    case 32:
        cipher = MBEDTLS_CIPHER_AES_256_ECB;
        break;
    default:
        pal_printf("Invalid key length %d requested for CMAC\n", key_len);
        return -EINVAL;
    }

    const mbedtls_cipher_info_t *cipher_info =
        mbedtls_cipher_info_from_type(cipher);

    if (mac_len < cipher_info->block_size) {
        return -EINVAL;
    }

    return mbedtls_cipher_cmac(cipher_info,
                               key, key_len * BITS_PER_BYTE,
                               input, input_len, mac);
}

int DkRSAInitKey(PAL_RSA_KEY *key)
{
    /* For now, we only need PKCS_V15 type padding. If we need to support
     * multiple padding types, I guess we'll need to add the padding type
     * to this API. We might need to add a wrapper type around the crypto
     * library's key/context type, since not all crypto providers store this
     * in the conext, and instead require you to pass it on each call. */

    /* Last parameter here is the hash type, which is only used for
     * PKCS padding type 2.0. */
    mbedtls_rsa_init(key, MBEDTLS_RSA_PKCS_V15, 0);
    return 0;
}

int DkRSAGenerateKey(PAL_RSA_KEY *key, PAL_NUM length_in_bits, PAL_NUM exponent)
{
    if (length_in_bits > UINT_MAX) {
        return -EINVAL;
    }
    if (exponent > UINT_MAX || (int) exponent < 0) {
        return -EINVAL;
    }
    return mbedtls_rsa_gen_key(key, RandomWrapper, NULL, length_in_bits,
                               exponent);
}

int DkRSAExportPublicKey(PAL_RSA_KEY *key, uint8_t *e, PAL_NUM *e_size,
                         uint8_t *n, PAL_NUM *n_size)
{
    int ret;

    /* Public exponent. */
    if ((ret = mbedtls_mpi_write_binary(&key->E, e, *e_size)) != 0) {
        return ret;
    }

    /* Modulus. */
    if ((ret = mbedtls_mpi_write_binary(&key->N, n, *n_size)) != 0) {
        return ret;
    }
    return 0;
}

int DkRSAFreeKey(PAL_RSA_KEY *key)
{
    mbedtls_rsa_free(key);
    return 0;
}

