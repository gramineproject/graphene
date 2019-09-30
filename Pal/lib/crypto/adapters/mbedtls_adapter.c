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
#include <stdint.h>
#include <limits.h>
#include "api.h"
#include "pal.h"
#include "pal_crypto.h"
#include "pal_error.h"
#include "pal_debug.h"
#include "assert.h"
#include "crypto/mbedtls/mbedtls/aes.h"
#include "crypto/mbedtls/mbedtls/cmac.h"
#include "crypto/mbedtls/mbedtls/sha256.h"
#include "crypto/mbedtls/mbedtls/rsa.h"

int mbedtls_to_pal_error(int error)
{
    switch(error) {
        case 0:
            return 0;

        case MBEDTLS_ERR_AES_INVALID_KEY_LENGTH:
            return -PAL_ERROR_CRYPTO_INVALID_KEY_LENGTH;

        case MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH:
        case MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED:
            return -PAL_ERROR_CRYPTO_INVALID_INPUT_LENGTH;

        case MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE:
        case MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE:
            return -PAL_ERROR_CRYPTO_FEATURE_UNAVAILABLE;

        case MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA:
        case MBEDTLS_ERR_DHM_BAD_INPUT_DATA:
        case MBEDTLS_ERR_MD_BAD_INPUT_DATA:
        case MBEDTLS_ERR_RSA_BAD_INPUT_DATA:
            return -PAL_ERROR_CRYPTO_BAD_INPUT_DATA;

        case MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE:
            return -PAL_ERROR_CRYPTO_INVALID_OUTPUT_LENGTH;

        case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
        case MBEDTLS_ERR_DHM_ALLOC_FAILED:
        case MBEDTLS_ERR_MD_ALLOC_FAILED:
            return -PAL_ERROR_NOMEM;

        case MBEDTLS_ERR_CIPHER_INVALID_PADDING:
        case MBEDTLS_ERR_RSA_INVALID_PADDING:
            return -PAL_ERROR_CRYPTO_INVALID_PADDING;

        case MBEDTLS_ERR_CIPHER_AUTH_FAILED:
            return -PAL_ERROR_CRYPTO_AUTH_FAILED;

        case MBEDTLS_ERR_CIPHER_INVALID_CONTEXT:
            return -PAL_ERROR_CRYPTO_INVALID_CONTEXT;

        case MBEDTLS_ERR_DHM_READ_PARAMS_FAILED:
        case MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED:
        case MBEDTLS_ERR_DHM_READ_PUBLIC_FAILED:
        case MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED:
        case MBEDTLS_ERR_DHM_CALC_SECRET_FAILED:
            return -PAL_ERROR_CRYPTO_BIGNUM_FAILED;

        case MBEDTLS_ERR_DHM_INVALID_FORMAT:
            return -PAL_ERROR_CRYPTO_INVALID_ASN1;

        case MBEDTLS_ERR_DHM_FILE_IO_ERROR:
        case MBEDTLS_ERR_MD_FILE_IO_ERROR:
            return -PAL_ERROR_CRYPTO_IO_ERROR;

        case MBEDTLS_ERR_RSA_KEY_GEN_FAILED:
            return -PAL_ERROR_CRYPTO_KEY_GEN_FAILED;

        case MBEDTLS_ERR_RSA_KEY_CHECK_FAILED:
            return -PAL_ERROR_CRYPTO_INVALID_KEY;

        case MBEDTLS_ERR_RSA_PUBLIC_FAILED:
            return -PAL_ERROR_CRYPTO_PUBLIC_FAILED;

        case MBEDTLS_ERR_RSA_PRIVATE_FAILED:
            return -PAL_ERROR_CRYPTO_PRIVATE_FAILED;

        case MBEDTLS_ERR_RSA_VERIFY_FAILED:
            return -PAL_ERROR_CRYPTO_PKCS1_VERIFY_FAILED;

        case MBEDTLS_ERR_RSA_RNG_FAILED:
            return -PAL_ERROR_CRYPTO_RNG_FAILED;

        default:
            return -PAL_ERROR_DENIED;
    }
}

#define BITS_PER_BYTE 8

/* This is declared in pal_internal.h, but that can't be included here. */
size_t _DkRandomBitsRead(void *buffer, size_t size);

/* Wrapper to provide mbedtls the RNG interface it expects. It passes an
 * extra context parameter, and expects a return value of 0 for success
 * and nonzero for failure. */
static int RandomWrapper(void *private, unsigned char *data, size_t size)
{
    __UNUSED(private);
    return _DkRandomBitsRead(data, size);
}

#define BITS_PER_BYTE 8

int lib_SHA256Init(LIB_SHA256_CONTEXT *context)
{
    mbedtls_sha256_init(context);
    mbedtls_sha256_starts(context, 0 /* 0 = use SSH256 */);
    return 0;
}

int lib_SHA256Update(LIB_SHA256_CONTEXT *context, const uint8_t *data,
                   uint64_t len)
{
    /* For compatibility with other SHA256 providers, don't support
     * large lengths. */
    if (len > UINT32_MAX) {
        return -PAL_ERROR_INVAL;
    }
    mbedtls_sha256_update(context, data, len);
    return 0;
}

int lib_SHA256Final(LIB_SHA256_CONTEXT *context, uint8_t *output)
{
    mbedtls_sha256_finish(context, output);
    /* This function is called free, but it doesn't actually free the memory.
     * It zeroes out the context to avoid potentially leaking information
     * about the hash that was just performed. */
    mbedtls_sha256_free(context);
    return 0;
}

int lib_AESCMAC(const uint8_t *key, uint64_t key_len, const uint8_t *input,
                uint64_t input_len, uint8_t *mac, uint64_t mac_len) {
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
        return -PAL_ERROR_INVAL;
    }

    const mbedtls_cipher_info_t *cipher_info =
        mbedtls_cipher_info_from_type(cipher);

    if (mac_len < cipher_info->block_size) {
        return -PAL_ERROR_INVAL;
    }

    int ret = mbedtls_cipher_cmac(cipher_info, key, key_len * BITS_PER_BYTE, input, input_len, mac);
    return mbedtls_to_pal_error(ret);
}

int lib_AESCMACInit(LIB_AESCMAC_CONTEXT * context,
                    const uint8_t *key, uint64_t key_len)
{
    switch (key_len) {
    case 16:
        context->cipher = MBEDTLS_CIPHER_AES_128_ECB;
        break;
    case 24:
        context->cipher = MBEDTLS_CIPHER_AES_192_ECB;
        break;
    case 32:
        context->cipher = MBEDTLS_CIPHER_AES_256_ECB;
        break;
    default:
        return -PAL_ERROR_INVAL;
    }

    const mbedtls_cipher_info_t *cipher_info =
        mbedtls_cipher_info_from_type(context->cipher);

    int ret = mbedtls_cipher_setup(&context->ctx, cipher_info);
    if (ret != 0)
        return mbedtls_to_pal_error(ret);

    ret = mbedtls_cipher_cmac_starts(&context->ctx, key, key_len * BITS_PER_BYTE);
    return mbedtls_to_pal_error(ret);
}

int lib_AESCMACUpdate(LIB_AESCMAC_CONTEXT * context, const uint8_t * input,
                      uint64_t input_len)
{
    int ret = mbedtls_cipher_cmac_update(&context->ctx, input, input_len);
    return mbedtls_to_pal_error(ret);
}

int lib_AESCMACFinish(LIB_AESCMAC_CONTEXT * context, uint8_t * mac,
                      uint64_t mac_len)
{
    const mbedtls_cipher_info_t *cipher_info =
        mbedtls_cipher_info_from_type(context->cipher);

    int ret = -PAL_ERROR_INVAL;
    if (mac_len < cipher_info->block_size)
        goto exit;

    ret = mbedtls_cipher_cmac_finish(&context->ctx, mac);
    ret = mbedtls_to_pal_error(ret);

exit:
    mbedtls_cipher_free( &context->ctx );
    return ret;
}

int lib_RSAInitKey(LIB_RSA_KEY *key)
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

int lib_RSAGenerateKey(LIB_RSA_KEY *key, uint64_t length_in_bits, uint64_t exponent)
{
    if (length_in_bits > UINT_MAX)
        return -PAL_ERROR_INVAL;

    if (exponent > UINT_MAX || (int) exponent < 0)
        return -PAL_ERROR_INVAL;

    int ret = mbedtls_rsa_gen_key(key, RandomWrapper, NULL, length_in_bits, exponent);
    return mbedtls_to_pal_error(ret);
}

int lib_RSAExportPublicKey(LIB_RSA_KEY *key, uint8_t *e, uint64_t *e_size,
                           uint8_t *n, uint64_t *n_size)
{
    /* Public exponent. */
    int ret = mbedtls_mpi_write_binary(&key->E, e, *e_size);
    if (ret != 0)
        return mbedtls_to_pal_error(ret);

    /* Modulus. */
    ret = mbedtls_mpi_write_binary(&key->N, n, *n_size);
    return mbedtls_to_pal_error(ret);
}

int lib_RSAImportPublicKey(LIB_RSA_KEY *key, const uint8_t *e, uint64_t e_size,
                           const uint8_t *n, uint64_t n_size)
{
    int ret;

    /* Public exponent. */
    ret = mbedtls_mpi_read_binary(&key->E, e, e_size);
    if (ret != 0)
        return mbedtls_to_pal_error(ret);

    /* Modulus. */
    ret = mbedtls_mpi_read_binary(&key->N, n, n_size);
    if (ret != 0)
        return mbedtls_to_pal_error(ret);

    /* This length is in bytes. */
    key->len = (mbedtls_mpi_bitlen(&key->N) + 7) >> 3;

    return 0;
}

int lib_RSAVerifySHA256(LIB_RSA_KEY* key, const uint8_t* hash, uint64_t hash_len,
                        const uint8_t* signature, uint64_t signature_len) {

    /* The mbedtls decrypt API assumes that you have a memory buffer that
     * is as large as the key size and take the length as a parameter. We
     * check, so that in the event the caller makes a mistake, you'll get
     * an error instead of reading off the end of the buffer. */
    if (signature_len != key->len)
        return -PAL_ERROR_INVAL;

    int ret = mbedtls_rsa_pkcs1_verify(key, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256,
                                       hash_len, hash, signature);

    return mbedtls_to_pal_error(ret);
}

int lib_RSAFreeKey(LIB_RSA_KEY *key)
{
    mbedtls_rsa_free(key);
    return 0;
}
