/* This file is part of Graphene Library OS.

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

#include <stdint.h>
#include "pal.h"
#include "pal_crypto.h"
#include "pal_error.h"
#include "crypto/mbedtls/mbedtls/cmac.h"
#include "crypto/mbedtls/mbedtls/sha256.h"

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

int lib_AESCMAC(const uint8_t *key, PAL_NUM key_len, const uint8_t *input,
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
        return -PAL_ERROR_INVAL;
    }

    const mbedtls_cipher_info_t *cipher_info =
        mbedtls_cipher_info_from_type(cipher);

    if (mac_len < cipher_info->block_size) {
        return -PAL_ERROR_INVAL;
    }

    return mbedtls_cipher_cmac(cipher_info,
                               key, key_len * BITS_PER_BYTE,
                               input, input_len, mac);
}
