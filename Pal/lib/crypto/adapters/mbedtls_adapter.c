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

#include <errno.h>
#include <stdint.h>
#include "pal.h"
#include "pal_crypto.h"
#include "crypto/mbedtls/mbedtls/sha256.h"

int DkSHA256Init(PAL_SHA256_CONTEXT *context)
{
    mbedtls_sha256_init(context);
    mbedtls_sha256_starts(context, 0 /* 0 = use SSH256 */);
    return 0;
}

int DkSHA256Update(PAL_SHA256_CONTEXT *context, const uint8_t *data,
                   PAL_NUM len)
{
    /* For compatibility with other SHA256 providers, don't support
     * large lengths. */
    if (len > UINT32_MAX) {
        return -1;
    }
    mbedtls_sha256_update(context, data, len);
    return 0;
}

int DkSHA256Final(PAL_SHA256_CONTEXT *context, uint8_t *output)
{
    mbedtls_sha256_finish(context, output);
    /* This function is called free, but it doesn't actually free the memory.
     * It zeroes out the context to avoid potentially leaking information
     * about the hash that was just performed. */
    mbedtls_sha256_free(context);
    return 0;
}

int DkRSAImportPublicKey(PAL_RSA_KEY *key, const uint8_t *e, PAL_NUM e_size,
                         const uint8_t *n, PAL_NUM n_size)
{
    int ret;

    /* Public exponent. */
    if ((ret = mbedtls_mpi_read_binary(&key->E, e, e_size)) != 0) {
        return ret;
    }

    /* Modulus. */
    if ((ret = mbedtls_mpi_read_binary(&key->N, n, n_size)) != 0) {
        return ret;
    }
    
    /* This length is in bytes. */
    key->len = (mbedtls_mpi_bitlen(&key->N) + 7) >> 3;
    
    return 0;
}

int DkRSAVerifySHA256(PAL_RSA_KEY *key, const uint8_t *signature,
                      PAL_NUM signature_len, uint8_t *signed_data_out,
                      PAL_NUM signed_data_out_len)
{
    size_t real_data_out_len;

    /* The mbedtls decrypt API assumes that you have a memory buffer that
     * is as large as the key size and take the length as a parameter. We
     * check, so that in the event the caller makes a mistake, you'll get
     * an error instead of reading off the end of the buffer. */
    if (signature_len != key->len) {
        return -EINVAL;
    }
    int ret = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(key, NULL, NULL,
                                                  MBEDTLS_RSA_PUBLIC,
                                                  &real_data_out_len,
                                                  signature,
                                                  signed_data_out,
                                                  signed_data_out_len);
    if (ret == 0) {
        if (real_data_out_len != SHA256_DIGEST_LEN) {
            return -EINVAL;
        }
    }
    return ret;
}

