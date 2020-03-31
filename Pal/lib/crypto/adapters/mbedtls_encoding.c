/* Copyright (C) 2019, Texas A&M University.

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
#include "pal_crypto.h"
#include "pal_error.h"
#include "mbedtls/base64.h"

/*!
 * \brief Encode a byte array into a Base64 string
 *
 * \param[in]     src  input data
 * \param[in]     slen size of input data
 * \param[in]     dst  buffer for the output
 * \param[in,out] dlen in: size of `dst`, out: length after encoding
 *
 * If `dst` is NULL, `*dlen` is still set to expected size after encoding.
 */
int lib_Base64Encode(const uint8_t* src, size_t slen, char* dst, size_t* dlen) {
    int ret = mbedtls_base64_encode((unsigned char*)dst, *dlen, dlen,
                                    (const unsigned char*)src, slen);
    if (ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        return !dst ? 0 : -PAL_ERROR_OVERFLOW;
    } else if (ret != 0) {
        return -PAL_ERROR_INVAL;
    } else {
        return 0;
    }
}

/*!
 * \brief Decode a Base64 string into a byte array
 *
 * \param[in]     src  input data
 * \param[in]     slen size of input data
 * \param[in]     dst  buffer for the output
 * \param[in,out] dlen in: size of `dst`, out: length after decoding
 *
 * If `dst` is NULL, `*dlen` is still set to expected size after decoding.
 */
int lib_Base64Decode(const char* src, size_t slen, uint8_t* dst, size_t* dlen) {
    int ret = mbedtls_base64_decode((unsigned char*)dst, *dlen, dlen,
                                    (const unsigned char*)src, slen);
    if (ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        return !dst ? 0 : -PAL_ERROR_OVERFLOW;
    } else if (ret != 0) {
        return -PAL_ERROR_INVAL;
    } else {
        return 0;
    }
}
