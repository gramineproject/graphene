/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2019, Texas A&M University. */

#include <errno.h>
#include "pal_crypto.h"
#include "pal_error.h"
#include "mbedtls/base64.h"

/*!
 * \brief Encode a byte array into a Base64 string
 *
 * \param[in]     src  input data
 * \param[in]     slen size of input data
 * \param[out]    dst  buffer for the output
 * \param[in,out] dlen in: size of \p dst, out: length after encoding
 *
 * If \p dst is NULL, `*dlen` is still set to expected size after encoding.
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
 * \param[out]    dst  buffer for the output
 * \param[in,out] dlen in: size of \p dst, out: length after decoding
 *
 * If \p dst is NULL, `*dlen` is still set to expected size after decoding.
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
