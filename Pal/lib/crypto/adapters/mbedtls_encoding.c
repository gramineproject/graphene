/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2019, Texas A&M University. */

#include <errno.h>

#include "mbedtls/base64.h"
#include "pal_crypto.h"
#include "pal_error.h"

/*!
 * \brief Encode a byte array into a Base64 string
 *
 * \param[in]     src      input data
 * \param[in]     src_size size of input data
 * \param[out]    dst      buffer for the output
 * \param[in,out] dst_size in: size of \p dst, out: size after encoding
 *
 * If \p dst is NULL, `*dst_size` is still set to expected size after encoding.
 */
int lib_Base64Encode(const uint8_t* src, size_t src_size, char* dst, size_t* dst_size) {
    int ret = mbedtls_base64_encode((unsigned char*)dst, *dst_size, dst_size,
                                    (const unsigned char*)src, src_size);
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
 * \param[in]     src      input data
 * \param[in]     src_size size of input data
 * \param[out]    dst      buffer for the output
 * \param[in,out] dst_size in: size of \p dst, out: size after decoding
 *
 * If \p dst is NULL, `*dst_size` is still set to expected size after decoding.
 */
int lib_Base64Decode(const char* src, size_t src_size, uint8_t* dst, size_t* dst_size) {
    int ret = mbedtls_base64_decode((unsigned char*)dst, *dst_size, dst_size,
                                    (const unsigned char*)src, src_size);
    if (ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        return !dst ? 0 : -PAL_ERROR_OVERFLOW;
    } else if (ret != 0) {
        return -PAL_ERROR_INVAL;
    } else {
        return 0;
    }
}
