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
#include "crypto/mbedtls/mbedtls/base64.h"
#include "crypto/mbedtls/mbedtls/asn1.h"

/*
 * Encoding a byte string in Base64 format. If "dst" is NULL, this function returns the
 * expected length after encoding.
 *
 * @src:  The raw data for encoding.
 * @slen: The length of data
 * @dst:  The buffer for storing the encoded data.
 * @dlen: Returns the length after encoding.
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

/*
 * Decoding a byte string in Base64 format. If "dst" is NULL, this function returns the
 * expected length after decoding.
 *
 * @src:  The Base64 string for decoding
 * @slen: The length of data
 * @dst:  The buffer for storing the decoded data.
 * @dlen: Returns the length after decoding.
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

/*
 * Retrieve the next serialized object in the ASN1 format.
 *
 * @ptr:          Pass in the pointer for reading the ASN1 data. On success, will be updated
 *                to the beginning of the next serialized object.
 * @end:          The end of ASN1 data.
 * @tag:          Returns the tag of the object.
 * @is_construct: Returns a boolean to represent whether the object is a construct object.
 * @buf:          Returns the data field of the object.
 * @len:          Returns the length of the data field.
 */
int lib_ASN1GetSerial(uint8_t** ptr, const uint8_t* end, enum asn1_tag* tag, bool* is_construct,
                      uint8_t** buf, size_t* len) {
    if (end - (*ptr) < 1)
        return -PAL_ERROR_ENDOFSTREAM;

    uint8_t t = *(*ptr)++;
    size_t l;
    int ret = mbedtls_asn1_get_len((unsigned char**)ptr, (const unsigned char*)end, &l);
    if (ret != 0)
        return -PAL_ERROR_INVAL;

    *tag = t & ~(MBEDTLS_ASN1_CONSTRUCTED|MBEDTLS_ASN1_CONTEXT_SPECIFIC);
    *is_construct = t & MBEDTLS_ASN1_CONSTRUCTED;
    *buf = *ptr;
    *len = l;
    *ptr += l;
    return 0;
}

/*
 * Retrieve the next ASN1 object which must be a large number (MBEDTLS_ASN1_INTEGER).
 * Returns -PAL_ERROR_INVAL if the object is not a large number.
 *
 * @ptr:          Pass in the pointer for reading the ASN1 data. On sucess, will be updated
 *                to the beginning of the next serialized object.
 * @end:          The end of ASN1 data.
 * @len:          Returns the length (number of bytes) of the large number.
 */
int lib_ASN1GetLargeNumberLength(uint8_t** ptr, const uint8_t* end, size_t* len) {
    int ret = mbedtls_asn1_get_tag(ptr, end, len, MBEDTLS_ASN1_INTEGER);
    if (ret < 0)
        return -PAL_ERROR_INVAL;
    return 0;
}

/*
 * Retrieve the next ASN1 object which must be a bitstring. Returns -PAL_ERROR_INVAL if the
 * object is not a bitstring.
 *
 * @ptr:          Pass in the pointer for reading the ASN1 data. On sucess, will be updated
 *                to the beginning of the next serialized object.
 * @end:          The end of ASN1 data.
 * @str:          Returns the pointer to the bitstring.
 * @len:          Returns the length of the bitstring.
 */
int lib_ASN1GetBitstring(uint8_t** ptr, const uint8_t* end, uint8_t** str, size_t* len) {
    mbedtls_asn1_bitstring bs;
    int ret = mbedtls_asn1_get_bitstring((unsigned char**)ptr, (const unsigned char*)end, &bs);
    if (ret < 0)
        return -PAL_ERROR_INVAL;
    *str = (uint8_t*)bs.p;
    *len = bs.len;
    return 0;
}
