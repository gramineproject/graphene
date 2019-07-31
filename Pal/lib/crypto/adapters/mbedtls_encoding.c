/* Copyright (C) 2017, University of North Carolina at Chapel Hill
   and Fortanix, Inc.
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

int lib_ASN1GetSerial(uint8_t** ptr, const uint8_t* end, enum asn1_tag* tag, bool* is_construct,
                      uint8_t** buf, size_t* len) {

    if (end - (*ptr) < 1)
        return -PAL_ERROR_ENDOFSTREAM;

    uint8_t t = *(*ptr)++;
    size_t l;
    int ret = mbedtls_asn1_get_len((unsigned char**)ptr, (const unsigned char*)end, &l);
    if (ret !=0)
        return -PAL_ERROR_INVAL;

    *tag = t & ~(MBEDTLS_ASN1_CONSTRUCTED|MBEDTLS_ASN1_CONTEXT_SPECIFIC);
    *is_construct = t & MBEDTLS_ASN1_CONSTRUCTED;
    *buf = *ptr;
    *len = l;
    *ptr += l;
    return( 0 );
}

int lib_ASN1GetLargeNumberLength(uint8_t** ptr, const uint8_t* end, size_t* len) {
    return mbedtls_asn1_get_tag(ptr, end, len, MBEDTLS_ASN1_INTEGER);
}

int lib_ASN1GetBitstring(uint8_t** ptr, const uint8_t* end, uint8_t** str, size_t* len) {
    mbedtls_asn1_bitstring bs;
    int ret = mbedtls_asn1_get_bitstring((unsigned char**)ptr, (const unsigned char*)end, &bs);
    if (ret < 0)
        return ret;
    *str = (uint8_t*)bs.p;
    *len = bs.len;
    return 0;
}
