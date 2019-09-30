/* Copyright (C) 2014 Stony Brook University
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

/*
 * pal_error.h
 *
 * This file contains definitions of PAL error codes.
 */

#ifndef PAL_ERROR_H
#define PAL_ERROR_H

#include <stddef.h>

#define PAL_ERROR_NOTIMPLEMENTED 1
#define PAL_ERROR_NOTDEFINED     2
#define PAL_ERROR_NOTSUPPORT     3
#define PAL_ERROR_INVAL          4
#define PAL_ERROR_TOOLONG        5
#define PAL_ERROR_DENIED         6
#define PAL_ERROR_BADHANDLE      7
#define PAL_ERROR_STREAMEXIST    8
#define PAL_ERROR_STREAMNOTEXIST 9
#define PAL_ERROR_STREAMISFILE   10
#define PAL_ERROR_STREAMISDIR    11
#define PAL_ERROR_STREAMISDEVICE 12
#define PAL_ERROR_INTERRUPTED    13
#define PAL_ERROR_OVERFLOW       14
#define PAL_ERROR_BADADDR        15
#define PAL_ERROR_NOMEM          16
#define PAL_ERROR_NOTKILLABLE    17
#define PAL_ERROR_INCONSIST      18
#define PAL_ERROR_TRYAGAIN       19
#define PAL_ERROR_ENDOFSTREAM    20
#define PAL_ERROR_NOTSERVER      21
#define PAL_ERROR_NOTCONNECTION  22
#define PAL_ERROR_ZEROSIZE       23
#define PAL_ERROR_CONNFAILED     24
#define PAL_ERROR_ADDRNOTEXIST   25

/* Crypto error constants and their descriptions are adapted from mbedtls. */
#define PAL_ERROR_CRYPTO_FEATURE_UNAVAILABLE   1000
#define PAL_ERROR_CRYPTO_INVALID_CONTEXT       1001
#define PAL_ERROR_CRYPTO_INVALID_KEY_LENGTH    1002
#define PAL_ERROR_CRYPTO_INVALID_INPUT_LENGTH  1003
#define PAL_ERROR_CRYPTO_INVALID_OUTPUT_LENGTH 1004
#define PAL_ERROR_CRYPTO_BAD_INPUT_DATA        1005
#define PAL_ERROR_CRYPTO_INVALID_PADDING       1006
#define PAL_ERROR_CRYPTO_DATA_MISALIGNED       1007
#define PAL_ERROR_CRYPTO_INVALID_ASN1          1008
#define PAL_ERROR_CRYPTO_AUTH_FAILED           1009
#define PAL_ERROR_CRYPTO_IO_ERROR              1010
#define PAL_ERROR_CRYPTO_KEY_GEN_FAILED        1011
#define PAL_ERROR_CRYPTO_INVALID_KEY           1012
#define PAL_ERROR_CRYPTO_PUBLIC_FAILED         1013
#define PAL_ERROR_CRYPTO_PRIVATE_FAILED        1014
#define PAL_ERROR_CRYPTO_PKCS1_VERIFY_FAILED   1015
#define PAL_ERROR_CRYPTO_RNG_FAILED            1016
#define PAL_ERROR_CRYPTO_BIGNUM_FAILED         1017

struct pal_error_description {
    int         error;
    const char* description;
};

static const struct pal_error_description pal_error_list[]
#ifdef __GNUC__
    __attribute__((unused))
#endif
= {
    {  0, "Success" },
    {  1, "Function not implemented" },
    {  2, "Symbol not defined" },
    {  3, "Function not supported" },
    {  4, "Invalid argument" },
    {  5, "Name/Path is too long" },
    {  6, "Operation Denied" },
    {  7, "Handle Corrupted" },
    {  8, "Stream already exists" },
    {  9, "Stream does not exists" },
    { 10, "Stream is File" },
    { 11, "Stream is Directory" },
    { 12, "Stream is Device" },
    { 13, "Operation interrupted" },
    { 14, "Buffer overflowed" },
    { 15, "Invalid address" },
    { 16, "Not enough memory" },
    { 17, "Thread state unkillable" },
    { 18, "Inconsistent system state" },
    { 19, "Try again" },
    { 20, "End of stream" },
    { 21, "Not a server" },
    { 22, "Not a connection" },
    { 23, "Zero size" },
    { 24, "Connection failed" },
    { 25, "Resource address does not exist" },

#define PAL_ERROR_NATIVE_COUNT 25

    { 1000, "[Crypto] Feature not available" },
    { 1001, "[Crypto] Invalid context" },
    { 1002, "[Crypto] Invalid key length" },
    { 1003, "[Crypto] Invalid input length" },
    { 1004, "[Crypto] Invalid output length" },
    { 1005, "[Crypto] Bad input parameters" },
    { 1006, "[Crypto] Invalid padding" },
    { 1007, "[Crypto] Data misaligned" },
    { 1008, "[Crypto] Invalid ASN.1 data" },
    { 1009, "[Crypto] Authentication failed" },
    { 1010, "[Crypto] I/O error" },
    { 1011, "[Crypto] Key generation failed" },
    { 1012, "[Crypto] Invalid key" },
    { 1013, "[Crypto] Public key operation failed" },
    { 1014, "[Crypto] Private key operation failed" },
    { 1015, "[Crypto] PKCS#1 verification failed" },
    { 1016, "[Crypto] RNG failed to generate data" },
    { 1017, "[Crypto] Bignum operation failed" },
};

#define PAL_ERROR_COUNT (sizeof(pal_error_list) / sizeof(pal_error_list[0]))

static inline const char* pal_strerror(int err) {
    for (size_t i = 0; i < PAL_ERROR_COUNT; i++)
        if (pal_error_list[i].error == err)
            return pal_error_list[i].description;
    return "Unknown error";
};

#endif
