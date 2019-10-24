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

typedef enum _pal_error_t {
    PAL_ERROR_SUCCESS = 0,
    PAL_ERROR_NOTIMPLEMENTED,
    PAL_ERROR_NOTDEFINED,
    PAL_ERROR_NOTSUPPORT,
    PAL_ERROR_INVAL,
    PAL_ERROR_TOOLONG,
    PAL_ERROR_DENIED,
    PAL_ERROR_BADHANDLE,
    PAL_ERROR_STREAMEXIST,
    PAL_ERROR_STREAMNOTEXIST,
    PAL_ERROR_STREAMISFILE,
    PAL_ERROR_STREAMISDIR,
    PAL_ERROR_STREAMISDEVICE,
    PAL_ERROR_INTERRUPTED,
    PAL_ERROR_OVERFLOW,
    PAL_ERROR_BADADDR,
    PAL_ERROR_NOMEM,
    PAL_ERROR_NOTKILLABLE,
    PAL_ERROR_INCONSIST,
    PAL_ERROR_TRYAGAIN,
    PAL_ERROR_ENDOFSTREAM,
    PAL_ERROR_NOTSERVER,
    PAL_ERROR_NOTCONNECTION,
    PAL_ERROR_CONNFAILED,
    PAL_ERROR_ADDRNOTEXIST,
    PAL_ERROR_AFNOSUPPORT,

#define PAL_ERROR_NATIVE_COUNT PAL_ERROR_AFNOSUPPORT
#define PAL_ERROR_CRYPTO_START PAL_ERROR_CRYPTO_FEATURE_UNAVAILABLE

    /* Crypto error constants and their descriptions are adapted from mbedtls. */
    PAL_ERROR_CRYPTO_FEATURE_UNAVAILABLE = 1000,
    PAL_ERROR_CRYPTO_INVALID_CONTEXT,
    PAL_ERROR_CRYPTO_INVALID_KEY_LENGTH,
    PAL_ERROR_CRYPTO_INVALID_INPUT_LENGTH,
    PAL_ERROR_CRYPTO_INVALID_OUTPUT_LENGTH,
    PAL_ERROR_CRYPTO_BAD_INPUT_DATA,
    PAL_ERROR_CRYPTO_INVALID_PADDING,
    PAL_ERROR_CRYPTO_DATA_MISALIGNED,
    PAL_ERROR_CRYPTO_INVALID_FORMAT,
    PAL_ERROR_CRYPTO_AUTH_FAILED,
    PAL_ERROR_CRYPTO_IO_ERROR,
    PAL_ERROR_CRYPTO_KEY_GEN_FAILED,
    PAL_ERROR_CRYPTO_INVALID_KEY,
    PAL_ERROR_CRYPTO_VERIFY_FAILED,
    PAL_ERROR_CRYPTO_RNG_FAILED,
    PAL_ERROR_CRYPTO_INVALID_DH_STATE,
#define PAL_ERROR_CRYPTO_END PAL_ERROR_CRYPTO_INVALID_DH_STATE
} pal_error_t;

const char* pal_strerror(int err);

#endif
