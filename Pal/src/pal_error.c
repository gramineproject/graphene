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

#include "pal_error.h"

struct pal_error_description {
    int error;
    const char* description;
};

static const struct pal_error_description pal_error_list[] = {
    {PAL_ERROR_SUCCESS, "Success"},
    {PAL_ERROR_NOTIMPLEMENTED, "Function not implemented"},
    {PAL_ERROR_NOTDEFINED, "Symbol not defined"},
    {PAL_ERROR_NOTSUPPORT, "Function not supported"},
    {PAL_ERROR_INVAL, "Invalid argument"},
    {PAL_ERROR_TOOLONG, "Name/path is too long"},
    {PAL_ERROR_DENIED, "Operation denied"},
    {PAL_ERROR_BADHANDLE, "Handle corrupted"},
    {PAL_ERROR_STREAMEXIST, "Stream already exists"},
    {PAL_ERROR_STREAMNOTEXIST, "Stream does not exist"},
    {PAL_ERROR_STREAMISFILE, "Stream is a file"},
    {PAL_ERROR_STREAMISDIR, "Stream is a directory"},
    {PAL_ERROR_STREAMISDEVICE, "Stream is a device"},
    {PAL_ERROR_INTERRUPTED, "Operation interrupted"},
    {PAL_ERROR_OVERFLOW, "Buffer overflowed"},
    {PAL_ERROR_BADADDR, "Invalid address"},
    {PAL_ERROR_NOMEM, "Not enough memory"},
    {PAL_ERROR_NOTKILLABLE, "Thread state unkillable"},
    {PAL_ERROR_INCONSIST, "Inconsistent system state"},
    {PAL_ERROR_TRYAGAIN, "Try again"},
    {PAL_ERROR_ENDOFSTREAM, "End of stream"},
    {PAL_ERROR_NOTSERVER, "Not a server"},
    {PAL_ERROR_NOTCONNECTION, "Not a connection"},
    {PAL_ERROR_CONNFAILED, "Connection failed"},
    {PAL_ERROR_ADDRNOTEXIST, "Resource address does not exist"},
    {PAL_ERROR_AFNOSUPPORT, "Address family not supported by protocol"},

    {PAL_ERROR_CRYPTO_FEATURE_UNAVAILABLE, "[Crypto] Feature not available"},
    {PAL_ERROR_CRYPTO_INVALID_CONTEXT, "[Crypto] Invalid context"},
    {PAL_ERROR_CRYPTO_INVALID_KEY_LENGTH, "[Crypto] Invalid key length"},
    {PAL_ERROR_CRYPTO_INVALID_INPUT_LENGTH, "[Crypto] Invalid input length"},
    {PAL_ERROR_CRYPTO_INVALID_OUTPUT_LENGTH, "[Crypto] Invalid output length"},
    {PAL_ERROR_CRYPTO_BAD_INPUT_DATA, "[Crypto] Bad input parameters"},
    {PAL_ERROR_CRYPTO_INVALID_PADDING, "[Crypto] Invalid padding"},
    {PAL_ERROR_CRYPTO_DATA_MISALIGNED, "[Crypto] Data misaligned"},
    {PAL_ERROR_CRYPTO_INVALID_FORMAT, "[Crypto] Invalid data format"},
    {PAL_ERROR_CRYPTO_AUTH_FAILED, "[Crypto] Authentication failed"},
    {PAL_ERROR_CRYPTO_IO_ERROR, "[Crypto] I/O error"},
    {PAL_ERROR_CRYPTO_KEY_GEN_FAILED, "[Crypto] Key generation failed"},
    {PAL_ERROR_CRYPTO_INVALID_KEY, "[Crypto] Invalid key"},
    {PAL_ERROR_CRYPTO_VERIFY_FAILED, "[Crypto] Verification failed"},
    {PAL_ERROR_CRYPTO_RNG_FAILED, "[Crypto] RNG failed to generate data"},
    {PAL_ERROR_CRYPTO_INVALID_DH_STATE, "[Crypto] Invalid DH state"},
};

#define PAL_ERROR_COUNT (sizeof(pal_error_list) / sizeof(pal_error_list[0]))

const char* pal_strerror(int err) {
    for (size_t i = 0; i < PAL_ERROR_COUNT; i++)
        if (pal_error_list[i].error == err)
            return pal_error_list[i].description;
    return "Unknown error";
}
