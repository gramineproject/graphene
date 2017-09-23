/* Copyright (C) 2017 Fortanix, Inc.

   This file is part of Graphene Library OS.

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
#include "crypto/wolfssl/sha256.h"

int lib_SHA256Init(LIB_SHA256_CONTEXT *context)
{
    return SHA256Init(context);
}

int lib_SHA256Update(LIB_SHA256_CONTEXT *context, const uint8_t *data,
                   uint64_t len)
{
    /* uint64_t is a 64-bit value, but SHA256Update takes a 32-bit len. */
    if (len > UINT32_MAX) {
        return -1;
    }
    return SHA256Update(context, data, len);
}

int lib_SHA256Final(LIB_SHA256_CONTEXT *context, uint8_t *output)
{
    return SHA256Final(context, output);
}
