/* Copyright (C) 2014 OSCAR lab, Stony Brook University

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

/*
 * Cryptographic primitive abstractions. This layer provides a way to
 * change the crypto library without changing the rest of Graphene code 
 * by providing a small crypto library adaptor implementing these methods.
 */

#ifndef PAL_CRYPTO_H
#define PAL_CRYPTO_H

/*
 * You can change which crypto library will be used by changing this
 * define. Currently supported options:
 * - wolfSSL
 */
#define PAL_CRYPTO_PROVIDER PAL_CRYPTO_MBEDTLS

/* These cryptosystems are still unconditionally provided by WolfSSL. */
#include "crypto/cmac.h"
#include "crypto/dh.h"
#include "crypto/rsa.h"

#define PAL_CRYPTO_WOLFSSL 1
#define PAL_CRYPTO_MBEDTLS 2

#define SHA256_DIGEST_LEN 32

#if PAL_CRYPTO_PROVIDER == PAL_CRYPTO_WOLFSSL
#include "crypto/sha256.h"
typedef SHA256 PAL_SHA256_CONTEXT;

#elif PAL_CRYPTO_PROVIDER == PAL_CRYPTO_MBEDTLS
#include "crypto/mbedtls/mbedtls/sha256.h"
typedef mbedtls_sha256_context PAL_SHA256_CONTEXT;

#else
# error "Unknown crypto provider. Set PAL_CRYPTO_PROVIDER in pal_crypto.h"
#endif

int DkSHA256Init(PAL_SHA256_CONTEXT *context);
int DkSHA256Update(PAL_SHA256_CONTEXT *context, const uint8_t *data,
                   PAL_NUM len);
int DkSHA256Final(PAL_SHA256_CONTEXT *context, uint8_t *output);
                  

#endif
