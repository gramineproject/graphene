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

#include "pal.h"

/*
 * You can change which crypto library will be used by changing this
 * define to one of the PAL_CRYPTO_* values below.
 */
#define PAL_CRYPTO_PROVIDER PAL_CRYPTO_MBEDTLS

/* These cryptosystems are still unconditionally provided by WolfSSL. */
#include "crypto/rsa.h"

#define PAL_CRYPTO_WOLFSSL 1
#define PAL_CRYPTO_MBEDTLS 2

#define SHA256_DIGEST_LEN 32

#define AES_CMAC_KEY_LEN    16
#define AES_CMAC_DIGEST_LEN 32

typedef enum {
    PAL_ENCRYPT,
    PAL_DECRYPT
} PAL_CRYPTO_TYPE;

#if PAL_CRYPTO_PROVIDER == PAL_CRYPTO_WOLFSSL
#include "crypto/wolfssl/cmac.h"
#include "crypto/wolfssl/aes.h"
#include "crypto/wolfssl/sha256.h"
#include "crypto/wolfssl/dh.h"
typedef SHA256 LIB_SHA256_CONTEXT;

#define DH_SIZE 128

typedef struct {
    uint8_t priv[DH_SIZE];
    uint32_t priv_size;
    DhKey key;
} LIB_DH_CONTEXT __attribute__((aligned(DH_SIZE)));

typedef struct AES PAL_AES_CONTEXT;

#elif PAL_CRYPTO_PROVIDER == PAL_CRYPTO_MBEDTLS
#include "crypto/mbedtls/mbedtls/cmac.h"
#include "crypto/mbedtls/mbedtls/dhm.h"
#include "crypto/mbedtls/mbedtls/sha256.h"
typedef mbedtls_sha256_context LIB_SHA256_CONTEXT;

/* DH_SIZE is tied to the choice of parameters in mbedtls_dh.c. */
#define DH_SIZE 256
#include "crypto/mbedtls/mbedtls/dhm.h"
typedef mbedtls_dhm_context LIB_DH_CONTEXT;

#else
# error "Unknown crypto provider. Set PAL_CRYPTO_PROVIDER in pal_crypto.h"
#endif

/* SHA256 */
int lib_SHA256Init(LIB_SHA256_CONTEXT *context);
int lib_SHA256Update(LIB_SHA256_CONTEXT *context, const uint8_t *data,
		     uint64_t len);
int lib_SHA256Final(LIB_SHA256_CONTEXT *context, uint8_t *output);

/* Diffie-Hellman Key Exchange */
int lib_DhInit(LIB_DH_CONTEXT *context);
int lib_DhCreatePublic(LIB_DH_CONTEXT *context, uint8_t *public,
                       uint64_t *public_size);
int lib_DhCalcSecret(LIB_DH_CONTEXT *context, uint8_t *peer, uint64_t peer_size,
                     uint8_t *secret, uint64_t *secret_size);
void lib_DhFinal(LIB_DH_CONTEXT *context);

/* AES-CMAC */
int lib_AESCMAC(const uint8_t *key, uint64_t key_len, const uint8_t *input,
                uint64_t input_len, uint8_t *mac, uint64_t mac_len);

#endif
