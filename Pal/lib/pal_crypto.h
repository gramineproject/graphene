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

#define PAL_AES_CMAC_KEY_LEN 16

typedef enum {
    PAL_ENCRYPT,
    PAL_DECRYPT
} PAL_CRYPTO_TYPE;

#if PAL_CRYPTO_PROVIDER == PAL_CRYPTO_WOLFSSL
#include "crypto/cmac.h"
#include "crypto/aes.h"
#include "crypto/dh.h"
#include "crypto/sha256.h"
typedef SHA256 PAL_SHA256_CONTEXT;

#define DH_SIZE 128

typedef struct {
    uint8_t priv[DH_SIZE];
    uint32_t priv_size;
    DhKey key;
} PAL_DH_CONTEXT __attribute__((aligned(DH_SIZE)));

typedef struct AES PAL_AES_CONTEXT;

#elif PAL_CRYPTO_PROVIDER == PAL_CRYPTO_MBEDTLS
#include "crypto/mbedtls/mbedtls/cmac.h"
#include "crypto/mbedtls/mbedtls/dhm.h"
#include "crypto/mbedtls/mbedtls/sha256.h"
typedef mbedtls_sha256_context PAL_SHA256_CONTEXT;

/* DH_SIZE is tied to the choice of parameters in mbedtls_dh.c. */
#define DH_SIZE 256
typedef mbedtls_dhm_context PAL_DH_CONTEXT;

#else
# error "Unknown crypto provider. Set PAL_CRYPTO_PROVIDER in pal_crypto.h"
#endif

/* SHA256 */
int DkSHA256Init(PAL_SHA256_CONTEXT *context);
int DkSHA256Update(PAL_SHA256_CONTEXT *context, const uint8_t *data,
                   PAL_NUM len);
int DkSHA256Final(PAL_SHA256_CONTEXT *context, uint8_t *output);

/* Diffie-Hellman Key Exchange */
int DkDhInit(PAL_DH_CONTEXT *context);
int DkDhCreatePublic(PAL_DH_CONTEXT *context, uint8_t *public,
                     PAL_NUM *public_size);
int DkDhCalcSecret(PAL_DH_CONTEXT *context, uint8_t *peer, PAL_NUM peer_size,
                   uint8_t *secret, PAL_NUM *secret_size);
void DkDhFinal(PAL_DH_CONTEXT *context);

/* AES-CMAC */
int DkAESCMAC(const uint8_t *key, PAL_NUM key_len, const uint8_t *input,
              PAL_NUM input_len, uint8_t *mac, PAL_NUM mac_len);
                  

#endif
