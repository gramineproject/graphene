/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* rsa.h
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef CTAO_CRYPT_RSA_H
#define CTAO_CRYPT_RSA_H

#include <stdint.h>

#ifndef word32
typedef uint32_t word32;
#endif
#ifndef byte
typedef uint8_t byte;
#endif

#include "integer.h"

enum {
    RSA_PUBLIC   = 0,
    RSA_PRIVATE  = 1
};

/* RSA */
typedef struct RSAKey {
    mp_int n, e, d, p, q, dP, dQ, u;
    int   type;                               /* public or private */
} RSAKey;

int InitRSAKey(RSAKey *key);
int FreeRSAKey(RSAKey *key);

int RSAPublicEncrypt(const byte *in, word32 inLen, byte *out,
                     word32 outLen, RSAKey *key);
int RSAPrivateDecryptInline(byte *in, word32 inLen, byte* *out,
                             RSAKey *key);
int RSAPrivateDecrypt(const byte *in, word32 inLen, byte *out,
                      word32 outLen, RSAKey *key);
int RSASSL_Sign(const byte *in, word32 inLen, byte *out,
                word32 outLen, RSAKey *key);
int RSASSL_VerifyInline(byte *in, word32 inLen, byte* *out,
                        RSAKey *key);
int RSASSL_Verify(const byte *in, word32 inLen, byte *out,
                  word32 outLen, RSAKey *key);
int RSAEncryptSize(RSAKey *key);

int RSAPrivateKeyDecode(const byte *input, word32 *inOutIdx,
                        RSAKey *key, word32 inSz);
int RSAPublicKeyDecode(const byte *input, word32 *inOutIdx,
                       RSAKey *key, word32 inSz);
int RSAPublicKeyDecodeRaw(const byte *n, word32 nSz, const byte *e,
                          word32 eSz, RSAKey *key);
int RSAFlattenPublicKey(RSAKey *key, byte *e, word32 *eSz, byte *n,
                        word32 *nSz);

int MakeRSAKey(RSAKey *key, int size, long e);
int RSAKeyToDer(RSAKey*, byte *output, word32 inLen);

#endif /* CTAO_CRYPT_RSA_H */
