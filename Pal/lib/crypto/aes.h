/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* aes.h
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

#ifndef CTAO_CRYPT_AES_H
#define CTAO_CRYPT_AES_H

#include <stdint.h>

#ifndef word32
typedef uint32_t word32;
#endif
#ifndef byte
typedef uint8_t byte;
#endif

#ifndef word
#ifdef __x86_64__
typedef uint64_t word;
#else
typedef uint32_t word;
#endif
#endif

#define WORD_SIZE sizeof(word)

#define ALIGN16 __attribute__((aligned (16)))

enum {
    AES_ENC_TYPE   = 1,   /* cipher unique type */
    AES_ENCRYPTION = 0,
    AES_DECRYPTION = 1,
    AES_BLOCK_SIZE = 16
};

typedef struct AES {
    /* AESNI needs key first, rounds 2nd, not sure why yet */
    ALIGN16 word32 key[60];
    word32  rounds;

    ALIGN16 word32 reg[AES_BLOCK_SIZE / sizeof(word32)];      /* for CBC mode */
    ALIGN16 word32 tmp[AES_BLOCK_SIZE / sizeof(word32)];      /* same         */
    word32  left;
} AES;

int  AESSetKey(AES *aes, const byte *key, word32 len, const byte *iv,
               int dir);
int  AESSetIV(AES *aes, const byte *iv);
void AESEncrypt(AES *aes, const byte *in, byte *out);
void AESDecrypt(AES *aes, const byte *in, byte *out);
int  AESCBCEncrypt(AES *aes, byte *out, const byte *in, word32 sz);
int  AESCBCDecrypt(AES *aes, byte *out, const byte *in, word32 sz);
int  AESCBCDecryptWithKey(byte *out, const byte *in, word32 inSz,
                          const byte *key, word32 keySz, const byte *iv);
void AESCTREncrypt(AES *aes, byte *out, const byte *in, word32 sz);

#endif /* CTAO_CRYPT_AES_H */
