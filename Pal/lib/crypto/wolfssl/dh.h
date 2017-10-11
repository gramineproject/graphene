/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* dh.h
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

#ifndef CTAO_CRYPT_DH_H
#define CTAO_CRYPT_DH_H

#include <stdint.h>

#ifndef word32
typedef uint32_t word32;
#endif
#ifndef byte
typedef uint8_t byte;
#endif

#define BIT_SIZE  8

#include "integer.h"

/* Diffie-Hellman Key */
typedef struct DhKey {
    mp_int p, g;                            /* group parameters  */
} DhKey;


void InitDhKey(DhKey *key);
void FreeDhKey(DhKey *key);

int DhGenerateKeyPair(DhKey *key, byte *priv,
                      word32 *privSz, byte *pub, word32 *pubSz);
int DhAgree(DhKey *key, byte *agree, word32 *agreeSz,
            const byte *priv, word32 privSz, const byte *otherPub,
            word32 pubSz);

int DhSetKey(DhKey *key, const byte *p, word32 pSz, const byte *g,
             word32 gSz);

#endif /* CTAO_CRYPT_DH_H */
