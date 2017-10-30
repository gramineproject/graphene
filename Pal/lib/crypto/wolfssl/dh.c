/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* dh.c
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

#include <stddef.h>
#include <stdint.h>

#include "crypto/wolfssl/integer.h"
#include "crypto/wolfssl/dh.h"
#include "crypto/wolfssl/error-crypt.h"

/*
 * source
 * http://fastapprox.googlecode.com/svn/trunk/fastapprox/src/fastonebigheader.h
 */

static inline float
fastlog2 (float x)
{
    union { float f; uint32_t i; } vx = { x };
    union { uint32_t i; float f; } mx = { (vx.i & 0x007FFFFF) | 0x3f000000 };
    float y = vx.i;
    y *= 1.1920928955078125e-7f;

    return y - 124.22551499f
             - 1.498030302f  *mx.f
             - 1.72587999f / (0.3520887068f + mx.f);
}

static inline float
fastlog (float x)
{
    return 0.69314718f  *fastlog2 (x);
}

static inline float
fastpow2 (float p)
{
  float offset = (p < 0) ? 1.0f : 0.0f;
  float clipp = (p < -126) ? -126.0f : p;
  int w = clipp;
  float z = clipp - w + offset;
  union { uint32_t i; float f; } v = { (uint32_t) ( (1 << 23)  *(clipp + 121.2740575f + 27.7280233f / (4.84252568f - z) - 1.49012907f  *z) ) };

  return v.f;
}

static inline float
fastpow (float x,
         float p)
{
  return fastpow2 (p  *fastlog2 (x));
}

#define XPOW(x,y) fastpow((x),(y))
#define XLOG(x)   fastlog((x))

#ifndef min
static inline word32 min(word32 a, word32 b)
{
    return a > b ? b : a;
}
#endif /* min */


void InitDhKey(DhKey *key)
{
    (void)key;
    key->p.dp = 0;
    key->g.dp = 0;
}


void FreeDhKey(DhKey *key)
{
    (void)key;
    mp_clear(&key->p);
    mp_clear(&key->g);
}

static word32 DiscreteLogWorkFactor(word32 n)
{
    /* assuming discrete log takes about the same time as factoring */
    if (n<5)
        return 0;
    else
        return (word32)(2.4  *XPOW((double)n, 1.0/3.0) *
                XPOW(XLOG((double)n), 2.0/3.0) - 5);
}

int _DkRandomBitsRead (void  *buffer, int size);

static int GeneratePrivate(DhKey *key, byte *priv, word32 *privSz)
{
    int ret;
    word32 sz = mp_unsigned_bin_size(&key->p);
    sz = min(sz, 2  * DiscreteLogWorkFactor(sz * BIT_SIZE) / BIT_SIZE + 1);

    ret = _DkRandomBitsRead(priv, sz);
    if (ret < 0)
        return ret;

    priv[0] |= 0x0C;
    *privSz = sz;
    return 0;
}


static int GeneratePublic(DhKey *key, const byte *priv, word32 privSz,
                          byte *pub, word32 *pubSz)
{
    int ret = 0;

    mp_int x;
    mp_int y;

    if (mp_init_multi(&x, &y, 0, 0, 0, 0) != MP_OKAY)
        return MP_INIT_E;

    if (mp_read_unsigned_bin(&x, priv, privSz) != MP_OKAY)
        ret = MP_READ_E;

    if (ret == 0 && mp_exptmod(&key->g, &x, &key->p, &y) != MP_OKAY)
        ret = MP_EXPTMOD_E;

    if (ret == 0 && mp_to_unsigned_bin(&y, pub) != MP_OKAY)
        ret = MP_TO_E;

    if (ret == 0)
        *pubSz = mp_unsigned_bin_size(&y);

    mp_clear(&y);
    mp_clear(&x);

    return ret;
}


int DhGenerateKeyPair(DhKey *key, byte *priv, word32 *privSz,
                      byte *pub, word32 *pubSz)
{
    int ret = GeneratePrivate(key, priv, privSz);

    return (ret != 0) ? ret : GeneratePublic(key, priv, *privSz, pub, pubSz);
}

int DhAgree(DhKey *key, byte *agree, word32 *agreeSz, const byte *priv,
            word32 privSz, const byte *otherPub, word32 pubSz)
{
    int ret = 0;

    mp_int x;
    mp_int y;
    mp_int z;

    if (mp_init_multi(&x, &y, &z, 0, 0, 0) != MP_OKAY)
        return MP_INIT_E;

    if (mp_read_unsigned_bin(&x, priv, privSz) != MP_OKAY)
        ret = MP_READ_E;

    if (ret == 0 && mp_read_unsigned_bin(&y, otherPub, pubSz) != MP_OKAY)
        ret = MP_READ_E;

    if (ret == 0 && mp_exptmod(&y, &x, &key->p, &z) != MP_OKAY)
        ret = MP_EXPTMOD_E;

    if (ret == 0 && mp_to_unsigned_bin(&z, agree) != MP_OKAY)
        ret = MP_TO_E;

    if (ret == 0)
        *agreeSz = mp_unsigned_bin_size(&z);

    mp_clear(&z);
    mp_clear(&y);
    mp_clear(&x);

    return ret;
}

int DhSetKey(DhKey* key, const byte* p, word32 pSz, const byte* g, word32 gSz)
{
    if (key == NULL || p == NULL || g == NULL || pSz == 0 || gSz == 0)
        return BAD_FUNC_ARG;

    /* may have leading 0 */
    if (p[0] == 0) {
        pSz--; p++;
    }

    if (g[0] == 0) {
        gSz--; g++;
    }

    if (mp_init(&key->p) != MP_OKAY)
        return MP_INIT_E;
    if (mp_read_unsigned_bin(&key->p, p, pSz) != 0) {
        mp_clear(&key->p);
        return ASN_DH_KEY_E;
    }

    if (mp_init(&key->g) != MP_OKAY) {
        mp_clear(&key->p);
        return MP_INIT_E;
    }
    if (mp_read_unsigned_bin(&key->g, g, gSz) != 0) {
        mp_clear(&key->g);
        mp_clear(&key->p);
        return ASN_DH_KEY_E;
    }

    return 0;
}
