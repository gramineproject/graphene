/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/*
 ---------------------------------------------------------------------------
 Copyright (c) 1998-2008, Brian Gladman, Worcester, UK. All rights reserved.

 LICENSE TERMS

 The redistribution and use of this software (with or without changes)
 is allowed without the payment of fees or royalties provided that:

  1. source code distributions include the above copyright notice, this
     list of conditions and the following disclaimer;

  2. binary distributions include the above copyright notice, this list
     of conditions and the following disclaimer in their documentation;

  3. the name of the copyright holder is not used to endorse products
     built using this software without specific written permission.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 6/10/2008
*/

#include <stddef.h>

#include "cmac.h"
#include "aes.h"

unsigned char const_Rb[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
};
unsigned char const_Zero[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void xor_128(unsigned char *a, unsigned char *b, unsigned char *out)
{
    int i;
    for (i = 0 ; i < 16 ; i++)
        out[i] = a[i] ^ b[i];
}

/* AES-CMAC Generation Function */

void leftshift_onebit(unsigned char *input,unsigned char *output)
{
    int i;
    unsigned char overflow = 0;

    for (i = 15; i >= 0 ; i--) {
        output[i] = input[i] << 1;
        output[i] |= overflow;
        overflow = (input[i] & 0x80)?1:0;
    }
}

void generate_subkey(unsigned char *key, unsigned char *K1, unsigned char *K2)
{
    unsigned char L[16];
    unsigned char Z[16];
    unsigned char tmp[16];
    int i;

    for ( i = 0 ; i < 16 ; i++) Z[i] = 0;

    AES aes;
    AESSetKey(&aes, key, 16, NULL, AES_ENCRYPTION);

    AESEncrypt(&aes, Z, L);

    if ((L[0] & 0x80) == 0) {
        /* If MSB(L) = 0, then K1 = L << 1 */
        leftshift_onebit(L,K1);
    } else {
        /* Else K1 = ( L << 1 ) (+) Rb */
        leftshift_onebit(L,tmp);
        xor_128(tmp,const_Rb,K1);
    }

    if ((K1[0] & 0x80) == 0) {
        leftshift_onebit(K1,K2);
    } else {
        leftshift_onebit(K1,tmp);
        xor_128(tmp,const_Rb,K2);
    }
}

void padding (unsigned char *lastb, unsigned char *pad, int length)
{
    int j;

    /* original last block */
    for ( j = 0 ; j < 16 ; j++) {
        if (j < length) {
            pad[j] = lastb[j];
        } else if (j == length) {
            pad[j] = 0x80;
        } else {
            pad[j] = 0x00;
        }
    }
}

#include "api.h"

void AES_CMAC (unsigned char *key, unsigned char *input, int length,
               unsigned char *mac)
{
    unsigned char X[16],Y[16], M_last[16], padded[16];
    unsigned char K1[16], K2[16];
    int n, i, flag;
    generate_subkey(key, K1, K2);

    n = (length+15) / 16;       /* n is number of rounds */

    if (n == 0) {
        n = 1;
        flag = 0;
    } else {
        if ((length%16) == 0) {
            /* last block is a complete block */
            flag = 1;
        } else {
            /* last block is not complete block */
            flag = 0;
        }
    }

    if (flag) {
        /* last block is complete block */
        xor_128(&input[16*(n-1)], K1, M_last);
    } else {
        padding(&input[16*(n-1)],padded,length%16);
        xor_128(padded, K2, M_last);
    }

    AES aes;
    AESSetKey(&aes, key, 16, NULL, AES_ENCRYPTION);

    for (i = 0 ; i < 16; i++) X[i] = 0;
    for (i = 0 ; i < n - 1; i++) {
        xor_128(X, &input[16 * i], Y); /* Y := Mi (+) X  */
        AESEncrypt(&aes, Y, X); /* X := AES-128(KEY, Y); */ 
    }

    xor_128(X, M_last, Y);
    AESEncrypt(&aes, Y, X);

    for (i = 0; i < 16; i++)
        mac[i] = X[i];
}
