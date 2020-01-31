/*
 * this function is shamelessly stolen from linux-sgx
 * https://github.com/intel/linux-sgx/blob/9ddec08fb98c1636ed3b1a77bbc4fa3520344ede/sdk/trts/trts_xsave.cpp
 * It has BSD lisence.
 */

/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <pal_linux.h>
#include <pal_linux_error.h>
#include <pal_internal.h>
#include <pal_debug.h>
#include <pal_error.h>
#include <pal_security.h>
#include <pal_crypto.h>
#include <api.h>
#include <list.h>
#include <stdbool.h>

#include "enclave_pages.h"

int xsave_enabled = 0;
uint64_t xsave_features = 0;
uint32_t xsave_size = 0;
//FXRSTOR only cares about the first 512 bytes, while
//XRSTOR in compacted mode will ignore the first 512 bytes.
const uint32_t xsave_reset_state[XSAVE_RESET_STATE_SIZE/sizeof(uint32_t)]
__attribute__((aligned(PAL_XSTATE_ALIGN))) = {
    0x037F, 0, 0, 0, 0, 0, 0x1F80, 0xFFFF, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // XCOMP_BV[63] = 1, compaction mode
};

void init_xsave_size(uint64_t xfrm) {
    const struct {
        uint64_t bits;
        uint32_t size;
    } xsave_size_table[] = { // Note that the xsave_size should be in ascending order
        {SGX_XFRM_LEGACY, 512 + 64},                    // 512 for legacy features, 64 for xsave header
        {SGX_XFRM_AVX,    512 + 64 + 256},              // 256 for YMM0_H - YMM15_H registers
        {SGX_XFRM_MPX,    512 + 64 + 256 + 256},        // 256 for MPX
        {SGX_XFRM_AVX512, 512 + 64 + 256 + 256 + 1600}, // 1600 for k0 - k7, ZMM0_H - ZMM15_H, ZMM16 - ZMM31
    };

    /* fxsave/fxrstore as fallback */
    xsave_enabled = 0;
    xsave_features = PAL_XFEATURE_MASK_FPSSE;
    xsave_size = 512 + 64;
    if (!xfrm || (xfrm & SGX_XFRM_RESERVED)) {
        SGX_DBG(DBG_M, "xsave is disabled, xfrm 0x%lx\n", xfrm);
        return;
    }

    xsave_enabled = (xfrm == SGX_XFRM_LEGACY) ? 0 : 1;
    for (size_t i = 0; i < ARRAY_SIZE(xsave_size_table); i++) {
        if ((xfrm & xsave_size_table[i].bits) == xsave_size_table[i].bits) {
            xsave_features = xfrm;
            xsave_size = xsave_size_table[i].size;
        }
    }
    SGX_DBG(DBG_M, "xsave is enabled with xsave_size: %u\n", xsave_size);
}
