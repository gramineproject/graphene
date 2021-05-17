/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#ifndef SGX_API_H
#define SGX_API_H

#include "sgx_arch.h"

long sgx_ocall(uint64_t code, void* ms);

bool sgx_is_completely_within_enclave(const void* addr, uint64_t size);
bool sgx_is_completely_outside_enclave(const void* addr, uint64_t size);

void* sgx_prepare_ustack(void);
void* sgx_alloc_on_ustack_aligned(uint64_t size, size_t alignment);
void* sgx_alloc_on_ustack(uint64_t size);
void* sgx_copy_to_ustack(const void* ptr, uint64_t size);
void sgx_reset_ustack(const void* old_ustack);

bool sgx_copy_ptr_to_enclave(void** ptr, void* uptr, size_t size);
bool sgx_copy_to_enclave(void* ptr, size_t maxsize, const void* uptr, size_t usize);

/*!
 * \brief Low-level wrapper around EREPORT instruction leaf.
 *
 * Caller is responsible for parameter alignment: 512B for `targetinfo`, 128B for `reportdata`,
 * and 512B for `report`.
 */
static inline int sgx_report(const sgx_target_info_t* targetinfo, const void* reportdata,
                             sgx_report_t* report) {
    __asm__ volatile(
        ENCLU "\n"
        :: "a"(EREPORT), "b"(targetinfo), "c"(reportdata), "d"(report)
        : "memory");
    return 0;
}

/*!
 * \brief Low-level wrapper around EGETKEY instruction leaf.
 *
 * Caller is responsible for parameter alignment: 512B for `keyrequest` and 16B for `key`.
 */
static inline int64_t sgx_getkey(sgx_key_request_t* keyrequest, sgx_key_128bit_t* key) {
    int64_t rax = EGETKEY;
    __asm__ volatile(
        ENCLU "\n"
        : "+a"(rax)
        : "b"(keyrequest), "c"(key)
        : "memory");
    return rax;
}

#endif /* SGX_API_H */
