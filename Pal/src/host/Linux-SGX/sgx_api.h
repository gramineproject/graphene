/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef SGX_API_H
#define SGX_API_H

#include "sgx_arch.h"
#include "pal_error.h"

int sgx_ocall (unsigned long code, void * ms);

bool sgx_is_completely_within_enclave (const void * addr, uint64_t size);
bool sgx_is_completely_outside_enclave(const void * addr, uint64_t size);

void* sgx_alloc_on_ustack(uint64_t size);
void* sgx_copy_to_ustack(const void* ptr, uint64_t size);
void sgx_reset_ustack(void);

bool sgx_copy_ptr_to_enclave(void** ptr, void* uptr, uint64_t size);
uint64_t sgx_copy_to_enclave(const void* ptr, uint64_t maxsize, const void* uptr, uint64_t usize);

/*
 * sgx_report:
 * Generate SGX hardware signed report.
 */
static inline int sgx_report (sgx_target_info_t * targetinfo,
                              void * reportdata, sgx_report_t * report)
{
    __asm__ volatile(
        ENCLU "\n"
        :: "a"(EREPORT), "b"(targetinfo), "c"(reportdata), "d"(report)
        : "memory");
    return 0;
}

/*
 * sgx_getkey:
 * Retrieve SGX hardware enclave cryptography key.
 */
static inline int64_t sgx_getkey (sgx_key_request_t * keyrequest,
                                  sgx_arch_key128_t * key)
{
    int64_t rax = EGETKEY;
    __asm__ volatile(
        ENCLU "\n"
        : "+a"(rax)
        : "b"(keyrequest), "c"(key)
        : "memory");
    return rax;
}

/*
 * rdrand:
 * Get hardware generated random value.
 */
static inline uint32_t rdrand (void)
{
    uint32_t ret;
    __asm__ volatile(
        "1: .byte 0x0f, 0xc7, 0xf0\n" /* RDRAND %EAX */
        "jnc 1b\n"
        :"=a"(ret)
        :: "cc");
    return ret;
}

/*
 * rdfsbase:
 * read FS register (allowed in enclaves).
 */
static inline uint64_t rdfsbase (void)
{
    uint64_t fsbase;
    __asm__ volatile(
        ".byte 0xf3, 0x48, 0x0f, 0xae, 0xc0\n"  /* RDFSBASE %RAX */
        : "=a"(fsbase));
    return fsbase;
}

/*
 * wrfsbase:
 * modify FS register (allowed in enclaves).
 */
static inline void wrfsbase (uint64_t addr)
{
    __asm__ volatile(
        ".byte 0xf3, 0x48, 0x0f, 0xae, 0xd7\n" /* WRFSBASE %RDI */
        :: "D"(addr));
}

void restore_sgx_context(sgx_cpu_context_t *ctx);
void _restore_sgx_context(sgx_cpu_context_t *ctx);

#endif /* SGX_API_H */
