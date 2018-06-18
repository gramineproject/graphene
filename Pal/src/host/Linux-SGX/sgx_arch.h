/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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

#ifndef SGX_ARCH_H
#define SGX_ARCH_H

#include "pal_linux_defs.h"

#ifndef __ASSEMBLER__

#include <stdint.h>

typedef uint8_t sgx_arch_key_t [384];
typedef uint8_t sgx_arch_hash_t[32];
typedef uint8_t sgx_arch_mac_t [16];
// This if for passing a mac to hex2str
#define MACBUF_SIZE ((sizeof(sgx_arch_mac_t)*2)+1) 

typedef struct {
    uint64_t flags, xfrm;
} sgx_arch_attributes_t;

#define SGX_FLAGS_INITIALIZED    0x01ULL
#define SGX_FLAGS_DEBUG          0x02ULL
#define SGX_FLAGS_MODE64BIT      0x04ULL
#define SGX_FLAGS_PROVISION_KEY  0x10ULL
#define SGX_FLAGS_LICENSE_KEY    0x20ULL

#define SGX_XFRM_LEGACY          0x03ULL
#define SGX_XFRM_AVX             0x06ULL

#define SGX_MISCSELECT_EXINFO    0x01UL

typedef struct {
    uint64_t size, baseaddr;
    uint32_t ssaframesize;
    uint32_t miscselect;
    uint8_t  reserved[24];
    sgx_arch_attributes_t attributes;
    sgx_arch_hash_t mrenclave;
    uint8_t  reserved2[32];
    sgx_arch_hash_t mrsigner;
    uint8_t  reserved3[96];
    uint16_t isvprodid, isvsvn;
    uint8_t  reserved4[3836];
} sgx_arch_secs_t;

typedef struct {
    uint64_t reserved;
    uint64_t flags;
    uint64_t ossa;
    uint32_t cssa;
    uint32_t nssa;
    uint64_t oentry;
    uint64_t reserved2;
    uint64_t ofsbasgx;
    uint64_t ogsbasgx;
    uint32_t fslimit;
    uint32_t gslimit;
    uint8_t  reserved3[4024];
} sgx_arch_tcs_t;

#define TCS_FLAGS_DBGOPTIN   (01ULL)

typedef struct {
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rflags;
    uint64_t rip;
    uint64_t ursp;
    uint64_t urbp;
    uint32_t exitinfo;
    uint32_t reserved;
#if SGX_HAS_FSGSBASE == 1
    uint64_t fsbase;
    uint64_t gsbase;
#endif
} sgx_arch_gpr_t;

typedef struct {
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rflags;
    uint64_t rip;
} sgx_context_t;

typedef struct {
    uint32_t vector:8;
    uint32_t type:3;
    uint32_t reserved:20;
    uint32_t valid:1;
} sgx_arch_exitinfo_t;

#define SGX_EXCEPTION_HARDWARE      3UL
#define SGX_EXCEPTION_SOFTWARE      6UL

#define SGX_EXCEPTION_VECTOR_DE     0UL  /* DIV and IDIV instructions */
#define SGX_EXCEPTION_VECTOR_DB     1UL  /* For Intel use only */
#define SGX_EXCEPTION_VECTOR_BP     3UL  /* INT 3 instruction */
#define SGX_EXCEPTION_VECTOR_BR     5UL  /* BOUND instruction */
#define SGX_EXCEPTION_VECTOR_UD     6UL  /* UD2 instruction or reserved opcodes */
#define SGX_EXCEPTION_VECTOR_MF    16UL  /* x87 FPU floating-point or WAIT/FWAIT instruction */
#define SGX_EXCEPTION_VECTOR_AC    17UL  /* Any data reference in memory */
#define SGX_EXCEPTION_VECTOR_XM    19UL  /* Any SIMD floating-point exceptions */

typedef struct {
    uint64_t linaddr;
    uint64_t srcpge;
    uint64_t secinfo;
    uint64_t secs;
} sgx_arch_pageinfo_t;

typedef struct {
    uint64_t flags;
    uint8_t  reserved[56];
} sgx_arch_secinfo_t;

#define SGX_SECINFO_FLAGS_R             0x001
#define SGX_SECINFO_FLAGS_W             0x002
#define SGX_SECINFO_FLAGS_X             0x004
#define SGX_SECINFO_FLAGS_SECS          0x000
#define SGX_SECINFO_FLAGS_TCS           0x100
#define SGX_SECINFO_FLAGS_REG           0x200

typedef struct {
    /* header part (signed) */
    uint32_t header[4], vendor;
    uint32_t date;
    uint32_t header2[4];
    uint32_t swdefined;
    uint8_t  reserved1[84];

    /* key part (unsigned) */
    sgx_arch_key_t modulus;
    uint32_t exponent;
    sgx_arch_key_t signature;

    /* body part (signed) */
    uint32_t miscselect, miscselect_mask;
    uint8_t  reserved2[20];
    sgx_arch_attributes_t attributes, attribute_mask;
    sgx_arch_hash_t enclave_hash;
    uint8_t  reserved3[32];
    uint16_t isvprodid, isvsvn;

    /* tail part (unsigned) */
    uint8_t  reserved4[12];
    sgx_arch_key_t q1, q2;
} __attribute__((packed)) sgx_arch_sigstruct_t;

typedef struct {
    uint32_t valid;
    uint8_t  reserved[44];
    sgx_arch_attributes_t attributes;
    sgx_arch_hash_t mrenclave;
    uint8_t  reserved2[32];
    sgx_arch_hash_t mrsigner;
    uint8_t  reserved3[32];
    uint64_t cpusvnle[2];
    uint16_t isvprodidle, isvsvnle;
    uint8_t  reserved4[24];
    uint32_t miscselect_mask;
    sgx_arch_attributes_t attribute_mask;
    sgx_arch_hash_t keyid;
    sgx_arch_mac_t mac;
} __attribute__((packed)) sgx_arch_token_t;

typedef struct {
    uint64_t cpusvn[2];
    uint32_t miscselect;
    uint8_t  reserved[28];
    sgx_arch_attributes_t attributes;
    sgx_arch_hash_t mrenclave;
    uint8_t  reserved2[32];
    sgx_arch_hash_t mrsigner;
    uint8_t  reserved3[96];
    uint16_t isvprodid, isvsvn;
    uint8_t  reserved4[60];
    uint8_t  report_data[64];
    uint8_t  keyid[32];
    sgx_arch_mac_t mac;
} __attribute__((packed, aligned(512))) sgx_arch_report_t;

#define SGX_REPORT_SIGNED_SIZE  384

typedef struct {
    sgx_arch_hash_t mrenclave;
    sgx_arch_attributes_t attributes;
    uint8_t  reserved[464];
} __attribute__((packed, aligned(512))) sgx_arch_targetinfo_t;

typedef struct {
    uint16_t keyname;
    uint16_t keypolicy;
    uint16_t isvsvn;
    uint8_t  reserved[2];
    uint64_t cpusvn[2];
    sgx_arch_attributes_t attributes_mask;
    uint8_t  keyid[32];
    uint32_t miscmask;
    uint8_t  reserved2[436];
} __attribute__((packed, aligned(512))) sgx_arch_keyrequest_t;

typedef uint8_t sgx_arch_key128_t[16] __attribute__((aligned(16)));

#else /* !__ASSEMBLER__ */

/* microcode to call ENCLU */
.macro ENCLU
    .byte 0x0f, 0x01, 0xd7
.endm

#endif

#define EENTER      2
#define ERESUME     3
#define EDBGRD      4
#define EDBGWR      5

#define EREPORT     0
#define EGETKEY     1
#define EEXIT       4

#define LAUNCH_KEY          0
#define PROVISION_KEY       1
#define PROVISION_SEAL_KEY  2
#define REPORT_KEY          3
#define SEAL_KEY            4

#define KEYPOLICY_MRENCLAVE     1
#define KEYPOLICY_MRSIGNER      2

#define SGX_GPR_RAX             0x00
#define SGX_GPR_RCX             0x08
#define SGX_GPR_RDX             0x10
#define SGX_GPR_RBX             0x18
#define SGX_GPR_RSP             0x20
#define SGX_GPR_RBP             0x28
#define SGX_GPR_RSI             0x30
#define SGX_GPR_RDI             0x38
#define SGX_GPR_R8              0x40
#define SGX_GPR_R9              0x48
#define SGX_GPR_R10             0x50
#define SGX_GPR_R11             0x58
#define SGX_GPR_R12             0x60
#define SGX_GPR_R13             0x68
#define SGX_GPR_R14             0x70
#define SGX_GPR_R15             0x78
#define SGX_GPR_RFLAGS          0x80
#define SGX_GPR_RIP             0x88
#define SGX_GPR_EXITINFO        0xa0

#define TCS_SIZE    4096
#define TCS_SHIFT   12

#define XSAVE_SIZE  512

#define STACK_ALIGN 0xfffffffffffffff0
#define XSAVE_ALIGN 0xffffffffffffffc0

#define RETURN_FROM_OCALL 0xffffffffffffffff

#endif /* SGX_ARCH_H */
