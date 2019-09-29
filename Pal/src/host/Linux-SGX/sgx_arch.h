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

#define SGX_HASH_SIZE        32
#define SGX_MAC_SIZE         16

typedef struct _sgx_measurement_t {
    uint8_t  m[SGX_HASH_SIZE];
} sgx_measurement_t;

typedef uint8_t  sgx_mac_t[SGX_MAC_SIZE];

// This if for passing a mac to hex2str
#define MACBUF_SIZE ((sizeof(sgx_mac_t) * 2) + 1)

typedef struct _sgx_attributes_t {
    uint64_t  flags;
    uint64_t  xfrm;
} sgx_attributes_t;

#define SGX_CPUSVN_SIZE       16
#define SGX_CONFIGID_SIZE     64
#define SGX_KEYID_SIZE        32
#define SGX_REPORT_DATA_SIZE  64

typedef struct _sgx_cpu_svn_t {
    uint8_t  svn[SGX_CPUSVN_SIZE];
} sgx_cpu_svn_t;

typedef uint32_t  sgx_misc_select_t;
typedef uint16_t  sgx_prod_id_t;
typedef uint16_t  sgx_isv_svn_t;
typedef uint16_t  sgx_config_svn_t;
typedef uint8_t   sgx_config_id_t[SGX_CONFIGID_SIZE];

#define SGX_FLAGS_INITIALIZED    0x01ULL
#define SGX_FLAGS_DEBUG          0x02ULL
#define SGX_FLAGS_MODE64BIT      0x04ULL
#define SGX_FLAGS_PROVISION_KEY  0x10ULL
#define SGX_FLAGS_LICENSE_KEY    0x20ULL

#define SGX_XFRM_LEGACY          0x03ULL
#define SGX_XFRM_AVX             0x06ULL
#define SGX_XFRM_MPX             0x18ULL
#define SGX_XFRM_AVX512          0xe6ULL

#define SGX_MISCSELECT_EXINFO    0x01UL

typedef struct {
    uint64_t          size;
    uint64_t          baseaddr;
    uint32_t          ssaframesize;
    sgx_misc_select_t miscselect;
    uint8_t           reserved[24];
    sgx_attributes_t  attributes;
    sgx_measurement_t mrenclave;
    uint8_t           reserved2[32];
    sgx_measurement_t mrsigner;
    uint8_t           reserved3[96];
    sgx_prod_id_t     isvprodid;
    sgx_isv_svn_t     isvsvn;
    uint8_t           reserved4[3836];
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
    uint64_t fsbase;
    uint64_t gsbase;
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
} sgx_cpu_context_t;

// Required by _restore_sgx_context, see enclave_entry.S.
_Static_assert(offsetof(sgx_cpu_context_t, rip) - offsetof(sgx_cpu_context_t, rflags) ==
               sizeof(((sgx_cpu_context_t) {0}).rflags),
               "rip must be directly after rflags in sgx_cpu_context_t");
_Static_assert(offsetof(sgx_cpu_context_t, rflags) - offsetof(sgx_cpu_context_t, rdi) <= RED_ZONE_SIZE,
               "rdi needs to be within red zone distance from rflags");

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
    sgx_misc_select_t miscselect;
    sgx_misc_select_t miscselect_mask;
    uint8_t  reserved2[20];
    sgx_attributes_t attributes;
    sgx_attributes_t attribute_mask;
    sgx_measurement_t enclave_hash;
    uint8_t  reserved3[32];
    sgx_prod_id_t isvprodid;
    sgx_isv_svn_t isvsvn;

    /* tail part (unsigned) */
    uint8_t  reserved4[12];
    sgx_arch_key_t q1;
    sgx_arch_key_t q2;
} __attribute__((packed)) sgx_arch_sigstruct_t;

typedef struct {
    uint32_t valid;
    uint8_t  reserved[44];
    sgx_attributes_t attributes;
    sgx_measurement_t mrenclave;
    uint8_t  reserved2[32];
    sgx_measurement_t mrsigner;
    uint8_t  reserved3[32];
    sgx_cpu_svn_t cpusvnle;
    sgx_prod_id_t isvprodidle;
    sgx_isv_svn_t isvsvnle;
    uint8_t  reserved4[24];
    sgx_misc_select_t miscselect_mask;
    sgx_attributes_t attribute_mask;
    sgx_measurement_t keyid;
    sgx_mac_t mac;
} __attribute__((packed)) sgx_arch_token_t;

typedef struct _sgx_report_data_t {
    uint8_t  d[SGX_REPORT_DATA_SIZE];
} sgx_report_data_t;

#define __sgx_mem_aligned __attribute__((aligned(512)))

typedef struct _report_body_t {
    sgx_cpu_svn_t      cpu_svn;
    sgx_misc_select_t  misc_select;
    uint8_t            reserved1[28];
    sgx_attributes_t   attributes;
    sgx_measurement_t  mr_enclave;
    uint8_t            reserved2[32];
    sgx_measurement_t  mr_signer;
    uint8_t            reserved3[96];
    sgx_prod_id_t      isv_prod_id;
    sgx_isv_svn_t      isv_svn;
    uint8_t            reserved4[60];
    sgx_report_data_t  report_data;
} sgx_report_body_t;

typedef struct _sgx_key_id_t
{
    uint8_t  id[SGX_KEYID_SIZE];
} sgx_key_id_t;

typedef struct _report_t {
    sgx_report_body_t  body;
    sgx_key_id_t       key_id;
    sgx_mac_t          mac;
} sgx_report_t;

#define SGX_REPORT_SIGNED_SIZE  384
#define SGX_REPORT_ACTUAL_SIZE  432

typedef struct _target_info_t {
    sgx_measurement_t  mr_enclave;
    sgx_attributes_t   attributes;
    uint8_t            reserved1[2];
    sgx_config_svn_t   config_svn;
    sgx_misc_select_t  misc_select;
    uint8_t            reserved2[8];
    sgx_config_id_t    config_id;
    uint8_t            reserved3[384];
} sgx_target_info_t;

typedef struct _key_request_t {
    uint16_t           key_name;
    uint16_t           key_policy;
    sgx_isv_svn_t      isv_svn;
    uint16_t           reserved1;
    sgx_cpu_svn_t      cpu_svn;
    sgx_attributes_t   attribute_mask;
    sgx_key_id_t       key_id;
    sgx_misc_select_t  misc_mask;
    sgx_config_svn_t   config_svn;
    uint8_t            reserved2[434];
    // struct is 512-bytes in size, alignment is required for EGETKEY
} sgx_key_request_t;

#define SGX_TARGETINFO_FILLED_SIZE  (sizeof(sgx_measurement_t) + \
                                     sizeof(sgx_attributes_t))

typedef uint8_t sgx_arch_key128_t[16];

#define ENCLU ".byte 0x0f, 0x01, 0xd7"

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

#define XSAVE_SIZE  512

#define STACK_ALIGN 0xfffffffffffffff0
#define XSAVE_ALIGN 0xffffffffffffffc0
#define XSAVE_NON_FX_MASK 0xfffffffffffffffc

#define RETURN_FROM_OCALL 0xffffffffffffffff

#define RFLAGS_DF (1<<10)

#endif /* SGX_ARCH_H */
