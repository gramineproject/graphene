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

/*
 * pal_internal.h
 *
 * This file contains definition of functions, variables and data structures
 * for internal uses.
 */

#ifndef SGX_INTERNAL_H
#define SGX_INTERNAL_H

#include "pal_linux.h"
#include "pal_security.h"
#include "api.h"

#include "sysdep-x86_64.h"
#include <sys/syscall.h>

#define IS_ERR INTERNAL_SYSCALL_ERROR
#define IS_ERR_P INTERNAL_SYSCALL_ERROR_P
#define ERRNO INTERNAL_SYSCALL_ERRNO
#define ERRNO_P INTERNAL_SYSCALL_ERRNO_P

int printf(const char * fmt, ...);
int snprintf(char * str, int size, const char * fmt, ...);

/* constants and macros to help rounding addresses to page
   boundaries */
extern unsigned long pagesize, pageshift, pagemask;

#undef ALLOC_ALIGNDOWN
#undef ALLOC_ALIGNUP
#undef ALLOC_ALIGNED

#define ALLOC_ALIGNDOWN(addr) \
    (pagesize ? ((unsigned long) (addr)) & pagemask : (unsigned long) (addr))
#define ALLOC_ALIGNUP(addr) \
    (pagesize ? (((unsigned long) (addr)) + pageshift) & pagemask : (unsigned long) (addr))
#define ALLOC_ALIGNED(addr) \
    (pagesize && ((unsigned long) (addr)) == (((unsigned long) (addr)) & pagemask))

uint32_t htonl (uint32_t longval);
uint16_t htons (uint16_t shortval);
uint32_t ntohl (uint32_t longval);
uint16_t ntohs (uint16_t shortval);

struct pal_enclave {
    /* attributes */
    unsigned long baseaddr;
    unsigned long size;
    unsigned long thread_num;
    unsigned long ssaframesize;

    /* files */
    int manifest;
    int exec;
    int sigfile;
    int token;

    /* manifest */
    struct config_store * config;

    /* security information */
    struct pal_sec pal_sec;
};

int open_gsgx (void);
bool is_wrfsbase_supported (void);

int read_enclave_token (int token_file, sgx_arch_token_t * token);
int read_enclave_sigstruct (int sigfile, sgx_arch_sigstruct_t * sig);

int create_enclave(sgx_arch_secs_t * secs,
                   unsigned long base,
                   unsigned long size,
                   sgx_arch_token_t * token);

enum sgx_page_type { SGX_PAGE_SECS, SGX_PAGE_TCS, SGX_PAGE_REG };
int add_pages_to_enclave(sgx_arch_secs_t * secs,
                         void * addr, void * user_addr,
                         unsigned long size,
                         enum sgx_page_type type, int prot,
                         bool skip_eextend,
                         const char * comment);

int init_enclave(sgx_arch_secs_t * secs,
                 sgx_arch_sigstruct_t * sigstruct,
                 sgx_arch_token_t * token);

int destroy_enclave(void * base_addr, size_t length);
void exit_process (int status, uint64_t start_exiting);

int sgx_ecall (long ecall_no, void * ms);
int sgx_raise (int event);

void async_exit_pointer (void);
#if SGX_HAS_FSGSBASE == 0
void double_async_exit (void);
#endif

int interrupt_thread (void * tcs);
int clone_thread (void);

void create_tcs_mapper (void * tcs_base, unsigned int thread_num);
void map_tcs (unsigned int tid);
void unmap_tcs (void);

extern __thread struct pal_enclave * current_enclave;

#define PAL_SEC() (&current_enclave->pal_sec)

extern __thread sgx_arch_tcs_t * current_tcs
            __attribute__((tls_model ("initial-exec")));

extern __thread unsigned long debug_register
            __attribute__((tls_model ("initial-exec")));

uint64_t sgx_edbgrd (void * addr);
void sgx_edbgwr (void * addr, uint64_t data);

int sgx_init_child_process (struct pal_sec * pal_sec);
int sgx_signal_setup (void);

#endif
