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

int printf(const char * fmt, ...) __attribute__((format(printf, 1, 2)));
int snprintf(char * str, size_t size, const char * fmt, ...) __attribute__((format(printf, 3, 4)));

/* constants and macros to help rounding addresses to page
   boundaries */
extern size_t g_page_size;

#undef IS_ALLOC_ALIGNED
#undef IS_ALLOC_ALIGNED_PTR
#undef ALLOC_ALIGN_UP
#undef ALLOC_ALIGN_UP_PTR
#undef ALLOC_ALIGN_DOWN
#undef ALLOC_ALIGN_DOWN_PTR

#define IS_ALLOC_ALIGNED(addr)     IS_ALIGNED_POW2(addr, g_page_size)
#define IS_ALLOC_ALIGNED_PTR(addr) IS_ALIGNED_PTR_POW2(addr, g_page_size)
#define ALLOC_ALIGN_UP(addr)       ALIGN_UP_POW2(addr, g_page_size)
#define ALLOC_ALIGN_UP_PTR(addr)   ALIGN_UP_PTR_POW2(addr, g_page_size)
#define ALLOC_ALIGN_DOWN(addr)     ALIGN_DOWN_POW2(addr, g_page_size)
#define ALLOC_ALIGN_DOWN_PTR(addr) ALIGN_DOWN_PTR_POW2(addr, g_page_size)

uint32_t htonl (uint32_t longval);
uint16_t htons (uint16_t shortval);
uint32_t ntohl (uint32_t longval);
uint16_t ntohs (uint16_t shortval);

extern struct pal_enclave {
    /* attributes */
    unsigned long baseaddr;
    unsigned long size;
    unsigned long thread_num;
    unsigned long rpc_thread_num;
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
} pal_enclave;

int open_gsgx (void);
bool is_wrfsbase_supported (void);

int read_enclave_token (int token_file, sgx_arch_token_t * token);
int read_enclave_sigstruct (int sigfile, sgx_arch_enclave_css_t * sig);

int create_enclave(sgx_arch_secs_t * secs,
                   sgx_arch_token_t * token);

enum sgx_page_type { SGX_PAGE_SECS, SGX_PAGE_TCS, SGX_PAGE_REG };
int add_pages_to_enclave(sgx_arch_secs_t * secs,
                         void * addr, void * user_addr,
                         unsigned long size,
                         enum sgx_page_type type, int prot,
                         bool skip_eextend,
                         const char * comment);

/*!
 * \brief Retrieve Quoting Enclave's sgx_target_info_t by talking to AESMD.
 *
 * \param[out] qe_targetinfo  Retrieved Quoting Enclave's target info.
 * \return                    0 on success, negative error code otherwise.
 */
int init_quoting_enclave_targetinfo(sgx_target_info_t* qe_targetinfo);

/*!
 * \brief Obtain SGX Quote from the Quoting Enclave (communicate via AESM).
 *
 * \param[in]  spid       Software provider ID (SPID).
 * \param[in]  linkable   Quote type (linkable vs unlinkable).
 * \param[in]  report     Enclave report to convert into a quote.
 * \param[in]  nonce      16B nonce to be included in the quote for freshness.
 * \param[out] quote      Quote returned by the Quoting Enclave (allocated via mmap() in this
 *                        function; the caller gets the ownership of the quote).
 * \param[out] quote_len  Length of the quote returned by the Quoting Enclave.
 * \return                0 on success, negative Linux error code otherwise.
 */
int retrieve_quote(const sgx_spid_t* spid, bool linkable, const sgx_report_t* report,
                   const sgx_quote_nonce_t* nonce, char** quote, size_t* quote_len);

int init_enclave(sgx_arch_secs_t * secs,
                 sgx_arch_enclave_css_t * sigstruct,
                 sgx_arch_token_t * token);

int destroy_enclave(void * base_addr, size_t length);
void exit_process (int status, uint64_t start_exiting);

int sgx_ecall (long ecall_no, void * ms);
int sgx_raise (int event);

void async_exit_pointer (void);

int interrupt_thread (void * tcs);
int clone_thread (void);

void create_tcs_mapper (void * tcs_base, unsigned int thread_num);
int pal_thread_init(void* tcbptr);
void map_tcs(unsigned int tid);
void unmap_tcs(void);
int current_enclave_thread_cnt(void);
void thread_exit(int status);

uint64_t sgx_edbgrd (void * addr);
void sgx_edbgwr (void * addr, uint64_t data);

int sgx_init_child_process (struct pal_sec * pal_sec);
int sgx_signal_setup (void);
int block_signals (bool block, const int * sigs, int nsig);
int block_async_signals (bool block);

#endif
