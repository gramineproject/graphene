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

#ifndef PAL_LINUX_H
#define PAL_LINUX_H

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "api.h"

#include "linux_types.h"
#include "sgx_arch.h"
#include "sgx_tls.h"
#include "sgx_api.h"
#include "enclave_ocalls.h"

#ifdef __x86_64__
# include "sysdep-x86_64.h"
#endif

#define IS_ERR INTERNAL_SYSCALL_ERROR
#define IS_ERR_P INTERNAL_SYSCALL_ERROR_P
#define ERRNO INTERNAL_SYSCALL_ERRNO
#define ERRNO_P INTERNAL_SYSCALL_ERRNO_P

extern struct pal_linux_state {
    PAL_NUM         parent_process_id;
    PAL_NUM         process_id;

    const char **   environ;

    /* credentials */
    unsigned int    uid, gid;

    /* currently enabled signals */
    __sigset_t      sigset;
    __sigset_t      blocked_signals;

    /* enclave */
    const char *    runtime_dir;
} linux_state;

#include <asm/mman.h>

#define PRESET_PAGESIZE (1 << 12)

#define DEFAULT_BACKLOG     2048

static inline int HOST_FLAGS (int alloc_type, int prot)
{
    return ((alloc_type & PAL_ALLOC_RESERVE) ? MAP_NORESERVE|MAP_UNINITIALIZED : 0) |
           ((prot & PAL_PROT_WRITECOPY) ? MAP_PRIVATE : MAP_SHARED);
}

static inline int HOST_PROT (int prot)
{
    return prot & (PAL_PROT_READ|PAL_PROT_WRITE|PAL_PROT_EXEC);
}

#define ACCESS_R    4
#define ACCESS_W    2
#define ACCESS_X    1

struct stat;
bool stataccess (struct stat * stats, int acc);

#ifdef IN_ENCLAVE

/* Locking and unlocking of Mutexes */
int __DkMutexCreate (struct mutex_handle * mut);
int _DkMutexAtomicCreate (struct mutex_handle * mut);
int __DkMutexDestroy (struct mutex_handle * mut);
int _DkMutexLock (struct mutex_handle * mut);
int _DkMutexLockTimeout (struct mutex_handle * mut, uint64_t timeout);
int _DkMutexUnlock (struct mutex_handle * mut);

int * get_futex (void);
void free_futex (int * futex);

extern char __text_start, __text_end, __data_start, __data_end;
#define TEXT_START (void *) (&__text_start)
#define TEXT_END   (void *) (&__text_end)
#define DATA_START (void *) (&__text_start)
#define DATA_END   (void *) (&__text_end)

typedef struct { char bytes[32]; } sgx_checksum_t;
typedef struct { char bytes[16]; } sgx_stub_t;

int init_trusted_files (void);

/* Function: load_trusted_file
 * checks if the file to be opened is trusted or allowed,
 * according to the setting in manifest
 *
 * file:     file handle to be opened
 * stubptr:  buffer for catching matched file stub.
 * sizeptr:  size pointer
 * create:   this file is newly created or not
 *
 * return:  0 succeed
 */

int load_trusted_file
    (PAL_HANDLE file, sgx_stub_t ** stubptr, uint64_t * sizeptr, int create);

int copy_and_verify_trusted_file (const char * path, const void * umem,
                    uint64_t umem_start, uint64_t umem_end,
                    void * buffer, uint64_t offset, uint64_t size,
                    sgx_stub_t * stubs, uint64_t total_size);

int init_trusted_children (void);
int register_trusted_child (const char * uri, const char * mrenclave_str);

/* if a stream is encrypted, its key is 256 bit */
typedef uint8_t PAL_SESSION_KEY [32];
typedef uint8_t PAL_MAC_KEY [16];

static inline
void session_key_to_mac_key (PAL_SESSION_KEY * session_key,
                             PAL_MAC_KEY * mac_key)
{
    uint8_t * s = (void *) session_key;
    uint8_t * m = (void *) mac_key;
    for (int i = 0 ; i < 16 ; i++)
        m[i] = s[i] ^ s[16 + i];
}

/* exchange and establish a 256-bit session key */
int _DkStreamKeyExchange (PAL_HANDLE stream, PAL_SESSION_KEY * key);

/* request and respond for remote attestation */
int _DkStreamAttestationRequest (PAL_HANDLE stream, void * data,
                                 int (*check_mrenclave) (sgx_arch_hash_t *,
                                                         void *, void *),
                                 void * check_param);
int _DkStreamAttestationRespond (PAL_HANDLE stream, void * data,
                                 int (*check_mrenclave) (sgx_arch_hash_t *,
                                                         void *, void *),
                                 void * check_param);

/* enclave state used for generating report */
#define PAL_ATTESTATION_DATA_SIZE   24

extern struct pal_enclave_state {
    uint64_t enclave_flags;         /* flags to specify the state of the
                                       enclave */
    uint8_t  data[PAL_ATTESTATION_DATA_SIZE];
                                    /* reserved for filling other data */
    sgx_arch_hash_t enclave_identifier;  /* unique identifier of the enclave */
} __attribute__((packed, aligned (128))) pal_enclave_state;

#include "sgx_arch.h"

#define PAL_ENCLAVE_INITIALIZED     0x0001ULL

extern struct pal_enclave_config {
    sgx_arch_hash_t        mrenclave;
    sgx_arch_attributes_t  enclave_attributes;
    void *                 enclave_key;
} pal_enclave_config;

#include <hex.h>

#else

#ifdef DEBUG
# ifndef SIGCHLD
#  define SIGCHLD  17
# endif

# define ARCH_VFORK()                                                       \
    (current_enclave->pal_sec.in_gdb ?                                      \
     INLINE_SYSCALL(clone, 4, CLONE_VM|CLONE_VFORK|SIGCHLD, 0, NULL, NULL) :\
     INLINE_SYSCALL(clone, 4, CLONE_VM|CLONE_VFORK, 0, NULL, NULL))
#else
# define ARCH_VFORK()                                                       \
    (INLINE_SYSCALL(clone, 4, CLONE_VM|CLONE_VFORK, 0, NULL, NULL))
#endif

#endif /* IN_ENCLAVE */

#define DBG_E   0x01
#define DBG_I   0x02
#define DBG_D   0x04
#define DBG_S   0x08
#define DBG_P   0x10
#define DBG_M   0x20

#ifdef DEBUG
# define DBG_LEVEL (DBG_E|DBG_I|DBG_D|DBG_S)
#else
# define DBG_LEVEL (DBG_E)
#endif

#ifdef IN_ENCLAVE
#define SGX_DBG(class, fmt...) \
    do { if ((class) & DBG_LEVEL) printf(fmt); } while (0)
#else
int pal_printf(const char * fmt, ...);

#define SGX_DBG(class, fmt...) \
    do { if ((class) & DBG_LEVEL) pal_printf(fmt); } while (0)
#endif

#endif /* PAL_LINUX_H */
