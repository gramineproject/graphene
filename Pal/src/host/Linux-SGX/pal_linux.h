/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#ifndef PAL_LINUX_H
#define PAL_LINUX_H

#include <asm/mman.h>
#include <linux/mman.h>

#include "api.h"
#include "assert.h"
#include "crypto.h"
#include "enclave_ocalls.h"
#include "linux_types.h"
#include "log.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_internal.h"
#include "pal_linux_defs.h"
#include "sgx_api.h"
#include "sgx_arch.h"
#include "sgx_attest.h"
#include "sgx_tls.h"
#include "sysdep-arch.h"

#define IS_ERR_P    INTERNAL_SYSCALL_ERROR_P
#define ERRNO_P     INTERNAL_SYSCALL_ERRNO_P
#define IS_UNIX_ERR INTERNAL_SYSCALL_ERRNO_RANGE

extern struct pal_linux_state {
    PAL_NUM parent_process_id;
    PAL_NUM process_id;

    const char** host_environ;

    /* credentials */
    unsigned int uid, gid;

    /* currently enabled signals */
    __sigset_t sigset;
    __sigset_t blocked_signals;

    /* enclave */
    const char* runtime_dir;
} g_linux_state;

#define DEFAULT_BACKLOG 2048

#define ACCESS_R 4
#define ACCESS_W 2
#define ACCESS_X 1

struct stat;
bool stataccess(struct stat* stats, int acc);

int init_child_process(PAL_HANDLE* parent);

#ifdef IN_ENCLAVE

extern const size_t g_page_size;
extern size_t g_pal_internal_mem_size;

struct pal_sec;
noreturn void pal_linux_main(char* uptr_libpal_uri, size_t libpal_uri_len, char* uptr_args,
                             size_t args_size, char* uptr_env, size_t env_size,
                             struct pal_sec* uptr_sec_info);
void pal_start_thread(void);

struct link_map;
void setup_pal_map(struct link_map* map);

extern char __text_start, __text_end, __data_start, __data_end;
#define TEXT_START ((void*)(&__text_start))
#define TEXT_END   ((void*)(&__text_end))
#define DATA_START ((void*)(&__data_start))
#define DATA_END   ((void*)(&__data_end))

extern int g_xsave_enabled;
extern uint64_t g_xsave_features;
extern uint32_t g_xsave_size;
#define XSAVE_RESET_STATE_SIZE (512 + 64)  // 512 for legacy regs, 64 for xsave header
extern const uint32_t g_xsave_reset_state[];

void init_xsave_size(uint64_t xfrm);
void save_xregs(PAL_XREGS_STATE* xsave_area);
void restore_xregs(const PAL_XREGS_STATE* xsave_area);
noreturn void _restore_sgx_context(sgx_cpu_context_t* uc, PAL_XREGS_STATE* xsave_area);

void _DkExceptionHandler(unsigned int exit_info, sgx_cpu_context_t* uc,
                         PAL_XREGS_STATE* xregs_state);
void _DkHandleExternalEvent(PAL_NUM event, sgx_cpu_context_t* uc, PAL_XREGS_STATE* xregs_state);

void init_cpuid(void);

bool is_tsc_usable(void);
uint64_t get_tsc_hz(void);
void init_tsc(void);

int init_enclave(void);
void init_untrusted_slab_mgr(void);

/* exchange and establish a 256-bit session key */
int _DkStreamKeyExchange(PAL_HANDLE stream, PAL_SESSION_KEY* key);

/* master key for all enclaves of one application, populated by the first enclave and inherited by
 * all other enclaves (children, their children, etc.); used as master key in pipes' encryption */
extern PAL_SESSION_KEY g_master_key;

/*
 * sgx_verify_report: verify a CPU-signed report from another local enclave
 * @report: the buffer storing the report to verify
 */
int sgx_verify_report(sgx_report_t* report);

/*!
 * \brief Obtain a CPU-signed report for local attestation.
 *
 * Caller must align all parameters to 512 bytes (cf. `__sgx_mem_aligned`).
 *
 * \param[in]  target_info  Information on the target enclave.
 * \param[in]  data         User-specified data to be included in the report.
 * \param[out] report       Output buffer to store the report.
 * \return                  0 on success, negative error code otherwise.
 */
int sgx_get_report(const sgx_target_info_t* target_info, const sgx_report_data_t* data,
                   sgx_report_t* report);

/*!
 * \brief Verify the remote enclave during SGX local attestation.
 *
 * Verifies that the MR_ENCLAVE of the remote enclave is the same as ours (all Graphene enclaves
 * with the same configuration have the same MR_ENCLAVE), and that the signer of the SGX report is
 * the owner of the newly established session key.
 *
 * \param  session key  Newly established session key between this enclave and remote enclave.
 * \param  mr_enclave   MR_ENCLAVE of the remote enclave received in its SGX report.
 * \param  remote_data  Remote enclave's SGX report data, contains hash of the session key.
 * \return 0 on success, negative error code otherwise.
 */
bool is_remote_enclave_ok(const PAL_SESSION_KEY* session_key, sgx_measurement_t* mr_enclave,
                          sgx_report_data_t* remote_data);
/*!
 * \brief Request a local report on an RPC stream (typically called by parent enclave).
 *
 * \param  stream           Stream handle for sending and receiving messages.
 * \param  sgx_report_data  User-defined data to embed into outbound SGX report.
 * \return 0 on success, negative error code otherwise.
 */
int _DkStreamReportRequest(PAL_HANDLE stream, sgx_report_data_t* sgx_report_data);
/*!
 * \brief Respond with a local report on an RPC stream (typically called by child enclave).
 *
 * \param  stream  stream handle for sending and receiving messages.
 * \param  sgx_report_data  User-defined data to embed into outbound SGX report.
 * \return 0 on success, negative error code otherwise.
 */
int _DkStreamReportRespond(PAL_HANDLE stream, sgx_report_data_t* sgx_report_data);

int _DkStreamSecureInit(PAL_HANDLE stream, bool is_server, PAL_SESSION_KEY* session_key,
                        LIB_SSL_CONTEXT** out_ssl_ctx, const uint8_t* buf_load_ssl_ctx,
                        size_t buf_size);
int _DkStreamSecureFree(LIB_SSL_CONTEXT* ssl_ctx);
int _DkStreamSecureRead(LIB_SSL_CONTEXT* ssl_ctx, uint8_t* buf, size_t len, bool is_blocking);
int _DkStreamSecureWrite(LIB_SSL_CONTEXT* ssl_ctx, const uint8_t* buf, size_t len,
                         bool is_blocking);
int _DkStreamSecureSave(LIB_SSL_CONTEXT* ssl_ctx, const uint8_t** obuf, size_t* olen);

#else /* IN_ENCLAVE */

#ifdef DEBUG
#ifndef SIGCHLD
#define SIGCHLD 17
#endif

#define ARCH_VFORK()                                                                 \
    (g_pal_enclave.pal_sec.in_gdb                                                    \
         ? INLINE_SYSCALL(clone, 4, CLONE_VM | CLONE_VFORK | SIGCHLD, 0, NULL, NULL) \
         : INLINE_SYSCALL(clone, 4, CLONE_VM | CLONE_VFORK, 0, NULL, NULL))
#else
#define ARCH_VFORK() \
    (INLINE_SYSCALL(clone, 4, CLONE_VM|CLONE_VFORK, 0, NULL, NULL))
#endif

int sgx_create_process(size_t nargs, const char** args, int* stream_fd, const char* manifest);

int clone(int (*__fn)(void* __arg), void* __child_stack, int __flags, const void* __arg, ...);

#endif /* IN_ENCLAVE */

#endif /* PAL_LINUX_H */
