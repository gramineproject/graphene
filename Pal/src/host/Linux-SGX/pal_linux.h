/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#ifndef PAL_LINUX_H
#define PAL_LINUX_H

#include <asm/mman.h>
#include <linux/mman.h>

#include "api.h"
#include "assert.h"
#include "enclave_ocalls.h"
#include "linux_types.h"
#include "pal.h"
#include "pal_crypto.h"
#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "protected_files.h"
#include "sgx_api.h"
#include "sgx_arch.h"
#include "sgx_attest.h"
#include "sgx_tls.h"
#include "sysdep-arch.h"
#include "uthash.h"

#define IS_ERR      INTERNAL_SYSCALL_ERROR
#define IS_ERR_P    INTERNAL_SYSCALL_ERROR_P
#define ERRNO       INTERNAL_SYSCALL_ERRNO
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
extern size_t g_pal_internal_mem_size;

struct pal_sec;
noreturn void pal_linux_main(char* uptr_libpal_uri, size_t libpal_uri_len, char* uptr_args,
                             size_t args_size, char* uptr_env, size_t env_size,
                             struct pal_sec* uptr_sec_info);
void pal_start_thread(void);

struct link_map;
void setup_pal_map(struct link_map* map);

/* Locking and unlocking of Mutexes */
int __DkMutexCreate(struct mutex_handle* mut);
int _DkMutexAtomicCreate(struct mutex_handle* mut);
int __DkMutexDestroy(struct mutex_handle* mut);
int _DkMutexLock(struct mutex_handle* mut);
int _DkMutexLockTimeout(struct mutex_handle* mut, int64_t timeout_us);
int _DkMutexUnlock(struct mutex_handle* mut);

int* get_futex(void);
void free_futex(int* futex);

extern char __text_start, __text_end, __data_start, __data_end;
#define TEXT_START ((void*)(&__text_start))
#define TEXT_END   ((void*)(&__text_end))
#define DATA_START ((void*)(&__text_start))
#define DATA_END   ((void*)(&__text_end))

typedef struct {
    char bytes[32];
} sgx_checksum_t;
typedef struct {
    char bytes[16];
} sgx_stub_t;

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

int init_trusted_files(void);
void init_cpuid(void);

bool is_tsc_usable(void);
uint64_t get_tsc_hz(void);
void init_tsc(void);

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

int load_trusted_file(PAL_HANDLE file, sgx_stub_t** stubptr, uint64_t* sizeptr, int create,
                      void** umem);

enum {
    FILE_CHECK_POLICY_STRICT = 0,
    FILE_CHECK_POLICY_ALLOW_ALL_BUT_LOG,
};

int init_file_check_policy(void);

int get_file_check_policy(void);

int copy_and_verify_trusted_file(const char* path, const void* umem, uint64_t umem_start,
                                 uint64_t umem_end, void* buffer, uint64_t offset, uint64_t size,
                                 sgx_stub_t* stubs, uint64_t total_size);

int register_trusted_child(const char* uri, const char* mr_enclave_str);

int init_enclave(void);
int init_enclave_key(void);

void init_untrusted_slab_mgr(void);

/* Used to track map buffers for protected files */
DEFINE_LIST(pf_map);
struct pf_map {
    LIST_TYPE(pf_map) list;
    struct protected_file* pf;
    void* buffer;
    uint64_t size;
    uint64_t offset; /* offset in PF, needed for write buffers when flushing to the PF */
};
DEFINE_LISTP(pf_map);

/* List of PF map buffers; this list is traversed on PF flush (on file close) */
extern LISTP_TYPE(pf_map) g_pf_map_list;

/* Data of a protected file */
struct protected_file {
    UT_hash_handle hh;
    size_t path_len;
    char* path;
    pf_context_t* context; /* NULL until PF is opened */
    int64_t refcount; /* used for deciding when to call unload_protected_file() */
    int writable_fd; /* fd of underlying file for writable PF, -1 if no writable handles are open */
};

/* Initialize the PF library, register PFs from the manifest */
int init_protected_files(void);

/* Take ownership of the global PF lock */
void pf_lock(void);

/* Release ownership of the global PF lock */
void pf_unlock(void);

/* Set new wrap key for protected files (e.g., provisioned by remote user) */
int set_protected_files_key(const char* pf_key_hex);

/* Return a registered PF that matches specified path
   (or the path is contained in a registered PF directory) */
struct protected_file* get_protected_file(const char* path);

/* Load and initialize a PF (must be called before any I/O operations)
 *
 * path:   normalized host path
 * fd:     pointer to an opened file descriptor (must point to a valid value for the whole time PF
 *         is being accessed)
 * size:   underlying file size (in bytes)
 * mode:   access mode
 * create: if true, the PF is being created/truncated
 * pf:     (optional) PF pointer if already known
 */
struct protected_file* load_protected_file(const char* path, int* fd, size_t size,
                                           pf_file_mode_t mode, bool create,
                                           struct protected_file* pf);

/* Flush PF map buffers and optionally remove and free them.
   If pf is NULL, process all maps containing given buffer.
   If buffer is NULL, process all maps for given pf. */
int flush_pf_maps(struct protected_file* pf, void* buffer, bool remove);

/* Flush map buffers and unload/close the PF */
int unload_protected_file(struct protected_file* pf);

/* Find registered PF by path (exact match) */
struct protected_file* find_protected_file(const char* path);

/* Find protected file by handle (uses handle's path to call find_protected_file) */
struct protected_file* find_protected_file_handle(PAL_HANDLE handle);

/* exchange and establish a 256-bit session key */
int _DkStreamKeyExchange(PAL_HANDLE stream, PAL_SESSION_KEY* key);

typedef uint8_t sgx_sign_data_t[48];

/* master key for all enclaves of one application, populated by the first enclave and inherited by
 * all other enclaves (children, their children, etc.); used as master key in pipes' encryption */
extern PAL_SESSION_KEY g_master_key;

/* enclave state used for generating report */
extern struct pal_enclave_state {
    uint64_t        enclave_flags; // Reserved for flags
    uint64_t        enclave_id;    // Unique identifier for authentication
    sgx_sign_data_t enclave_data;  // Reserved for signing other data
} __attribute__((packed)) g_pal_enclave_state;
static_assert(sizeof(struct pal_enclave_state) == sizeof(sgx_report_data_t),
              "incorrect struct size");

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

typedef bool (*mr_enclave_check_t)(PAL_HANDLE, sgx_measurement_t*, struct pal_enclave_state*);

/*
 * _DkStreamReportRequest, _DkStreamReportRespond:
 * Request and respond a local report on an RPC stream
 *
 * @stream:           stream handle for sending and receiving messages
 * @data:             data to sign in the outbound message
 * @is_mr_enclave_ok: callback function for checking the measurement of the other end
 */
int _DkStreamReportRequest(PAL_HANDLE stream, sgx_sign_data_t* data,
                           mr_enclave_check_t is_mr_enclave_ok);
int _DkStreamReportRespond(PAL_HANDLE stream, sgx_sign_data_t* data,
                           mr_enclave_check_t is_mr_enclave_ok);

int _DkStreamSecureInit(PAL_HANDLE stream, bool is_server, PAL_SESSION_KEY* session_key,
                        LIB_SSL_CONTEXT** out_ssl_ctx, const uint8_t* buf_load_ssl_ctx,
                        size_t buf_size);
int _DkStreamSecureFree(LIB_SSL_CONTEXT* ssl_ctx);
int _DkStreamSecureRead(LIB_SSL_CONTEXT* ssl_ctx, uint8_t* buf, size_t len);
int _DkStreamSecureWrite(LIB_SSL_CONTEXT* ssl_ctx, const uint8_t* buf, size_t len);
int _DkStreamSecureSave(LIB_SSL_CONTEXT* ssl_ctx, const uint8_t** obuf, size_t* olen);

#include "sgx_arch.h"

#define PAL_ENCLAVE_INITIALIZED 0x0001ULL

#include "hex.h"

#else

int sgx_create_process(const char* uri, size_t nargs, const char** args, int* stream_fd,
                       const char* manifest);

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

#endif /* IN_ENCLAVE */

#ifdef IN_ENCLAVE
#undef uthash_fatal
#define uthash_fatal(msg)               \
    do {                                \
        __UNUSED(msg);                  \
        DkProcessExit(PAL_ERROR_NOMEM); \
    } while (0)
#endif

#ifndef IN_ENCLAVE
int clone(int (*__fn)(void* __arg), void* __child_stack, int __flags, const void* __arg, ...);
#endif

#endif /* PAL_LINUX_H */
