/*
 * This is for enclave to make ocalls to untrusted runtime.
 */

#include <stdbool.h>
#include <stddef.h>
#include "linux_types.h"
#include "pal.h"
#include "sgx_arch.h"
#include "sgx_attest.h"

/*
 * GCC's structure padding may cause leaking from uninialized
 * regions (https://arxiv.org/abs/1710.09061).
 * A simple contermeasure is to enable packing for all ocall
 * argument structures.
 */
#pragma pack(push, 1)

typedef int (*sgx_ocall_fn_t)(void*);

enum {
    OCALL_EXIT = 0,
    OCALL_MMAP_UNTRUSTED,
    OCALL_MUNMAP_UNTRUSTED,
    OCALL_CPUID,
    OCALL_OPEN,
    OCALL_CLOSE,
    OCALL_READ,
    OCALL_WRITE,
    OCALL_FSTAT,
    OCALL_FIONREAD,
    OCALL_FSETNONBLOCK,
    OCALL_FCHMOD,
    OCALL_FSYNC,
    OCALL_FTRUNCATE,
    OCALL_LSEEK,
    OCALL_MKDIR,
    OCALL_GETDENTS,
    OCALL_RESUME_THREAD,
    OCALL_CLONE_THREAD,
    OCALL_CREATE_PROCESS,
    OCALL_FUTEX,
    OCALL_SOCKETPAIR,
    OCALL_SOCK_LISTEN,
    OCALL_SOCK_ACCEPT,
    OCALL_SOCK_CONNECT,
    OCALL_SOCK_RECV,
    OCALL_SOCK_SEND,
    OCALL_SOCK_RECV_FD,
    OCALL_SOCK_SEND_FD,
    OCALL_SOCK_SETOPT,
    OCALL_SOCK_SHUTDOWN,
    OCALL_GETTIME,
    OCALL_SLEEP,
    OCALL_POLL,
    OCALL_RENAME,
    OCALL_DELETE,
    OCALL_LOAD_DEBUG,
    OCALL_GET_ATTESTATION,
    OCALL_NR,
};

typedef struct {
    int ms_exitcode;
    int ms_is_exitgroup;
} ms_ocall_exit_t;

typedef struct {
    int ms_fd;
    uint64_t ms_offset;
    uint64_t ms_size;
    unsigned short ms_prot;
    void * ms_mem;
} ms_ocall_mmap_untrusted_t;

typedef struct {
    const void * ms_mem;
    uint64_t ms_size;
} ms_ocall_munmap_untrusted_t;

typedef struct {
    unsigned int ms_leaf;
    unsigned int ms_subleaf;
    unsigned int ms_values[4];
} ms_ocall_cpuid_t;

typedef struct {
    const char * ms_pathname;
    int ms_flags;
    unsigned short ms_mode;
} ms_ocall_open_t;

typedef struct {
    int ms_fd;
} ms_ocall_close_t;

typedef struct {
    int ms_fd;
    void * ms_buf;
    unsigned int ms_count;
} ms_ocall_read_t;

typedef struct {
    int ms_fd;
    const void * ms_buf;
    unsigned int ms_count;
} ms_ocall_write_t;

typedef struct {
    int ms_fd;
    struct stat ms_stat;
} ms_ocall_fstat_t;

typedef struct {
    int ms_fd;
} ms_ocall_fionread_t;

typedef struct {
    int ms_fd;
    int ms_nonblocking;
} ms_ocall_fsetnonblock_t;

typedef struct {
    int ms_fd;
    unsigned short ms_mode;
} ms_ocall_fchmod_t;

typedef struct {
    int ms_fd;
} ms_ocall_fsync_t;

typedef struct {
    int ms_fd;
    uint64_t ms_length;
} ms_ocall_ftruncate_t;

typedef struct {
    int ms_fd;
    uint64_t ms_offset;
    int ms_whence;
} ms_ocall_lseek_t;

typedef struct {
    const char * ms_pathname;
    unsigned short ms_mode;
} ms_ocall_mkdir_t;

typedef struct {
    int ms_fd;
    struct linux_dirent64 * ms_dirp;
    unsigned int ms_size;
} ms_ocall_getdents_t;

typedef struct {
    unsigned int ms_pid;
    const char * ms_uri;
    int ms_proc_fds[3];
    int ms_nargs;
    const char * ms_args[];
} ms_ocall_create_process_t;

typedef struct {
    int* ms_futex;
    int ms_op, ms_val;
    int64_t ms_timeout_us;
} ms_ocall_futex_t;

typedef struct {
    int ms_domain, ms_type, ms_protocol;
    int ms_sockfds[2];
} ms_ocall_socketpair_t;

typedef struct {
    int ms_domain, ms_type, ms_protocol;
    const struct sockaddr * ms_addr;
    unsigned int ms_addrlen;
    struct sockopt ms_sockopt;
} ms_ocall_sock_listen_t;

typedef struct {
    int ms_sockfd;
    struct sockaddr * ms_addr;
    unsigned int ms_addrlen;
    struct sockopt ms_sockopt;
} ms_ocall_sock_accept_t;

typedef struct {
    int ms_domain, ms_type, ms_protocol;
    const struct sockaddr * ms_addr;
    unsigned int ms_addrlen;
    struct sockaddr * ms_bind_addr;
    unsigned int ms_bind_addrlen;
    struct sockopt ms_sockopt;
} ms_ocall_sock_connect_t;

typedef struct {
    PAL_IDX ms_sockfd;
    void * ms_buf;
    unsigned int ms_count;
    struct sockaddr * ms_addr;
    unsigned int ms_addrlen;
} ms_ocall_sock_recv_t;

typedef struct {
    PAL_IDX ms_sockfd;
    const void * ms_buf;
    unsigned int ms_count;
    const struct sockaddr * ms_addr;
    unsigned int ms_addrlen;
} ms_ocall_sock_send_t;

typedef struct {
    int ms_sockfd;
    void * ms_buf;
    unsigned int ms_count;
    unsigned int * ms_fds;
    unsigned int ms_nfds;
} ms_ocall_sock_recv_fd_t;

typedef struct {
    int ms_sockfd;
    const void * ms_buf;
    unsigned int ms_count;
    const unsigned int * ms_fds;
    unsigned int ms_nfds;
} ms_ocall_sock_send_fd_t;

typedef struct {
    int ms_sockfd;
    int ms_level;
    int ms_optname;
    const void * ms_optval;
    unsigned int ms_optlen;
} ms_ocall_sock_setopt_t;

typedef struct {
    int ms_sockfd;
    int ms_how;
} ms_ocall_sock_shutdown_t;

typedef struct {
    unsigned long ms_microsec;
} ms_ocall_gettime_t;

typedef struct {
    unsigned long ms_microsec;
} ms_ocall_sleep_t;

typedef struct {
    struct pollfd* ms_fds;
    int ms_nfds;
    int64_t ms_timeout_us;
} ms_ocall_poll_t;

typedef struct {
    const char * ms_oldpath;
    const char * ms_newpath;
} ms_ocall_rename_t;

typedef struct {
    const char * ms_pathname;
} ms_ocall_delete_t;

typedef struct {
    unsigned int ms_tid;
} ms_ocall_schedule_t;

typedef struct {
    sgx_spid_t        ms_spid;
    const char*       ms_subkey;
    bool              ms_linkable;
    sgx_report_t      ms_report;
    sgx_quote_nonce_t ms_nonce;
    sgx_attestation_t ms_attestation;
} ms_ocall_get_attestation_t;

#pragma pack(pop)
