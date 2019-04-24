/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/*
 * This is for enclave to make ocalls to untrusted runtime.
 */

#include "pal_linux.h"
#include "pal_internal.h"
#include "pal_debug.h"
#include "enclave_ocalls.h"
#include "ocall_types.h"
#include "ecall_types.h"
#include <api.h>
#include <asm/errno.h>

/* Allocate size bytes on untrusted stack frame of this OCALL.
 * NULL is returned if there is no memory available on untrusted
 * stack. Used to allocate ms structs. */
static void* alloc_ms_outside_enclave(uint64_t size) {
    return sgx_ocalloc(size);
}

/* First check if region (ptr, size) is at least partially inside
 * enclave. If yes, then allocate size bytes on untrusted stack
 * frame of this OCALL and return pointer to allocated region.
 * Otherwise region is already outside of enclave, so return ptr. */
static void* alloc_outside_enclave(void* ptr, uint64_t size) {
    if (!sgx_is_completely_outside_enclave(ptr, size)) {
        return sgx_ocalloc(size);
    }
    return ptr;
}

/* First check if region (ptr, size) is at least partially inside
 * enclave. If yes, then allocate size bytes on untrusted stack
 * frame of this OCALL, copy to allocated region, and return pointer
 * to allocated region. Otherwise region is already outside of enclave,
 * no copy is needed, so return ptr. */
static void* copy_outside_enclave(const void* ptr, uint64_t size) {
    if (!sgx_is_completely_outside_enclave(ptr, size)) {
        void* tmp = sgx_ocalloc(size);
        if (tmp) {
            memcpy(tmp, ptr, size);
        }
        return tmp;
    };
    return (void*) ptr;
}

/* Check that the region uptr points to (with the given size) is
 * completely in untrusted memory. If the check is successful,
 * ptr is set to checked value and true is returned.
 * Otherwise ptr is set to NULL and false is returned.
 *
 * NOTE: Value from possibly untrusted uptr must be copied inside
 * CPU register or enclave stack (to prevent TOCTOU). Function call
 * achieves this. Attribute ensures no inline optimization. */
static __attribute__((noinline))
bool copy_ptr_inside_enclave(void** ptr, void* uptr, uint64_t size) {
    if (!ptr)
        return false;
    *ptr = NULL;
    if (sgx_is_completely_outside_enclave(uptr, size)) {
        *ptr = uptr;
        return true;
    }
    return false;
}

/* Check that:
 *   - there is no buffer/integer overflow and
 *   - region (uptr, usize) is completely in untrusted memory and
 *   - if destination ptr isn't same as uptr, then region (uptr, usize)
 *     is completely within enclave memory.
 * If the checks are successful, copy region of untrusted memory (uptr, usize)
 * inside enclave and return number of bytes copied. Otherwise return 0.
 *
 * NOTE: Value from possibly untrusted uptr and usize must be copied
 * inside CPU registers or enclave stack (to prevent TOCTOU). Function
 * call achieves this. Attribute ensures no inline optimization. */
static __attribute__((noinline))
uint64_t copy_inside_enclave(const void* ptr, uint64_t maxsize, const void* uptr, uint64_t usize) {
    if (usize <= maxsize && sgx_is_completely_outside_enclave(uptr, usize)) {
        if (ptr != uptr) {
            if (sgx_is_completely_within_enclave(ptr, usize)) {
                memcpy((void*) ptr, uptr, usize);
                return usize;
            }
        } else {
            return usize;
        }
    }
    return 0;
}

/* Free untrusted stack frame of this OCALL. */
static void cleanup() {
    sgx_ocfree();
}


int ocall_exit(int exitcode)
{
    int64_t code = exitcode;
    // There are two reasons for this loop:
    //  1. Ocalls can be interuppted.
    //  2. We can't trust the outside to actually exit, so we need to ensure
    //     that we never return even when the outside tries to trick us.
    while (true) {
        sgx_ocall(OCALL_EXIT, (void *) code);
    }
    return 0;
}

int ocall_print_string (const char * str, unsigned int length)
{
    int retval = 0;
    ms_ocall_print_string_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    if (!str || length <= 0) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_length = length;
    ms->ms_str = copy_outside_enclave(str, length);

    if (!ms->ms_str) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    retval = sgx_ocall(OCALL_PRINT_STRING, ms);

    cleanup();
    return retval;
}

int ocall_alloc_untrusted (uint64_t size, void ** mem)
{
    int retval = 0;
    ms_ocall_alloc_untrusted_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_size = size;

    retval = sgx_ocall(OCALL_ALLOC_UNTRUSTED, ms);

    if (!retval) {
        if (!copy_ptr_inside_enclave(mem, ms->ms_mem, size)) {
            cleanup();
            return -PAL_ERROR_DENIED;
        }
    }

    cleanup();
    return retval;
}

int ocall_map_untrusted (int fd, uint64_t offset,
                         uint64_t size, unsigned short prot,
                         void ** mem)
{
    int retval = 0;
    ms_ocall_map_untrusted_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_fd = fd;
    ms->ms_offset = offset;
    ms->ms_size = size;
    ms->ms_prot = prot;

    retval = sgx_ocall(OCALL_MAP_UNTRUSTED, ms);

    if (!retval) {
        if (!copy_ptr_inside_enclave(mem, ms->ms_mem, size)) {
            cleanup();
            return -PAL_ERROR_DENIED;
        }
    }

    cleanup();
    return retval;
}

int ocall_unmap_untrusted (const void * mem, uint64_t size)
{
    int retval = 0;
    ms_ocall_unmap_untrusted_t * ms;

    if (!sgx_is_completely_outside_enclave(mem, size)) {
        cleanup();
        return -PAL_ERROR_INVAL;
    }

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_mem  = mem;
    ms->ms_size = size;

    retval = sgx_ocall(OCALL_UNMAP_UNTRUSTED, ms);

    cleanup();
    return retval;
}

int ocall_cpuid (unsigned int leaf, unsigned int subleaf,
                 unsigned int values[4])
{
    int retval = 0;
    ms_ocall_cpuid_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_leaf = leaf;
    ms->ms_subleaf = subleaf;

    retval = sgx_ocall(OCALL_CPUID, ms);

    if (!retval) {
        values[0] = ms->ms_values[0];
        values[1] = ms->ms_values[1];
        values[2] = ms->ms_values[2];
        values[3] = ms->ms_values[3];
    }

    cleanup();
    return retval;
}

int ocall_open (const char * pathname, int flags, unsigned short mode)
{
    int retval = 0;
    int len = pathname ? strlen(pathname) + 1 : 0;
    ms_ocall_open_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_flags = flags;
    ms->ms_mode = mode;
    ms->ms_pathname = copy_outside_enclave(pathname, len);

    if (!ms->ms_pathname) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    retval = sgx_ocall(OCALL_OPEN, ms);

    cleanup();
    return retval;
}

int ocall_close (int fd)
{
    int retval = 0;
    ms_ocall_close_t *ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_fd = fd;

    retval = sgx_ocall(OCALL_CLOSE, ms);

    cleanup();
    return retval;
}

int ocall_read (int fd, void * buf, unsigned int count)
{
    int retval = 0;
    void * obuf = NULL;
    ms_ocall_read_t * ms;

    if (count > 4096) {
        retval = ocall_alloc_untrusted(ALLOC_ALIGNUP(count), &obuf);
        if (retval < 0)
            return retval;
    }

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        retval = -PAL_ERROR_DENIED;
        goto out;
    }

    ms->ms_fd = fd;
    ms->ms_count = count;
    if (obuf)
        ms->ms_buf = obuf;
    else
        ms->ms_buf = alloc_outside_enclave(buf, count);

    if (!ms->ms_buf) {
        retval = -PAL_ERROR_DENIED;
        goto out;
    }

    retval = sgx_ocall(OCALL_READ, ms);

    if (retval > 0) {
        if (!copy_inside_enclave(buf, count, ms->ms_buf, retval)) {
            retval = -PAL_ERROR_DENIED;
            goto out;
        }
    }

out:
    cleanup();
    if (obuf)
        ocall_unmap_untrusted(obuf, ALLOC_ALIGNUP(count));
    return retval;
}

int ocall_write (int fd, const void * buf, unsigned int count)
{
    int retval = 0;
    void * obuf = NULL;
    ms_ocall_write_t * ms;

    if (count > 4096) {
        retval = ocall_alloc_untrusted(ALLOC_ALIGNUP(count), &obuf);
        if (retval < 0)
            return retval;
    }

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        retval = -PAL_ERROR_DENIED;
        goto out;
    }

    ms->ms_fd = fd;
    ms->ms_count = count;
    if (obuf) {
        ms->ms_buf = obuf;
        memcpy(obuf, buf, count);
    } else {
        ms->ms_buf = copy_outside_enclave(buf, count);
    }

    if (!ms->ms_buf) {
        retval = -PAL_ERROR_DENIED;
        goto out;
    }

    retval = sgx_ocall(OCALL_WRITE, ms);

out:
    cleanup();
    if (obuf)
        ocall_unmap_untrusted(obuf, ALLOC_ALIGNUP(count));
    return retval;
}

int ocall_fstat (int fd, struct stat * buf)
{
    int retval = 0;
    ms_ocall_fstat_t * ms;


    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_fd = fd;

    retval = sgx_ocall(OCALL_FSTAT, ms);

    if (!retval)
        memcpy(buf, &ms->ms_stat, sizeof(struct stat));

    cleanup();
    return retval;
}

int ocall_fionread (int fd)
{
    int retval = 0;
    ms_ocall_fionread_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_fd = fd;

    retval = sgx_ocall(OCALL_FIONREAD, ms);

    cleanup();
    return retval;
}

int ocall_fsetnonblock (int fd, int nonblocking)
{
    int retval = 0;
    ms_ocall_fsetnonblock_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_fd = fd;
    ms->ms_nonblocking = nonblocking;

    retval = sgx_ocall(OCALL_FSETNONBLOCK, ms);

    cleanup();
    return retval;
}

int ocall_fchmod (int fd, unsigned short mode)
{
    int retval = 0;
    ms_ocall_fchmod_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_fd = fd;
    ms->ms_mode = mode;

    retval = sgx_ocall(OCALL_FCHMOD, ms);

    cleanup();
    return retval;
}

int ocall_fsync (int fd)
{
    int retval = 0;
    ms_ocall_fsync_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_fd = fd;

    retval = sgx_ocall(OCALL_FSYNC, ms);

    cleanup();
    return retval;
}

int ocall_ftruncate (int fd, uint64_t length)
{
    int retval = 0;
    ms_ocall_ftruncate_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_fd = fd;
    ms->ms_length = length;

    retval = sgx_ocall(OCALL_FTRUNCATE, ms);

    cleanup();
    return retval;
}

int ocall_mkdir (const char * pathname, unsigned short mode)
{
    int retval = 0;
    int len = pathname ? strlen(pathname) + 1 : 0;
    ms_ocall_mkdir_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_mode = mode;
    ms->ms_pathname = copy_outside_enclave(pathname, len);

    if (!ms->ms_pathname) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    retval = sgx_ocall(OCALL_MKDIR, ms);

    cleanup();
    return retval;
}

int ocall_getdents (int fd, struct linux_dirent64 * dirp, unsigned int size)
{
    int retval = 0;
    ms_ocall_getdents_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_fd = fd;
    ms->ms_size = size;
    ms->ms_dirp = alloc_outside_enclave(dirp, size);

    if (!ms->ms_dirp) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    retval = sgx_ocall(OCALL_GETDENTS, ms);

    if (retval > 0) {
        if (!copy_inside_enclave(dirp, size, ms->ms_dirp, retval)) {
            cleanup();
            return -PAL_ERROR_DENIED;
        }
    }

    cleanup();
    return retval;
}

int ocall_wake_thread (void * tcs)
{
    return sgx_ocall(OCALL_WAKE_THREAD, tcs);
}

int ocall_create_process (const char * uri,
                          int nargs, const char ** args,
                          int procfds[3],
                          unsigned int * pid)
{
    int retval = 0;
    int ulen = uri ? strlen(uri) + 1 : 0;
    ms_ocall_create_process_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms) + nargs * sizeof(char *));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_uri = uri ? copy_outside_enclave(uri, ulen) : NULL;
    if (uri && !ms->ms_uri) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_nargs = nargs;
    for (int i = 0 ; i < nargs ; i++) {
        int len = args[i] ? strlen(args[i]) + 1 : 0;
        ms->ms_args[i] = args[i] ? copy_outside_enclave(args[i], len) : NULL;

        if (args[i] && !ms->ms_args[i]) {
            cleanup();
            return -PAL_ERROR_DENIED;
        }
    }

    retval = sgx_ocall(OCALL_CREATE_PROCESS, ms);

    if (!retval) {
        if (pid)
            *pid = ms->ms_pid;
        procfds[0] = ms->ms_proc_fds[0];
        procfds[1] = ms->ms_proc_fds[1];
        procfds[2] = ms->ms_proc_fds[2];
    }

    cleanup();
    return retval;
}

int ocall_futex (int * futex, int op, int val,
                 const uint64_t * timeout)
{
    int retval = 0;
    ms_ocall_futex_t * ms;

    if (!sgx_is_completely_outside_enclave(futex, sizeof(int))) {
        cleanup();
        return -PAL_ERROR_INVAL;
    }

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_futex = futex;
    ms->ms_op = op;
    ms->ms_val = val;
    ms->ms_timeout = timeout ? *timeout : OCALL_NO_TIMEOUT;

    retval = sgx_ocall(OCALL_FUTEX, ms);

    cleanup();
    return retval;
}

int ocall_socketpair (int domain, int type, int protocol,
                      int sockfds[2])
{
    int retval = 0;
    ms_ocall_socketpair_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_domain = domain;
    ms->ms_type = type;
    ms->ms_protocol = protocol;

    retval = sgx_ocall(OCALL_SOCKETPAIR, ms);

    if (!retval) {
        sockfds[0] = ms->ms_sockfds[0];
        sockfds[1] = ms->ms_sockfds[1];
    }

    cleanup();
    return retval;
}

int ocall_sock_listen (int domain, int type, int protocol,
                       struct sockaddr * addr, unsigned int * addrlen,
                       struct sockopt * sockopt)
{
    int retval = 0;
    unsigned int copied;
    unsigned int len = addrlen ? *addrlen : 0;
    ms_ocall_sock_listen_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_domain = domain;
    ms->ms_type = type;
    ms->ms_protocol = protocol;
    ms->ms_addrlen = len;
    ms->ms_addr = (addr && len) ? copy_outside_enclave(addr, len) : NULL;

    if (addr && len && !ms->ms_addr) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    retval = sgx_ocall(OCALL_SOCK_LISTEN, ms);

    if (retval >= 0) {
        if (addr && len) {
            copied = copy_inside_enclave(addr, len, ms->ms_addr, ms->ms_addrlen);
            if (!copied) {
                cleanup();
                return -PAL_ERROR_DENIED;
            }
            *addrlen = copied;
        }

        if (sockopt) {
            *sockopt = ms->ms_sockopt;
        }
    }

    cleanup();
    return retval;
}

int ocall_sock_accept (int sockfd, struct sockaddr * addr,
                       unsigned int * addrlen, struct sockopt * sockopt)
{
    int retval = 0;
    unsigned int copied;
    unsigned int len = addrlen ? *addrlen : 0;
    ms_ocall_sock_accept_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_addrlen = len;
    ms->ms_addr = (addr && len) ? copy_outside_enclave(addr, len) : NULL;

    if (addr && len && !ms->ms_addr) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    retval = sgx_ocall(OCALL_SOCK_ACCEPT, ms);

    if (retval >= 0) {
        if (addr && len) {
            copied = copy_inside_enclave(addr, len, ms->ms_addr, ms->ms_addrlen);
            if (!copied) {
                cleanup();
                return -PAL_ERROR_DENIED;
            }
            *addrlen = copied;
        }

        if (sockopt) {
            *sockopt = ms->ms_sockopt;
        }
    }

    cleanup();
    return retval;
}

int ocall_sock_connect (int domain, int type, int protocol,
                        const struct sockaddr * addr,
                        unsigned int addrlen,
                        struct sockaddr * bind_addr,
                        unsigned int * bind_addrlen, struct sockopt * sockopt)
{
    int retval = 0;
    unsigned int copied;
    unsigned int bind_len = bind_addrlen ? *bind_addrlen : 0;
    ms_ocall_sock_connect_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_domain = domain;
    ms->ms_type = type;
    ms->ms_protocol = protocol;
    ms->ms_addrlen = addrlen;
    ms->ms_bind_addrlen = bind_len;
    ms->ms_addr = addr ? copy_outside_enclave(addr, addrlen) : NULL;
    ms->ms_bind_addr = bind_addr ? copy_outside_enclave(bind_addr, bind_len) : NULL;

    if ((addr && !ms->ms_addr) || (bind_addr && !ms->ms_bind_addr)) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    retval = sgx_ocall(OCALL_SOCK_CONNECT, ms);

    if (retval >= 0) {
        if (bind_addr && bind_len) {
            copied = copy_inside_enclave(bind_addr, bind_len, ms->ms_bind_addr, ms->ms_bind_addrlen);
            if (!copied) {
                cleanup();
                return -PAL_ERROR_DENIED;
            }
            *bind_addrlen = copied;
        }

        if (sockopt) {
            *sockopt = ms->ms_sockopt;
        }
    }

    cleanup();
    return retval;
}

int ocall_sock_recv (int sockfd, void * buf, unsigned int count,
                     struct sockaddr * addr, unsigned int * addrlen)
{
    int retval = 0;
    unsigned int copied;
    unsigned int len = addrlen ? *addrlen : 0;
    ms_ocall_sock_recv_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_count = count;
    ms->ms_addrlen = len;
    ms->ms_buf = alloc_outside_enclave(buf, count);
    ms->ms_addr = addr ? alloc_outside_enclave(addr, len) : NULL;

    if (!ms->ms_buf || (addr && !ms->ms_addr)) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    retval = sgx_ocall(OCALL_SOCK_RECV, ms);

    if (retval >= 0) {
        if (addr && len) {
            copied = copy_inside_enclave(addr, len, ms->ms_addr, ms->ms_addrlen);
            if (!copied) {
                cleanup();
                return -PAL_ERROR_DENIED;
            }
            *addrlen = copied;
        }

        if (!copy_inside_enclave(buf, count, ms->ms_buf, retval)) {
            cleanup();
            return -PAL_ERROR_DENIED;
        }
    }

    cleanup();
    return retval;
}

int ocall_sock_send (int sockfd, const void * buf, unsigned int count,
                     const struct sockaddr * addr, unsigned int addrlen)
{
    int retval = 0;
    ms_ocall_sock_send_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_count = count;
    ms->ms_addrlen = addrlen;
    ms->ms_buf = copy_outside_enclave(buf, count);
    ms->ms_addr = addr ? copy_outside_enclave(addr, addrlen) : NULL;

    if (!ms->ms_buf || (addr && !ms->ms_addr)) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    retval = sgx_ocall(OCALL_SOCK_SEND, ms);

    cleanup();
    return retval;
}

int ocall_sock_recv_fd (int sockfd, void * buf, unsigned int count,
                        unsigned int * fds, unsigned int * nfds)
{
    int retval = 0;
    unsigned int copied;
    unsigned int max_nfds_bytes = (*nfds) * sizeof(int);
    ms_ocall_sock_recv_fd_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_count = count;
    ms->ms_nfds = *nfds;
    ms->ms_buf = alloc_outside_enclave(buf, count);
    ms->ms_fds = alloc_outside_enclave(fds, max_nfds_bytes);

    if (!ms->ms_buf || !ms->ms_fds) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    retval = sgx_ocall(OCALL_SOCK_RECV_FD, ms);

    if (retval >= 0) {
        if (!copy_inside_enclave(buf, count, ms->ms_buf, retval)) {
            cleanup();
            return -PAL_ERROR_DENIED;
        }

        copied = copy_inside_enclave(fds, max_nfds_bytes, ms->ms_fds, ms->ms_nfds * sizeof(int));
        if (!copied) {
            cleanup();
            return -PAL_ERROR_DENIED;
        }
        *nfds = copied / sizeof(int);
    }

    cleanup();
    return retval;
}

int ocall_sock_send_fd (int sockfd, const void * buf, unsigned int count,
                        const unsigned int * fds, unsigned int nfds)
{
    int retval = 0;
    ms_ocall_sock_send_fd_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_count = count;
    ms->ms_nfds = nfds;
    ms->ms_buf = copy_outside_enclave(buf, count);
    ms->ms_fds = copy_outside_enclave(fds, nfds * sizeof(int));

    if (!ms->ms_buf || !ms->ms_fds) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    retval = sgx_ocall(OCALL_SOCK_SEND_FD, ms);

    cleanup();
    return retval;
}

int ocall_sock_setopt (int sockfd, int level, int optname,
                       const void * optval, unsigned int optlen)
{
    int retval = 0;
    ms_ocall_sock_setopt_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_level = level;
    ms->ms_optname = optname;
    ms->ms_optlen = 0;
    ms->ms_optval = NULL;

    if (optval && optlen > 0) {
        ms->ms_optlen = optlen;
        ms->ms_optval = copy_outside_enclave(optval, optlen);

        if (!ms->ms_optval) {
            cleanup();
            return -PAL_ERROR_DENIED;
        }
    }

    retval = sgx_ocall(OCALL_SOCK_SETOPT, ms);

    cleanup();
    return retval;
}

int ocall_sock_shutdown (int sockfd, int how)
{
    int retval = 0;
    ms_ocall_sock_shutdown_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_how = how;

    retval = sgx_ocall(OCALL_SOCK_SHUTDOWN, ms);

    cleanup();
    return retval;
}

int ocall_gettime (unsigned long * microsec)
{
    int retval = 0;
    ms_ocall_gettime_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    retval = sgx_ocall(OCALL_GETTIME, ms);
    if (!retval)
        *microsec = ms->ms_microsec;

    cleanup();
    return retval;
}

int ocall_sleep (unsigned long * microsec)
{
    int retval = 0;
    ms_ocall_sleep_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_microsec = microsec ? *microsec : 0;

    retval = sgx_ocall(OCALL_SLEEP, ms);
    if (microsec) {
        if (!retval)
            *microsec = 0;
        else if (retval == -EINTR)
            *microsec = ms->ms_microsec;
    }

    cleanup();
    return retval;
}

int ocall_poll (struct pollfd * fds, int nfds, uint64_t * timeout)
{
    int retval = 0;
    unsigned int nfds_bytes = nfds * sizeof(struct pollfd);
    ms_ocall_poll_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_nfds = nfds;
    ms->ms_timeout = timeout ? *timeout : OCALL_NO_TIMEOUT;
    ms->ms_fds = copy_outside_enclave(fds, nfds_bytes);

    if (!ms->ms_fds) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    retval = sgx_ocall(OCALL_POLL, ms);

    if (retval == -EINTR && timeout)
        *timeout = ms->ms_timeout;

    if (retval >= 0) {
        if (!copy_inside_enclave(fds, nfds_bytes, ms->ms_fds, nfds_bytes)) {
            cleanup();
            return -PAL_ERROR_DENIED;
        }
    }

    cleanup();
    return retval;
}

int ocall_rename (const char * oldpath, const char * newpath)
{
    int retval = 0;
    int oldlen = oldpath ? strlen(oldpath) + 1 : 0;
    int newlen = newpath ? strlen(newpath) + 1 : 0;
    ms_ocall_rename_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_oldpath = copy_outside_enclave(oldpath, oldlen);
    ms->ms_newpath = copy_outside_enclave(newpath, newlen);

    if (!ms->ms_oldpath || !ms->ms_newpath) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    retval = sgx_ocall(OCALL_RENAME, ms);

    cleanup();
    return retval;
}

int ocall_delete (const char * pathname)
{
    int retval = 0;
    int len = pathname ? strlen(pathname) + 1 : 0;
    ms_ocall_delete_t * ms;

    ms = alloc_ms_outside_enclave(sizeof(*ms));
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_pathname = copy_outside_enclave(pathname, len);
    if (!ms->ms_pathname) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    retval = sgx_ocall(OCALL_DELETE, ms);

    cleanup();
    return retval;
}

int ocall_load_debug(const char * command)
{
    int retval = 0;
    int len = strlen(command) + 1;

    const char * ms = copy_outside_enclave(command, len);
    if (!ms) {
        cleanup();
        return -PAL_ERROR_DENIED;
    }

    retval = sgx_ocall(OCALL_LOAD_DEBUG, (void *) ms);

    cleanup();
    return retval;
}
