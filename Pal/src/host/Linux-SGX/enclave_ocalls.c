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

int printf(const char * fmt, ...);

#define SGX_OCALL(code, ms) sgx_ocall(code, ms)

#define OCALL_CLEANUP()                                 \
    do {                                                \
        sgx_ocfree();                                   \
    } while (0)

/* OCALLOC sets ptr to NULL if there is no memory available on
 * untrusted stack of this thread. Similarly, ALLOC_OUTSIDE_ENCLAVE
 * and COPY_OUTSIDE_ENCLAVE return NULL. Users of these macros must
 * verify that memory was indeed allocated. */
#define OCALLOC(ptr, type, size) do {    \
    void * _tmp = sgx_ocalloc(size);     \
    (ptr) = (type) _tmp;                \
} while (0)

#define OCALLOC_MS(ms) OCALLOC(ms, __typeof__(ms), sizeof(*ms))

#define ALLOC_OUTSIDE_ENCLAVE(ptr, size)                         \
    ({                                                           \
        __typeof__(ptr) tmp = ptr;                               \
        if (!sgx_is_completely_outside_enclave(ptr, size)) {     \
            OCALLOC(tmp, __typeof__(tmp), size);                 \
        }; tmp;                                                  \
    })

#define COPY_OUTSIDE_ENCLAVE(ptr, size)                          \
    ({                                                           \
        __typeof__(ptr) tmp = ptr;                               \
        if (!sgx_is_completely_outside_enclave(ptr, size)) {     \
            OCALLOC(tmp, __typeof__(tmp), size);                 \
            memcpy((void *) tmp, ptr, size);                     \
        }; tmp;                                                  \
    })

/* First copy value from possibly untrusted uptr inside enclave (to
 * prevent TOCTOU). Then check that the region uptr points to (with
 * the given size) is completely in untrusted memory. If the check is
 * successful, ptr is set to checked value and true is returned.
 * Otherwise ptr is set to NULL and false is returned. */
#define COPY_PTR_INSIDE_ENCLAVE(ptr, uptr, size)                   \
    ({                                                             \
        bool _ret = false;                                         \
        *ptr = NULL;                                               \
        void* uptr_safe;                                           \
        memcpy(&uptr_safe, &uptr, sizeof(uptr_safe));              \
        if (sgx_is_completely_outside_enclave(uptr_safe, size)) {  \
            *ptr = uptr_safe;                                      \
            _ret = true;                                           \
        } _ret;                                                    \
    })

/* First copy value from possibly untrusted uptr and usize inside enclave
 * (to prevent TOCTOU). Then check that:
 *   - there is no buffer/integer overflow and
 *   - region (uptr, usize) is completely in untrusted memory and
 *   - if destination ptr isn't same as uptr, then region (putr, usize)
 *     is completely within enclave memory.
 * If the checks are successful, copy region of untrusted memory (uptr, usize)
 * inside enclave and return number of bytes copied. Otherwise return 0. */
#define COPY_INSIDE_ENCLAVE(ptr, uptr, maxsize, usize)                     \
    ({                                                                     \
        unsigned int _ret = 0;                                             \
        void* uptr_safe;                                                   \
        unsigned int usize_safe;                                           \
        memcpy(&uptr_safe,  &uptr,  sizeof(uptr_safe));                    \
        memcpy(&usize_safe, &usize, sizeof(usize_safe));                   \
        if (usize_safe <= maxsize &&                                       \
            sgx_is_completely_outside_enclave(uptr_safe, usize_safe)) {    \
            if (ptr != uptr_safe) {                                        \
                if (sgx_is_completely_within_enclave(ptr, usize_safe)) {   \
                    memcpy(ptr, uptr_safe, usize_safe);                    \
                    _ret = usize_safe;                                     \
                }                                                          \
            } else {                                                       \
                _ret = usize_safe;                                         \
            }                                                              \
        } _ret;                                                            \
    })

int ocall_exit(int exitcode)
{
    int64_t code = exitcode;
    // There are two reasons for this loop:
    //  1. Ocalls can be interuppted.
    //  2. We can't trust the outside to actually exit, so we need to ensure
    //     that we never return even when the outside tries to trick us.
    while (true) {
        SGX_OCALL(OCALL_EXIT, (void *) code);
    }
    return 0;
}

int ocall_print_string (const char * str, unsigned int length)
{
    int retval = 0;
    ms_ocall_print_string_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    if (!str || length <= 0) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_length = length;
    ms->ms_str = COPY_OUTSIDE_ENCLAVE(str, length);

    if (!ms->ms_str) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    retval = SGX_OCALL(OCALL_PRINT_STRING, ms);

    OCALL_CLEANUP();
    return retval;
}

int ocall_alloc_untrusted (uint64_t size, void ** mem)
{
    int retval = 0;
    ms_ocall_alloc_untrusted_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_size = size;

    retval = SGX_OCALL(OCALL_ALLOC_UNTRUSTED, ms);

    if (!retval) {
        if (!COPY_PTR_INSIDE_ENCLAVE(mem, ms->ms_mem, size)) {
            OCALL_CLEANUP();
            return -PAL_ERROR_DENIED;
        }
    }

    OCALL_CLEANUP();
    return retval;
}

int ocall_map_untrusted (int fd, uint64_t offset,
                         uint64_t size, unsigned short prot,
                         void ** mem)
{
    int retval = 0;
    ms_ocall_map_untrusted_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_fd = fd;
    ms->ms_offset = offset;
    ms->ms_size = size;
    ms->ms_prot = prot;

    retval = SGX_OCALL(OCALL_MAP_UNTRUSTED, ms);

    if (!retval) {
        if (!COPY_PTR_INSIDE_ENCLAVE(mem, ms->ms_mem, size)) {
            OCALL_CLEANUP();
            return -PAL_ERROR_DENIED;
        }
    }

    OCALL_CLEANUP();
    return retval;
}

int ocall_unmap_untrusted (const void * mem, uint64_t size)
{
    int retval = 0;
    ms_ocall_unmap_untrusted_t * ms;

    if (!sgx_is_completely_outside_enclave(mem, size)) {
        OCALL_CLEANUP();
        return -PAL_ERROR_INVAL;
    }

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_mem  = mem;
    ms->ms_size = size;

    retval = SGX_OCALL(OCALL_UNMAP_UNTRUSTED, ms);

    OCALL_CLEANUP();
    return retval;
}

int ocall_cpuid (unsigned int leaf, unsigned int subleaf,
                 unsigned int values[4])
{
    int retval = 0;
    ms_ocall_cpuid_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_leaf = leaf;
    ms->ms_subleaf = subleaf;

    retval = SGX_OCALL(OCALL_CPUID, ms);

    if (!retval) {
        values[0] = ms->ms_values[0];
        values[1] = ms->ms_values[1];
        values[2] = ms->ms_values[2];
        values[3] = ms->ms_values[3];
    }

    OCALL_CLEANUP();
    return retval;
}

int ocall_open (const char * pathname, int flags, unsigned short mode)
{
    int retval = 0;
    int len = pathname ? strlen(pathname) + 1 : 0;
    ms_ocall_open_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_flags = flags;
    ms->ms_mode = mode;
    ms->ms_pathname = COPY_OUTSIDE_ENCLAVE(pathname, len);

    if (!ms->ms_pathname) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    retval = SGX_OCALL(OCALL_OPEN, ms);

    OCALL_CLEANUP();
    return retval;
}

int ocall_close (int fd)
{
    int retval = 0;
    ms_ocall_close_t *ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_fd = fd;

    retval = SGX_OCALL(OCALL_CLOSE, ms);

    OCALL_CLEANUP();
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

    OCALLOC_MS(ms);
    if (!ms) {
        retval = -PAL_ERROR_DENIED;
        goto out;
    }

    ms->ms_fd = fd;
    ms->ms_count = count;
    if (obuf)
        ms->ms_buf = obuf;
    else
        ms->ms_buf = ALLOC_OUTSIDE_ENCLAVE(buf, count);

    if (!ms->ms_buf) {
        retval = -PAL_ERROR_DENIED;
        goto out;
    }

    retval = SGX_OCALL(OCALL_READ, ms);

    if (retval > 0) {
        if (!COPY_INSIDE_ENCLAVE(buf, ms->ms_buf, count, retval)) {
            retval = -PAL_ERROR_DENIED;
            goto out;
        }
    }

out:
    OCALL_CLEANUP();
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

    OCALLOC_MS(ms);
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
        ms->ms_buf = COPY_OUTSIDE_ENCLAVE(buf, count);
    }

    if (!ms->ms_buf) {
        retval = -PAL_ERROR_DENIED;
        goto out;
    }

    retval = SGX_OCALL(OCALL_WRITE, ms);

out:
    OCALL_CLEANUP();
    if (obuf)
        ocall_unmap_untrusted(obuf, ALLOC_ALIGNUP(count));
    return retval;
}

int ocall_fstat (int fd, struct stat * buf)
{
    int retval = 0;
    ms_ocall_fstat_t * ms;


    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_fd = fd;

    retval = SGX_OCALL(OCALL_FSTAT, ms);

    if (!retval)
        memcpy(buf, &ms->ms_stat, sizeof(struct stat));

    OCALL_CLEANUP();
    return retval;
}

int ocall_fionread (int fd)
{
    int retval = 0;
    ms_ocall_fionread_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_fd = fd;

    retval = SGX_OCALL(OCALL_FIONREAD, ms);

    OCALL_CLEANUP();
    return retval;
}

int ocall_fsetnonblock (int fd, int nonblocking)
{
    int retval = 0;
    ms_ocall_fsetnonblock_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_fd = fd;
    ms->ms_nonblocking = nonblocking;

    retval = SGX_OCALL(OCALL_FSETNONBLOCK, ms);

    OCALL_CLEANUP();
    return retval;
}

int ocall_fchmod (int fd, unsigned short mode)
{
    int retval = 0;
    ms_ocall_fchmod_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_fd = fd;
    ms->ms_mode = mode;

    retval = SGX_OCALL(OCALL_FCHMOD, ms);

    OCALL_CLEANUP();
    return retval;
}

int ocall_fsync (int fd)
{
    int retval = 0;
    ms_ocall_fsync_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_fd = fd;

    retval = SGX_OCALL(OCALL_FSYNC, ms);

    OCALL_CLEANUP();
    return retval;
}

int ocall_ftruncate (int fd, uint64_t length)
{
    int retval = 0;
    ms_ocall_ftruncate_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_fd = fd;
    ms->ms_length = length;

    retval = SGX_OCALL(OCALL_FTRUNCATE, ms);

    OCALL_CLEANUP();
    return retval;
}

int ocall_mkdir (const char * pathname, unsigned short mode)
{
    int retval = 0;
    int len = pathname ? strlen(pathname) + 1 : 0;
    ms_ocall_mkdir_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_mode = mode;
    ms->ms_pathname = COPY_OUTSIDE_ENCLAVE(pathname, len);

    if (!ms->ms_pathname) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    retval = SGX_OCALL(OCALL_MKDIR, ms);

    OCALL_CLEANUP();
    return retval;
}

int ocall_getdents (int fd, struct linux_dirent64 * dirp, unsigned int size)
{
    int retval = 0;
    ms_ocall_getdents_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_fd = fd;
    ms->ms_size = size;
    ms->ms_dirp = ALLOC_OUTSIDE_ENCLAVE(dirp, size);

    if (!ms->ms_dirp) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    retval = SGX_OCALL(OCALL_GETDENTS, ms);

    if (retval > 0) {
        if (!COPY_INSIDE_ENCLAVE(dirp, ms->ms_dirp, size, retval)) {
            OCALL_CLEANUP();
            return -PAL_ERROR_DENIED;
        }
    }

    OCALL_CLEANUP();
    return retval;
}

int ocall_wake_thread (void * tcs)
{
    return SGX_OCALL(OCALL_WAKE_THREAD, tcs);
}

int ocall_create_process (const char * uri,
                          int nargs, const char ** args,
                          int procfds[3],
                          unsigned int * pid)
{
    int retval = 0;
    int ulen = uri ? strlen(uri) + 1 : 0;
    ms_ocall_create_process_t * ms;

    OCALLOC(ms, ms_ocall_create_process_t *,
            sizeof(*ms) + sizeof(const char *) * nargs);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_uri = uri ? COPY_OUTSIDE_ENCLAVE(uri, ulen) : NULL;
    if (uri && !ms->ms_uri) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_nargs = nargs;
    for (int i = 0 ; i < nargs ; i++) {
        int len = args[i] ? strlen(args[i]) + 1 : 0;
        ms->ms_args[i] = args[i] ? COPY_OUTSIDE_ENCLAVE(args[i], len) : NULL;

        if (args[i] && !ms->ms_args[i]) {
            OCALL_CLEANUP();
            return -PAL_ERROR_DENIED;
        }
    }

    retval = SGX_OCALL(OCALL_CREATE_PROCESS, ms);

    if (!retval) {
        if (pid)
            *pid = ms->ms_pid;
        procfds[0] = ms->ms_proc_fds[0];
        procfds[1] = ms->ms_proc_fds[1];
        procfds[2] = ms->ms_proc_fds[2];
    }

    OCALL_CLEANUP();
    return retval;
}

int ocall_futex (int * futex, int op, int val,
                 const uint64_t * timeout)
{
    int retval = 0;
    ms_ocall_futex_t * ms;

    if (!sgx_is_completely_outside_enclave(futex, sizeof(int))) {
        OCALL_CLEANUP();
        return -PAL_ERROR_INVAL;
    }

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_futex = futex;
    ms->ms_op = op;
    ms->ms_val = val;
    ms->ms_timeout = timeout ? *timeout : OCALL_NO_TIMEOUT;

    retval = SGX_OCALL(OCALL_FUTEX, ms);

    OCALL_CLEANUP();
    return retval;
}

int ocall_socketpair (int domain, int type, int protocol,
                      int sockfds[2])
{
    int retval = 0;
    ms_ocall_socketpair_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_domain = domain;
    ms->ms_type = type;
    ms->ms_protocol = protocol;

    retval = SGX_OCALL(OCALL_SOCKETPAIR, ms);

    if (!retval) {
        sockfds[0] = ms->ms_sockfds[0];
        sockfds[1] = ms->ms_sockfds[1];
    }

    OCALL_CLEANUP();
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

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_domain = domain;
    ms->ms_type = type;
    ms->ms_protocol = protocol;
    ms->ms_addrlen = len;
    ms->ms_addr = (addr && len) ? COPY_OUTSIDE_ENCLAVE(addr, len) : NULL;

    if (addr && len && !ms->ms_addr) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    retval = SGX_OCALL(OCALL_SOCK_LISTEN, ms);

    if (retval >= 0) {
        if (addr && len) {
            copied = COPY_INSIDE_ENCLAVE(addr, ms->ms_addr, len, ms->ms_addrlen);
            if (!copied) {
                OCALL_CLEANUP();
                return -PAL_ERROR_DENIED;
            }
            *addrlen = copied;
        }

        if (sockopt) {
            *sockopt = ms->ms_sockopt;
        }
    }

    OCALL_CLEANUP();
    return retval;
}

int ocall_sock_accept (int sockfd, struct sockaddr * addr,
                       unsigned int * addrlen, struct sockopt * sockopt)
{
    int retval = 0;
    unsigned int copied;
    unsigned int len = addrlen ? *addrlen : 0;
    ms_ocall_sock_accept_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_addrlen = len;
    ms->ms_addr = (addr && len) ? COPY_OUTSIDE_ENCLAVE(addr, len) : NULL;

    if (addr && len && !ms->ms_addr) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    retval = SGX_OCALL(OCALL_SOCK_ACCEPT, ms);

    if (retval >= 0) {
        if (addr && len) {
            copied = COPY_INSIDE_ENCLAVE(addr, ms->ms_addr, len, ms->ms_addrlen);
            if (!copied) {
                OCALL_CLEANUP();
                return -PAL_ERROR_DENIED;
            }
            *addrlen = copied;
        }

        if (sockopt) {
            *sockopt = ms->ms_sockopt;
        }
    }

    OCALL_CLEANUP();
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

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_domain = domain;
    ms->ms_type = type;
    ms->ms_protocol = protocol;
    ms->ms_addrlen = addrlen;
    ms->ms_bind_addrlen = bind_len;
    ms->ms_addr = addr ? COPY_OUTSIDE_ENCLAVE(addr, addrlen) : NULL;
    ms->ms_bind_addr = bind_addr ? COPY_OUTSIDE_ENCLAVE(bind_addr, bind_len) : NULL;

    if ((addr && !ms->ms_addr) || (bind_addr && !ms->ms_bind_addr)) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    retval = SGX_OCALL(OCALL_SOCK_CONNECT, ms);

    if (retval >= 0) {
        if (bind_addr && bind_len) {
            copied = COPY_INSIDE_ENCLAVE(bind_addr, ms->ms_bind_addr, bind_len, ms->ms_bind_addrlen);
            if (!copied) {
                OCALL_CLEANUP();
                return -PAL_ERROR_DENIED;
            }
            *bind_addrlen = copied;
        }

        if (sockopt) {
            *sockopt = ms->ms_sockopt;
        }
    }

    OCALL_CLEANUP();
    return retval;
}

int ocall_sock_recv (int sockfd, void * buf, unsigned int count,
                     struct sockaddr * addr, unsigned int * addrlen)
{
    int retval = 0;
    unsigned int copied;
    unsigned int len = addrlen ? *addrlen : 0;
    ms_ocall_sock_recv_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_count = count;
    ms->ms_addrlen = len;
    ms->ms_buf = ALLOC_OUTSIDE_ENCLAVE(buf, count);
    ms->ms_addr = addr ? ALLOC_OUTSIDE_ENCLAVE(addr, len) : NULL;

    if (!ms->ms_buf || (addr && !ms->ms_addr)) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    retval = SGX_OCALL(OCALL_SOCK_RECV, ms);

    if (retval >= 0) {
        if (addr && len) {
            copied = COPY_INSIDE_ENCLAVE(addr, ms->ms_addr, len, ms->ms_addrlen);
            if (!copied) {
                OCALL_CLEANUP();
                return -PAL_ERROR_DENIED;
            }
            *addrlen = copied;
        }

        if (!COPY_INSIDE_ENCLAVE(buf, ms->ms_buf, count, retval)) {
            OCALL_CLEANUP();
            return -PAL_ERROR_DENIED;
        }
    }

    OCALL_CLEANUP();
    return retval;
}

int ocall_sock_send (int sockfd, const void * buf, unsigned int count,
                     const struct sockaddr * addr, unsigned int addrlen)
{
    int retval = 0;
    ms_ocall_sock_send_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_count = count;
    ms->ms_addrlen = addrlen;
    ms->ms_buf = COPY_OUTSIDE_ENCLAVE(buf, count);
    ms->ms_addr = addr ? COPY_OUTSIDE_ENCLAVE(addr, addrlen) : NULL;

    if (!ms->ms_buf || (addr && !ms->ms_addr)) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    retval = SGX_OCALL(OCALL_SOCK_SEND, ms);

    OCALL_CLEANUP();
    return retval;
}

int ocall_sock_recv_fd (int sockfd, void * buf, unsigned int count,
                        unsigned int * fds, unsigned int * nfds)
{
    int retval = 0;
    unsigned int copied;
    ms_ocall_sock_recv_fd_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_count = count;
    ms->ms_nfds = *nfds;
    ms->ms_buf = ALLOC_OUTSIDE_ENCLAVE(buf, count);
    ms->ms_fds = ALLOC_OUTSIDE_ENCLAVE(fds, (*nfds) * sizeof(int));

    if (!ms->ms_buf || !ms->ms_fds) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    retval = SGX_OCALL(OCALL_SOCK_RECV_FD, ms);

    if (retval >= 0) {
        unsigned int ms_nfds_bytes  = ms->ms_nfds * sizeof(int);
        unsigned int max_nfds_bytes = (*nfds) * sizeof(int);
        copied = COPY_INSIDE_ENCLAVE(fds, ms->ms_fds, max_nfds_bytes, ms_nfds_bytes);
        if (!copied) {
            OCALL_CLEANUP();
            return -PAL_ERROR_DENIED;
        }
        *nfds = copied / sizeof(int);

        if (!COPY_INSIDE_ENCLAVE(buf, ms->ms_buf, count, retval)) {
            OCALL_CLEANUP();
            return -PAL_ERROR_DENIED;
        }
    }

    OCALL_CLEANUP();
    return retval;
}

int ocall_sock_send_fd (int sockfd, const void * buf, unsigned int count,
                        const unsigned int * fds, unsigned int nfds)
{
    int retval = 0;
    ms_ocall_sock_send_fd_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_count = count;
    ms->ms_nfds = nfds;
    ms->ms_buf = COPY_OUTSIDE_ENCLAVE(buf, count);
    ms->ms_fds = COPY_OUTSIDE_ENCLAVE(fds, nfds * sizeof(int));

    if (!ms->ms_buf || !ms->ms_fds) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    retval = SGX_OCALL(OCALL_SOCK_SEND_FD, ms);

    OCALL_CLEANUP();
    return retval;
}

int ocall_sock_setopt (int sockfd, int level, int optname,
                       const void * optval, unsigned int optlen)
{
    int retval = 0;
    ms_ocall_sock_setopt_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_level = level;
    ms->ms_optname = optname;
    ms->ms_optlen = optlen;
    ms->ms_optval = COPY_OUTSIDE_ENCLAVE(optval, optlen);

    if (!ms->ms_optval) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    retval = SGX_OCALL(OCALL_SOCK_SETOPT, ms);

    OCALL_CLEANUP();
    return retval;
}

int ocall_sock_shutdown (int sockfd, int how)
{
    int retval = 0;
    ms_ocall_sock_shutdown_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_how = how;

    retval = SGX_OCALL(OCALL_SOCK_SHUTDOWN, ms);

    OCALL_CLEANUP();
    return retval;
}

int ocall_gettime (unsigned long * microsec)
{
    int retval = 0;
    ms_ocall_gettime_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    retval = SGX_OCALL(OCALL_GETTIME, ms);
    if (!retval)
        *microsec = ms->ms_microsec;

    OCALL_CLEANUP();
    return retval;
}

int ocall_sleep (unsigned long * microsec)
{
    int retval = 0;
    ms_ocall_sleep_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_microsec = microsec ? *microsec : 0;

    retval = SGX_OCALL(OCALL_SLEEP, ms);
    if (microsec) {
        if (!retval)
            *microsec = 0;
        else if (retval == -EINTR)
            *microsec = ms->ms_microsec;
    }

    OCALL_CLEANUP();
    return retval;
}

int ocall_poll (struct pollfd * fds, int nfds, uint64_t * timeout)
{
    int retval = 0;
    ms_ocall_poll_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_nfds = nfds;
    ms->ms_timeout = timeout ? *timeout : OCALL_NO_TIMEOUT;
    ms->ms_fds = COPY_OUTSIDE_ENCLAVE(fds, sizeof(struct pollfd) * nfds);

    if (!ms->ms_fds) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    retval = SGX_OCALL(OCALL_POLL, ms);

    if (retval == -EINTR && timeout)
        *timeout = ms->ms_timeout;

    if (retval >= 0) {
        unsigned int nfds_bytes = sizeof(struct pollfd) * nfds;
        if (!COPY_INSIDE_ENCLAVE(fds, ms->ms_fds, nfds_bytes, nfds_bytes)) {
            OCALL_CLEANUP();
            return -PAL_ERROR_DENIED;
        }
    }

    OCALL_CLEANUP();
    return retval;
}

int ocall_rename (const char * oldpath, const char * newpath)
{
    int retval = 0;
    int oldlen = oldpath ? strlen(oldpath) + 1 : 0;
    int newlen = newpath ? strlen(newpath) + 1 : 0;
    ms_ocall_rename_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_oldpath = COPY_OUTSIDE_ENCLAVE(oldpath, oldlen);
    ms->ms_newpath = COPY_OUTSIDE_ENCLAVE(newpath, newlen);

    if (!ms->ms_oldpath || !ms->ms_newpath) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    retval = SGX_OCALL(OCALL_RENAME, ms);

    OCALL_CLEANUP();
    return retval;
}

int ocall_delete (const char * pathname)
{
    int retval = 0;
    int len = pathname ? strlen(pathname) + 1 : 0;
    ms_ocall_delete_t * ms;

    OCALLOC_MS(ms);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_pathname = COPY_OUTSIDE_ENCLAVE(pathname, len);
    if (!ms->ms_pathname) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    retval = SGX_OCALL(OCALL_DELETE, ms);

    OCALL_CLEANUP();
    return retval;
}

int ocall_load_debug(const char * command)
{
    int retval = 0;
    int len = strlen(command) + 1;

    const char * ms = COPY_OUTSIDE_ENCLAVE(command, len);
    if (!ms) {
        OCALL_CLEANUP();
        return -PAL_ERROR_DENIED;
    }

    retval = SGX_OCALL(OCALL_LOAD_DEBUG, (void *) ms);

    OCALL_CLEANUP();
    return retval;
}
