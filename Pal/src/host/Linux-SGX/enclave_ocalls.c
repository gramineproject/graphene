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

#define OCALLOC(val, type, len) do {    \
    void * _tmp = sgx_ocalloc(len);     \
    if (_tmp == NULL) {                 \
        OCALL_EXIT();                   \
        return -PAL_ERROR_DENIED;  /* TODO: remove this control-flow obfuscation */  \
    }                                   \
    (val) = (type) _tmp;                \
} while (0)

int printf(const char * fmt, ...);

#define SGX_OCALL(code, ms) sgx_ocall(code, ms)

#define OCALL_EXIT()                                    \
    do {                                                \
        sgx_ocfree();                                   \
    } while (0)

#define ALLOC_IN_USER(ptr, size)                    \
    ({                                              \
        typeof(ptr) tmp = ptr;                      \
        if (sgx_is_within_enclave(ptr, size)) {     \
            OCALLOC(tmp, typeof(tmp), size);        \
        }; tmp;                                     \
    })

#define COPY_TO_USER(ptr, size)                     \
    ({                                              \
        typeof(ptr) tmp = ptr;                      \
        if (sgx_is_within_enclave(ptr, size)) {     \
            OCALLOC(tmp, typeof(tmp), size);        \
            memcpy((void *) tmp, ptr, size);        \
        }; tmp;                                     \
    })

#define COPY_FROM_USER(var, user_var, size)                 \
    ({                                                      \
        int _ret = 0;                                       \
        if (var != user_var) {                              \
            if (sgx_is_within_enclave(user_var, size) ||    \
                !sgx_is_within_enclave(var, size)) {        \
                _ret = -PAL_ERROR_DENIED;                   \
            } else {                                        \
                _ret = 0;                                   \
                memcpy(var, user_var, size);                \
            }                                               \
        } _ret;                                             \
    })

int ocall_exit(int exitcode)
{
    int retval = 0;
    int64_t code = exitcode;
    SGX_OCALL(OCALL_EXIT, (void *) code);
    /* never reach here */
    return retval;
}

int ocall_print_string (const char * str, unsigned int length)
{
    int retval = 0;
    ms_ocall_print_string_t * ms;
    OCALLOC(ms, ms_ocall_print_string_t *, sizeof(*ms));

    if (!str || length <= 0) {
        OCALL_EXIT();
        return -PAL_ERROR_DENIED;
    }

    ms->ms_str = COPY_TO_USER(str, length);
    ms->ms_length = length;

    retval = SGX_OCALL(OCALL_PRINT_STRING, ms);
    OCALL_EXIT();
    return retval;
}

int ocall_alloc_untrusted (uint64_t size, void ** mem)
{
    int retval = 0;
    ms_ocall_alloc_untrusted_t * ms;

    OCALLOC(ms, ms_ocall_alloc_untrusted_t *, sizeof(*ms));

    ms->ms_size = size;

    retval = SGX_OCALL(OCALL_ALLOC_UNTRUSTED, ms);
    if (!retval) {
        if (sgx_is_within_enclave(ms->ms_mem, size)) {
            OCALL_EXIT();
            return -PAL_ERROR_DENIED;
        }
        *mem = ms->ms_mem;
    }
    OCALL_EXIT();
    return retval;
}

int ocall_map_untrusted (int fd, uint64_t offset,
                         uint64_t size, unsigned short prot,
                         void ** mem)
{
    int retval = 0;
    ms_ocall_map_untrusted_t * ms;

    OCALLOC(ms, ms_ocall_map_untrusted_t *, sizeof(*ms));

    ms->ms_fd = fd;
    ms->ms_offset = offset;
    ms->ms_size = size;
    ms->ms_prot = prot;

    retval = SGX_OCALL(OCALL_MAP_UNTRUSTED, ms);
    if (!retval) {
        if (sgx_is_within_enclave(ms->ms_mem, size)) {
            OCALL_EXIT();
            return -PAL_ERROR_DENIED;
        }
        *mem = ms->ms_mem;
    }
    OCALL_EXIT();
    return retval;
}

int ocall_unmap_untrusted (const void * mem, uint64_t size)
{
    int retval = 0;

    if (sgx_is_within_enclave(mem, size)) {
        OCALL_EXIT();
        return -PAL_ERROR_INVAL;
    }

    ms_ocall_unmap_untrusted_t * ms;
    OCALLOC(ms, ms_ocall_unmap_untrusted_t *, sizeof(*ms));

    ms->ms_mem  = mem;
    ms->ms_size = size;

    retval = SGX_OCALL(OCALL_UNMAP_UNTRUSTED, ms);
    OCALL_EXIT();
    return retval;
}

int ocall_cpuid (unsigned int leaf, unsigned int subleaf,
                 unsigned int values[4])
{
    int retval = 0;
    ms_ocall_cpuid_t * ms;
    OCALLOC(ms, ms_ocall_cpuid_t *, sizeof(*ms));

    ms->ms_leaf = leaf;
    ms->ms_subleaf = subleaf;

    retval = SGX_OCALL(OCALL_CPUID, ms);
    if (!retval) {
        values[0] = ms->ms_values[0];
        values[1] = ms->ms_values[1];
        values[2] = ms->ms_values[2];
        values[3] = ms->ms_values[3];
    }

    OCALL_EXIT();
    return retval;
}

int ocall_open (const char * pathname, int flags, unsigned short mode)
{
    int retval = 0;
    int len = pathname ? strlen(pathname) + 1 : 0;
    ms_ocall_open_t * ms;
    OCALLOC(ms, ms_ocall_open_t *, sizeof(*ms));

    ms->ms_pathname = COPY_TO_USER(pathname, len);
    ms->ms_flags = flags;
    ms->ms_mode = mode;

    retval = SGX_OCALL(OCALL_OPEN, ms);
    OCALL_EXIT();
    return retval;
}

int ocall_close (int fd)
{
    int retval = 0;
    ms_ocall_close_t *ms;
    OCALLOC(ms, ms_ocall_close_t *, sizeof(*ms));

    ms->ms_fd = fd;

    retval = SGX_OCALL(OCALL_CLOSE, ms);
    OCALL_EXIT();
    return retval;
}

int ocall_read (int fd, void * buf, unsigned int count)
{
    int retval = 0;
    void * obuf = NULL;

    if (count > 4096) {
        retval = ocall_alloc_untrusted(ALLOC_ALIGNUP(count), &obuf);
        if (retval < 0)
            return retval;
    }

    ms_ocall_read_t * ms;
    OCALLOC(ms, ms_ocall_read_t *, sizeof(*ms));

    ms->ms_fd = fd;
    if (obuf)
        ms->ms_buf = obuf;
    else
        OCALLOC(ms->ms_buf, void *, count);
    ms->ms_count = count;

    retval = SGX_OCALL(OCALL_READ, ms);

    if (retval > 0)
        memcpy(buf, ms->ms_buf, retval);
    OCALL_EXIT();

    if (obuf)
        ocall_unmap_untrusted(obuf, ALLOC_ALIGNUP(count));

    return retval;
}

int ocall_write (int fd, const void * buf, unsigned int count)
{
    int retval = 0;
    void * obuf = NULL;

    if (count > 4096) {
        retval = ocall_alloc_untrusted(ALLOC_ALIGNUP(count), &obuf);
        if (retval < 0)
            return retval;
    }

    ms_ocall_write_t * ms;
    OCALLOC(ms, ms_ocall_write_t *, sizeof(*ms));

    ms->ms_fd = fd;
    if (obuf) {
        ms->ms_buf = obuf;
        memcpy(obuf, buf, count);
    } else {
        ms->ms_buf = COPY_TO_USER(buf, count);
    }
    ms->ms_count = count;

    retval = SGX_OCALL(OCALL_WRITE, ms);
    OCALL_EXIT();

    if (obuf)
        ocall_unmap_untrusted(obuf, ALLOC_ALIGNUP(count));

    return retval;
}

int ocall_fstat (int fd, struct stat * buf)
{
    int retval = 0;
    ms_ocall_fstat_t * ms;
    OCALLOC(ms, ms_ocall_fstat_t *, sizeof(*ms));

    ms->ms_fd = fd;

    retval = SGX_OCALL(OCALL_FSTAT, ms);
    if (!retval)
        memcpy(buf, &ms->ms_stat, sizeof(struct stat));
    OCALL_EXIT();
    return retval;
}

int ocall_fionread (int fd)
{
    int retval = 0;
    ms_ocall_fionread_t * ms;
    OCALLOC(ms, ms_ocall_fionread_t *, sizeof(*ms));

    ms->ms_fd = fd;

    retval = SGX_OCALL(OCALL_FIONREAD, ms);
    OCALL_EXIT();
    return retval;
}

int ocall_fsetnonblock (int fd, int nonblocking)
{
    int retval = 0;
    ms_ocall_fsetnonblock_t * ms;
    OCALLOC(ms, ms_ocall_fsetnonblock_t *, sizeof(*ms));

    ms->ms_fd = fd;
    ms->ms_nonblocking = nonblocking;

    retval = SGX_OCALL(OCALL_FSETNONBLOCK, ms);
    OCALL_EXIT();
    return retval;
}

int ocall_fchmod (int fd, unsigned short mode)
{
    int retval = 0;
    ms_ocall_fchmod_t * ms;
    OCALLOC(ms, ms_ocall_fchmod_t *, sizeof(*ms));

    ms->ms_fd = fd;
    ms->ms_mode = mode;

    retval = SGX_OCALL(OCALL_FCHMOD, ms);
    OCALL_EXIT();
    return retval;
}

int ocall_fsync (int fd)
{
    int retval = 0;
    ms_ocall_fsync_t * ms;
    OCALLOC(ms, ms_ocall_fsync_t *, sizeof(*ms));

    ms->ms_fd = fd;

    retval = SGX_OCALL(OCALL_FSYNC, ms);
    OCALL_EXIT();
    return retval;
}

int ocall_ftruncate (int fd, uint64_t length)
{
    int retval = 0;
    ms_ocall_ftruncate_t * ms;
    OCALLOC(ms, ms_ocall_ftruncate_t *, sizeof(*ms));

    ms->ms_fd = fd;
    ms->ms_length = length;

    retval = SGX_OCALL(OCALL_FTRUNCATE, ms);
    OCALL_EXIT();
    return retval;
}

int ocall_mkdir (const char * pathname, unsigned short mode)
{
    int retval = 0;
    int len = pathname ? strlen(pathname) + 1 : 0;
    ms_ocall_mkdir_t * ms;
    OCALLOC(ms, ms_ocall_mkdir_t *, sizeof(*ms));

    ms->ms_pathname = COPY_TO_USER(pathname, len);
    ms->ms_mode = mode;

    retval = SGX_OCALL(OCALL_MKDIR, ms);
    OCALL_EXIT();
    return retval;
}

int ocall_getdents (int fd, struct linux_dirent64 * dirp, unsigned int size)
{
    int retval = 0;
    ms_ocall_getdents_t * ms;
    OCALLOC(ms, ms_ocall_getdents_t *, sizeof(*ms));

    ms->ms_fd = fd;
    ms->ms_dirp = ALLOC_IN_USER(dirp, size);
    ms->ms_size = size;

    retval = SGX_OCALL(OCALL_GETDENTS, ms);
    if (retval > 0)
        COPY_FROM_USER(dirp, ms->ms_dirp, retval);
    OCALL_EXIT();
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

    ms->ms_uri = uri ? COPY_TO_USER(uri, ulen) : NULL;
    ms->ms_nargs = nargs;
    for (int i = 0 ; i < nargs ; i++) {
        int len = args[i] ? strlen(args[i]) + 1 : 0;
        ms->ms_args[i] = args[i] ? COPY_TO_USER(args[i], len) : NULL;
    }

    retval = SGX_OCALL(OCALL_CREATE_PROCESS, ms);
    if (!retval) {
        if (pid)
            *pid = ms->ms_pid;
        procfds[0] = ms->ms_proc_fds[0];
        procfds[1] = ms->ms_proc_fds[1];
        procfds[2] = ms->ms_proc_fds[2];
    }
    OCALL_EXIT();
    return retval;
}

int ocall_futex (int * futex, int op, int val,
                 const uint64_t * timeout)
{
    int retval = 0;
    ms_ocall_futex_t * ms;
    OCALLOC(ms, ms_ocall_futex_t *, sizeof(*ms));

    if (sgx_is_within_enclave(futex, sizeof(int))) {
        OCALL_EXIT();
        return -PAL_ERROR_INVAL;
    }

    ms->ms_futex = futex;
    ms->ms_op = op;
    ms->ms_val = val;
    ms->ms_timeout = timeout ? *timeout : OCALL_NO_TIMEOUT;

    retval = SGX_OCALL(OCALL_FUTEX, ms);
    OCALL_EXIT();
    return retval;
}

int ocall_socketpair (int domain, int type, int protocol,
                      int sockfds[2])
{
    int retval = 0;
    ms_ocall_socketpair_t * ms;
    OCALLOC(ms, ms_ocall_socketpair_t *, sizeof(*ms));

    ms->ms_domain = domain;
    ms->ms_type = type;
    ms->ms_protocol = protocol;

    retval = SGX_OCALL(OCALL_SOCKETPAIR, ms);
    if (!retval) {
        sockfds[0] = ms->ms_sockfds[0];
        sockfds[1] = ms->ms_sockfds[1];
    }
    OCALL_EXIT();
    return retval;
}

int ocall_sock_listen (int domain, int type, int protocol,
                       struct sockaddr * addr, unsigned int * addrlen,
                       struct sockopt * sockopt)
{
    int retval = 0;
    unsigned int bind_len = *addrlen;
    ms_ocall_sock_listen_t * ms;
    OCALLOC(ms, ms_ocall_sock_listen_t *, sizeof(*ms));

    ms->ms_domain = domain;
    ms->ms_type = type;
    ms->ms_protocol = protocol;
    ms->ms_addr = COPY_TO_USER(addr, bind_len);
    ms->ms_addrlen = bind_len;

    retval = SGX_OCALL(OCALL_SOCK_LISTEN, ms);
    if (retval >= 0) {
        if (addrlen && (
            sgx_is_within_enclave(ms->ms_addr, bind_len) ||
            ms->ms_addrlen > bind_len)) {
            OCALL_EXIT();
            return -PAL_ERROR_DENIED;
        }

        if (addr) {
            COPY_FROM_USER(addr, ms->ms_addr, ms->ms_addrlen);
            *addrlen = ms->ms_addrlen;
        }
        if (sockopt)
            *sockopt = ms->ms_sockopt;
    }
    OCALL_EXIT();
    return retval;
}

int ocall_sock_accept (int sockfd, struct sockaddr * addr,
                       unsigned int * addrlen, struct sockopt * sockopt)
{
    int retval = 0;
    unsigned int len = addrlen ? *addrlen : 0;
    ms_ocall_sock_accept_t * ms;
    OCALLOC(ms, ms_ocall_sock_accept_t *, sizeof(*ms));

    ms->ms_sockfd = sockfd;
    ms->ms_addr = COPY_TO_USER(addr, len);
    ms->ms_addrlen = len;

    retval = SGX_OCALL(OCALL_SOCK_ACCEPT, ms);
    if (retval >= 0) {
        if (len && (sgx_is_within_enclave(ms->ms_addr, len) ||
                    ms->ms_addrlen > len)) {
            OCALL_EXIT();
            return -PAL_ERROR_DENIED;
        }

        if (addr) {
            COPY_FROM_USER(addr, ms->ms_addr, ms->ms_addrlen);
            *addrlen = ms->ms_addrlen;
        }
        if (sockopt)
            *sockopt = ms->ms_sockopt;
    }
    OCALL_EXIT();
    return retval;
}

int ocall_sock_connect (int domain, int type, int protocol,
                        const struct sockaddr * addr,
                        unsigned int addrlen,
                        struct sockaddr * bind_addr,
                        unsigned int * bind_addrlen, struct sockopt * sockopt)
{
    int retval = 0;
    unsigned int bind_len = bind_addrlen ? *bind_addrlen : 0;
    ms_ocall_sock_connect_t * ms;
    OCALLOC(ms, ms_ocall_sock_connect_t *, sizeof(*ms));

    ms->ms_domain = domain;
    ms->ms_type = type;
    ms->ms_protocol = protocol;
    ms->ms_addr = COPY_TO_USER(addr, addrlen);
    ms->ms_addrlen = addrlen;
    ms->ms_bind_addr = bind_addr ? COPY_TO_USER(bind_addr, bind_len) : NULL;
    ms->ms_bind_addrlen = bind_len;

    retval = SGX_OCALL(OCALL_SOCK_CONNECT, ms);
    if (retval >= 0) {
        if (bind_len && (
            sgx_is_within_enclave(ms->ms_bind_addr, bind_len) ||
            ms->ms_bind_addrlen > bind_len)) {
            OCALL_EXIT();
            return -PAL_ERROR_DENIED;
        }

        if (bind_addr) {
            COPY_FROM_USER(bind_addr, ms->ms_bind_addr,
                           ms->ms_bind_addrlen);
            *bind_addrlen = ms->ms_bind_addrlen;
        }
        if (sockopt)
            *sockopt = ms->ms_sockopt;
    }
    OCALL_EXIT();
    return retval;
}

int ocall_sock_recv (int sockfd, void * buf, unsigned int count,
                     struct sockaddr * addr, unsigned int * addrlen)
{
    int retval = 0;
    unsigned int len = addrlen ? *addrlen : 0;
    ms_ocall_sock_recv_t * ms;
    OCALLOC(ms, ms_ocall_sock_recv_t *, sizeof(*ms));

    ms->ms_sockfd = sockfd;
    ms->ms_buf = ALLOC_IN_USER(buf, count);
    ms->ms_count = count;
    ms->ms_addr = addr ? ALLOC_IN_USER(addr, len) : NULL;
    ms->ms_addrlen = len;

    retval = SGX_OCALL(OCALL_SOCK_RECV, ms);
    if (retval >= 0) {
        if (len && (sgx_is_within_enclave(ms->ms_addr, len) ||
                    ms->ms_addrlen > len)) {
            OCALL_EXIT();
            return -PAL_ERROR_DENIED;
        }

        COPY_FROM_USER(buf, ms->ms_buf, retval);
        COPY_FROM_USER(addr, ms->ms_addr, ms->ms_addrlen);
        if (addrlen)
            *addrlen = ms->ms_addrlen;
    }
    OCALL_EXIT();
    return retval;
}

int ocall_sock_send (int sockfd, const void * buf, unsigned int count,
                     const struct sockaddr * addr, unsigned int addrlen)
{
    int retval = 0;
    ms_ocall_sock_send_t * ms;
    OCALLOC(ms, ms_ocall_sock_send_t *, sizeof(*ms));

    ms->ms_sockfd = sockfd;
    ms->ms_buf = COPY_TO_USER(buf, count);
    ms->ms_count = count;
    ms->ms_addr = addr ? COPY_TO_USER(addr, addrlen) : NULL;
    ms->ms_addrlen = addrlen;

    retval = SGX_OCALL(OCALL_SOCK_SEND, ms);
    OCALL_EXIT();
    return retval;
}

int ocall_sock_recv_fd (int sockfd, void * buf, unsigned int count,
                        unsigned int * fds, unsigned int * nfds)
{
    int retval = 0;
    ms_ocall_sock_recv_fd_t * ms;
    OCALLOC(ms, ms_ocall_sock_recv_fd_t *, sizeof(*ms));

    ms->ms_sockfd = sockfd;
    ms->ms_buf = ALLOC_IN_USER(buf, count);
    ms->ms_count = count;
    ms->ms_fds = fds ? ALLOC_IN_USER(fds, sizeof(int) * (*nfds)) : NULL;
    ms->ms_nfds = *nfds;

    retval = SGX_OCALL(OCALL_SOCK_RECV_FD, ms);
    if (retval >= 0) {
        if (sgx_is_within_enclave(ms->ms_fds, sizeof(int) * (*nfds)) ||
            ms->ms_nfds > (*nfds)) {
            OCALL_EXIT();
            return -PAL_ERROR_DENIED;
        }

        COPY_FROM_USER(buf, ms->ms_buf, retval);
        COPY_FROM_USER(fds, ms->ms_fds, sizeof(int) * ms->ms_nfds);
        *nfds = ms->ms_nfds;
    }
    OCALL_EXIT();
    return retval;
}

int ocall_sock_send_fd (int sockfd, const void * buf, unsigned int count,
                        const unsigned int * fds, unsigned int nfds)
{
    int retval = 0;
    ms_ocall_sock_send_fd_t * ms;
    OCALLOC(ms, ms_ocall_sock_send_fd_t *, sizeof(*ms));

    ms->ms_sockfd = sockfd;
    ms->ms_buf = COPY_TO_USER(buf, count);
    ms->ms_count = count;
    ms->ms_fds = fds ? COPY_TO_USER(fds, sizeof(int) * nfds) : NULL;
    ms->ms_nfds = nfds;

    retval = SGX_OCALL(OCALL_SOCK_SEND_FD, ms);
    OCALL_EXIT();
    return retval;
}

int ocall_sock_setopt (int sockfd, int level, int optname,
                       const void * optval, unsigned int optlen)
{
    int retval = 0;
    ms_ocall_sock_setopt_t * ms;
    OCALLOC(ms, ms_ocall_sock_setopt_t *, sizeof(*ms));

    ms->ms_sockfd = sockfd;
    ms->ms_level = level;
    ms->ms_optname = optname;
    ms->ms_optval = COPY_TO_USER(optval, optlen);
    ms->ms_optlen = optlen;

    retval = SGX_OCALL(OCALL_SOCK_SETOPT, ms);
    OCALL_EXIT();
    return retval;
}

int ocall_sock_shutdown (int sockfd, int how)
{
    int retval = 0;
    ms_ocall_sock_shutdown_t * ms;
    OCALLOC(ms, ms_ocall_sock_shutdown_t *, sizeof(*ms));

    ms->ms_sockfd = sockfd;
    ms->ms_how = how;

    retval = SGX_OCALL(OCALL_SOCK_SHUTDOWN, ms);
    OCALL_EXIT();
    return retval;
}

int ocall_gettime (unsigned long * microsec)
{
    int retval = 0;
    ms_ocall_gettime_t * ms;
    OCALLOC(ms, ms_ocall_gettime_t *, sizeof(*ms));

    retval = SGX_OCALL(OCALL_GETTIME, ms);
    if (!retval)
        *microsec = ms->ms_microsec;
    OCALL_EXIT();
    return retval;
}

int ocall_sleep (unsigned long * microsec)
{
    int retval = 0;
    ms_ocall_sleep_t * ms;
    OCALLOC(ms, ms_ocall_sleep_t *, sizeof(*ms));

    ms->ms_microsec = microsec ? *microsec : 0;

    retval = SGX_OCALL(OCALL_SLEEP, ms);
    if (microsec) {
        if (!retval)
            *microsec = 0;
        else if (retval == -EINTR)
            *microsec = ms->ms_microsec;
    }
    OCALL_EXIT();
    return retval;
}

int ocall_poll (struct pollfd * fds, int nfds, uint64_t * timeout)
{
    int retval = 0;
    ms_ocall_poll_t * ms;
    OCALLOC(ms, ms_ocall_poll_t *, sizeof(*ms));

    ms->ms_fds = COPY_TO_USER(fds, sizeof(struct pollfd) * nfds);
    ms->ms_nfds = nfds;
    ms->ms_timeout = timeout ? *timeout : OCALL_NO_TIMEOUT;

    retval = SGX_OCALL(OCALL_POLL, ms);
    if (retval == -EINTR && timeout)
        *timeout = ms->ms_timeout;
    if (retval >= 0)
        COPY_FROM_USER(fds, ms->ms_fds, sizeof(struct pollfd) * nfds);
    OCALL_EXIT();
    return retval;
}

int ocall_rename (const char * oldpath, const char * newpath)
{
    int retval = 0;
    int oldlen = oldpath ? strlen(oldpath) + 1 : 0;
    int newlen = newpath ? strlen(newpath) + 1 : 0;
    ms_ocall_rename_t * ms;
    OCALLOC(ms, ms_ocall_rename_t *, sizeof(*ms));

    ms->ms_oldpath = COPY_TO_USER(oldpath, oldlen);
    ms->ms_newpath = COPY_TO_USER(newpath, newlen);

    retval = SGX_OCALL(OCALL_RENAME, ms);
    OCALL_EXIT();
    return retval;
}

int ocall_delete (const char * pathname)
{
    int retval = 0;
    int len = pathname ? strlen(pathname) + 1 : 0;
    ms_ocall_delete_t * ms;
    OCALLOC(ms, ms_ocall_delete_t *, sizeof(*ms));

    ms->ms_pathname = COPY_TO_USER(pathname, len);

    retval = SGX_OCALL(OCALL_DELETE, ms);
    OCALL_EXIT();
    return retval;
}

int ocall_load_debug(const char * command)
{
    int retval = 0;
    int len = strlen(command);
    const char * ms = COPY_TO_USER(command, len + 1);
    retval = SGX_OCALL(OCALL_LOAD_DEBUG, (void *) ms);
    OCALL_EXIT();
    return retval;
}
