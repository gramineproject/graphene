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

noreturn void ocall_exit(int exitcode)
{
    int64_t code = exitcode;
    // There are two reasons for this loop:
    //  1. Ocalls can be interuppted.
    //  2. We can't trust the outside to actually exit, so we need to ensure
    //     that we never return even when the outside tries to trick us.
    while (true) {
        sgx_ocall(OCALL_EXIT, (void *) code);
    }
}

int ocall_print_string (const char * str, unsigned int length)
{
    int retval = 0;
    ms_ocall_print_string_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    if (!str || length <= 0) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_length = length;
    ms->ms_str = sgx_copy_to_ustack(str, length);

    if (!ms->ms_str) {
        sgx_reset_ustack();
        return -EPERM;
    }

    retval = sgx_ocall(OCALL_PRINT_STRING, ms);

    sgx_reset_ustack();
    return retval;
}

int ocall_alloc_untrusted (uint64_t size, void ** mem)
{
    int retval = 0;
    ms_ocall_alloc_untrusted_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_size = size;

    retval = sgx_ocall(OCALL_ALLOC_UNTRUSTED, ms);

    if (!retval) {
        if (!sgx_copy_ptr_to_enclave(mem, ms->ms_mem, size)) {
            sgx_reset_ustack();
            return -EPERM;
        }
    }

    sgx_reset_ustack();
    return retval;
}

int ocall_map_untrusted (int fd, uint64_t offset,
                         uint64_t size, unsigned short prot,
                         void ** mem)
{
    int retval = 0;
    ms_ocall_map_untrusted_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_fd = fd;
    ms->ms_offset = offset;
    ms->ms_size = size;
    ms->ms_prot = prot;

    retval = sgx_ocall(OCALL_MAP_UNTRUSTED, ms);

    if (!retval) {
        if (!sgx_copy_ptr_to_enclave(mem, ms->ms_mem, size)) {
            sgx_reset_ustack();
            return -EPERM;
        }
    }

    sgx_reset_ustack();
    return retval;
}

int ocall_unmap_untrusted (const void * mem, uint64_t size)
{
    int retval = 0;
    ms_ocall_unmap_untrusted_t * ms;

    if (!sgx_is_completely_outside_enclave(mem, size)) {
        sgx_reset_ustack();
        return -EINVAL;
    }

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_mem  = mem;
    ms->ms_size = size;

    retval = sgx_ocall(OCALL_UNMAP_UNTRUSTED, ms);

    sgx_reset_ustack();
    return retval;
}

int ocall_cpuid (unsigned int leaf, unsigned int subleaf,
                 unsigned int values[4])
{
    int retval = 0;
    ms_ocall_cpuid_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
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

    sgx_reset_ustack();
    return retval;
}

int ocall_open (const char * pathname, int flags, unsigned short mode)
{
    int retval = 0;
    int len = pathname ? strlen(pathname) + 1 : 0;
    ms_ocall_open_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_flags = flags;
    ms->ms_mode = mode;
    ms->ms_pathname = sgx_copy_to_ustack(pathname, len);

    if (!ms->ms_pathname) {
        sgx_reset_ustack();
        return -EPERM;
    }

    retval = sgx_ocall(OCALL_OPEN, ms);

    sgx_reset_ustack();
    return retval;
}

int ocall_close (int fd)
{
    int retval = 0;
    ms_ocall_close_t *ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_fd = fd;

    retval = sgx_ocall(OCALL_CLOSE, ms);

    sgx_reset_ustack();
    return retval;
}

int ocall_read (int fd, void * buf, unsigned int count)
{
    int retval = 0;
    void * obuf = NULL;
    ms_ocall_read_t * ms;

    if (count > PRESET_PAGESIZE) {
        retval = ocall_alloc_untrusted(ALLOC_ALIGNUP(count), &obuf);
        if (IS_ERR(retval))
            return retval;
    }

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        retval = -EPERM;
        goto out;
    }

    ms->ms_fd = fd;
    ms->ms_count = count;
    if (obuf)
        ms->ms_buf = obuf;
    else
        ms->ms_buf = sgx_alloc_on_ustack(count);

    if (!ms->ms_buf) {
        retval = -EPERM;
        goto out;
    }

    retval = sgx_ocall(OCALL_READ, ms);

    if (retval > 0) {
        if (!sgx_copy_to_enclave(buf, count, ms->ms_buf, retval)) {
            retval = -EPERM;
            goto out;
        }
    }

out:
    sgx_reset_ustack();
    if (obuf)
        ocall_unmap_untrusted(obuf, ALLOC_ALIGNUP(count));
    return retval;
}

int ocall_write (int fd, const void * buf, unsigned int count)
{
    int retval = 0;
    void * obuf = NULL;
    ms_ocall_write_t * ms;

    if (count > PRESET_PAGESIZE) {
        retval = ocall_alloc_untrusted(ALLOC_ALIGNUP(count), &obuf);
        if (IS_ERR(retval))
            return retval;
    }

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        retval = -EPERM;
        goto out;
    }

    ms->ms_fd = fd;
    ms->ms_count = count;
    if (obuf) {
        ms->ms_buf = obuf;
        memcpy(obuf, buf, count);
    } else {
        ms->ms_buf = sgx_copy_to_ustack(buf, count);
    }

    if (!ms->ms_buf) {
        retval = -EPERM;
        goto out;
    }

    retval = sgx_ocall(OCALL_WRITE, ms);

out:
    sgx_reset_ustack();
    if (obuf)
        ocall_unmap_untrusted(obuf, ALLOC_ALIGNUP(count));
    return retval;
}

int ocall_fstat (int fd, struct stat * buf)
{
    int retval = 0;
    ms_ocall_fstat_t * ms;


    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_fd = fd;

    retval = sgx_ocall(OCALL_FSTAT, ms);

    if (!retval)
        memcpy(buf, &ms->ms_stat, sizeof(struct stat));

    sgx_reset_ustack();
    return retval;
}

int ocall_fionread (int fd)
{
    int retval = 0;
    ms_ocall_fionread_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_fd = fd;

    retval = sgx_ocall(OCALL_FIONREAD, ms);

    sgx_reset_ustack();
    return retval;
}

int ocall_fsetnonblock (int fd, int nonblocking)
{
    int retval = 0;
    ms_ocall_fsetnonblock_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_fd = fd;
    ms->ms_nonblocking = nonblocking;

    retval = sgx_ocall(OCALL_FSETNONBLOCK, ms);

    sgx_reset_ustack();
    return retval;
}

int ocall_fchmod (int fd, unsigned short mode)
{
    int retval = 0;
    ms_ocall_fchmod_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_fd = fd;
    ms->ms_mode = mode;

    retval = sgx_ocall(OCALL_FCHMOD, ms);

    sgx_reset_ustack();
    return retval;
}

int ocall_fsync (int fd)
{
    int retval = 0;
    ms_ocall_fsync_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_fd = fd;

    retval = sgx_ocall(OCALL_FSYNC, ms);

    sgx_reset_ustack();
    return retval;
}

int ocall_ftruncate (int fd, uint64_t length)
{
    int retval = 0;
    ms_ocall_ftruncate_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_fd = fd;
    ms->ms_length = length;

    retval = sgx_ocall(OCALL_FTRUNCATE, ms);

    sgx_reset_ustack();
    return retval;
}

int ocall_mkdir (const char * pathname, unsigned short mode)
{
    int retval = 0;
    int len = pathname ? strlen(pathname) + 1 : 0;
    ms_ocall_mkdir_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_mode = mode;
    ms->ms_pathname = sgx_copy_to_ustack(pathname, len);

    if (!ms->ms_pathname) {
        sgx_reset_ustack();
        return -EPERM;
    }

    retval = sgx_ocall(OCALL_MKDIR, ms);

    sgx_reset_ustack();
    return retval;
}

int ocall_getdents (int fd, struct linux_dirent64 * dirp, unsigned int size)
{
    int retval = 0;
    ms_ocall_getdents_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_fd = fd;
    ms->ms_size = size;
    ms->ms_dirp = sgx_alloc_on_ustack(size);

    if (!ms->ms_dirp) {
        sgx_reset_ustack();
        return -EPERM;
    }

    retval = sgx_ocall(OCALL_GETDENTS, ms);

    if (retval > 0) {
        if (!sgx_copy_to_enclave(dirp, size, ms->ms_dirp, retval)) {
            sgx_reset_ustack();
            return -EPERM;
        }
    }

    sgx_reset_ustack();
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

    ms = sgx_alloc_on_ustack(sizeof(*ms) + nargs * sizeof(char *));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_uri = uri ? sgx_copy_to_ustack(uri, ulen) : NULL;
    if (uri && !ms->ms_uri) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_nargs = nargs;
    for (int i = 0 ; i < nargs ; i++) {
        int len = args[i] ? strlen(args[i]) + 1 : 0;
        ms->ms_args[i] = args[i] ? sgx_copy_to_ustack(args[i], len) : NULL;

        if (args[i] && !ms->ms_args[i]) {
            sgx_reset_ustack();
            return -EPERM;
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

    sgx_reset_ustack();
    return retval;
}

int ocall_futex (int * futex, int op, int val,
                 const int64_t * timeout)
{
    int retval = 0;
    ms_ocall_futex_t * ms;

    if (!sgx_is_completely_outside_enclave(futex, sizeof(int))) {
        sgx_reset_ustack();
        return -EINVAL;
    }

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_futex = futex;
    ms->ms_op = op;
    ms->ms_val = val;
    ms->ms_timeout = timeout ? *timeout : OCALL_NO_TIMEOUT;

    retval = sgx_ocall(OCALL_FUTEX, ms);

    sgx_reset_ustack();
    return retval;
}

int ocall_socketpair (int domain, int type, int protocol,
                      int sockfds[2])
{
    int retval = 0;
    ms_ocall_socketpair_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_domain = domain;
    ms->ms_type = type;
    ms->ms_protocol = protocol;

    retval = sgx_ocall(OCALL_SOCKETPAIR, ms);

    if (!retval) {
        sockfds[0] = ms->ms_sockfds[0];
        sockfds[1] = ms->ms_sockfds[1];
    }

    sgx_reset_ustack();
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

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_domain = domain;
    ms->ms_type = type;
    ms->ms_protocol = protocol;
    ms->ms_addrlen = len;
    ms->ms_addr = (addr && len) ? sgx_copy_to_ustack(addr, len) : NULL;

    if (addr && len && !ms->ms_addr) {
        sgx_reset_ustack();
        return -EPERM;
    }

    retval = sgx_ocall(OCALL_SOCK_LISTEN, ms);

    if (retval >= 0) {
        if (addr && len) {
            copied = sgx_copy_to_enclave(addr, len, ms->ms_addr, ms->ms_addrlen);
            if (!copied) {
                sgx_reset_ustack();
                return -EPERM;
            }
            *addrlen = copied;
        }

        if (sockopt) {
            *sockopt = ms->ms_sockopt;
        }
    }

    sgx_reset_ustack();
    return retval;
}

int ocall_sock_accept (int sockfd, struct sockaddr * addr,
                       unsigned int * addrlen, struct sockopt * sockopt)
{
    int retval = 0;
    unsigned int copied;
    unsigned int len = addrlen ? *addrlen : 0;
    ms_ocall_sock_accept_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_addrlen = len;
    ms->ms_addr = (addr && len) ? sgx_copy_to_ustack(addr, len) : NULL;

    if (addr && len && !ms->ms_addr) {
        sgx_reset_ustack();
        return -EPERM;
    }

    retval = sgx_ocall(OCALL_SOCK_ACCEPT, ms);

    if (retval >= 0) {
        if (addr && len) {
            copied = sgx_copy_to_enclave(addr, len, ms->ms_addr, ms->ms_addrlen);
            if (!copied) {
                sgx_reset_ustack();
                return -EPERM;
            }
            *addrlen = copied;
        }

        if (sockopt) {
            *sockopt = ms->ms_sockopt;
        }
    }

    sgx_reset_ustack();
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

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_domain = domain;
    ms->ms_type = type;
    ms->ms_protocol = protocol;
    ms->ms_addrlen = addrlen;
    ms->ms_bind_addrlen = bind_len;
    ms->ms_addr = addr ? sgx_copy_to_ustack(addr, addrlen) : NULL;
    ms->ms_bind_addr = bind_addr ? sgx_copy_to_ustack(bind_addr, bind_len) : NULL;

    if ((addr && !ms->ms_addr) || (bind_addr && !ms->ms_bind_addr)) {
        sgx_reset_ustack();
        return -EPERM;
    }

    retval = sgx_ocall(OCALL_SOCK_CONNECT, ms);

    if (retval >= 0) {
        if (bind_addr && bind_len) {
            copied = sgx_copy_to_enclave(bind_addr, bind_len, ms->ms_bind_addr, ms->ms_bind_addrlen);
            if (!copied) {
                sgx_reset_ustack();
                return -EPERM;
            }
            *bind_addrlen = copied;
        }

        if (sockopt) {
            *sockopt = ms->ms_sockopt;
        }
    }

    sgx_reset_ustack();
    return retval;
}

int ocall_sock_recv (int sockfd, void * buf, unsigned int count,
                     struct sockaddr * addr, unsigned int * addrlen)
{
    int retval = 0;
    void * obuf = NULL;
    unsigned int copied;
    unsigned int len = addrlen ? *addrlen : 0;
    ms_ocall_sock_recv_t * ms;

    if ((count + len) > PRESET_PAGESIZE) {
        retval = ocall_alloc_untrusted(ALLOC_ALIGNUP(count), &obuf);
        if (IS_ERR(retval))
            return retval;
    }

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        retval = -EPERM;
        goto out;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_count = count;
    ms->ms_addrlen = len;
    ms->ms_addr = addr ? sgx_alloc_on_ustack(len) : NULL;
    if (obuf)
        ms->ms_buf = obuf;
    else
        ms->ms_buf = sgx_alloc_on_ustack(count);

    if (!ms->ms_buf || (addr && !ms->ms_addr)) {
        retval = -EPERM;
        goto out;
    }

    retval = sgx_ocall(OCALL_SOCK_RECV, ms);

    if (retval >= 0) {
        if (addr && len) {
            copied = sgx_copy_to_enclave(addr, len, ms->ms_addr, ms->ms_addrlen);
            if (!copied) {
                retval = -EPERM;
                goto out;
            }
            *addrlen = copied;
        }

        if (!sgx_copy_to_enclave(buf, count, ms->ms_buf, retval)) {
            retval = -EPERM;
            goto out;
        }
    }

out:
    sgx_reset_ustack();
    if (obuf)
        ocall_unmap_untrusted(obuf, ALLOC_ALIGNUP(count));
    return retval;
}

int ocall_sock_send (int sockfd, const void * buf, unsigned int count,
                     const struct sockaddr * addr, unsigned int addrlen)
{
    int retval = 0;
    void * obuf = NULL;
    ms_ocall_sock_send_t * ms;

    if ((count + addrlen) > PRESET_PAGESIZE) {
        retval = ocall_alloc_untrusted(ALLOC_ALIGNUP(count), &obuf);
        if (IS_ERR(retval))
            return retval;
    }

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        retval = -EPERM;
        goto out;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_count = count;
    ms->ms_addrlen = addrlen;
    ms->ms_addr = addr ? sgx_copy_to_ustack(addr, addrlen) : NULL;
    if (obuf) {
        ms->ms_buf = obuf;
        memcpy(obuf, buf, count);
    } else {
        ms->ms_buf = sgx_copy_to_ustack(buf, count);
    }

    if (!ms->ms_buf || (addr && !ms->ms_addr)) {
        retval = -EPERM;
        goto out;
    }

    retval = sgx_ocall(OCALL_SOCK_SEND, ms);

out:
    sgx_reset_ustack();
    if (obuf)
        ocall_unmap_untrusted(obuf, ALLOC_ALIGNUP(count));
    return retval;
}

int ocall_sock_recv_fd (int sockfd, void * buf, unsigned int count,
                        unsigned int * fds, unsigned int * nfds)
{
    int retval = 0;
    unsigned int copied;
    unsigned int max_nfds_bytes = (*nfds) * sizeof(int);
    ms_ocall_sock_recv_fd_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_count = count;
    ms->ms_nfds = *nfds;
    ms->ms_buf = sgx_alloc_on_ustack(count);
    ms->ms_fds = sgx_alloc_on_ustack(max_nfds_bytes);

    if (!ms->ms_buf || !ms->ms_fds) {
        sgx_reset_ustack();
        return -EPERM;
    }

    retval = sgx_ocall(OCALL_SOCK_RECV_FD, ms);

    if (retval >= 0) {
        if (!sgx_copy_to_enclave(buf, count, ms->ms_buf, retval)) {
            sgx_reset_ustack();
            return -EPERM;
        }

        copied = sgx_copy_to_enclave(fds, max_nfds_bytes, ms->ms_fds, ms->ms_nfds * sizeof(int));
        if (!copied) {
            sgx_reset_ustack();
            return -EPERM;
        }
        *nfds = copied / sizeof(int);
    }

    sgx_reset_ustack();
    return retval;
}

int ocall_sock_send_fd (int sockfd, const void * buf, unsigned int count,
                        const unsigned int * fds, unsigned int nfds)
{
    int retval = 0;
    ms_ocall_sock_send_fd_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_count = count;
    ms->ms_nfds = nfds;
    ms->ms_buf = sgx_copy_to_ustack(buf, count);
    ms->ms_fds = sgx_copy_to_ustack(fds, nfds * sizeof(int));

    if (!ms->ms_buf || !ms->ms_fds) {
        sgx_reset_ustack();
        return -EPERM;
    }

    retval = sgx_ocall(OCALL_SOCK_SEND_FD, ms);

    sgx_reset_ustack();
    return retval;
}

int ocall_sock_setopt (int sockfd, int level, int optname,
                       const void * optval, unsigned int optlen)
{
    int retval = 0;
    ms_ocall_sock_setopt_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_level = level;
    ms->ms_optname = optname;
    ms->ms_optlen = 0;
    ms->ms_optval = NULL;

    if (optval && optlen > 0) {
        ms->ms_optlen = optlen;
        ms->ms_optval = sgx_copy_to_ustack(optval, optlen);

        if (!ms->ms_optval) {
            sgx_reset_ustack();
            return -EPERM;
        }
    }

    retval = sgx_ocall(OCALL_SOCK_SETOPT, ms);

    sgx_reset_ustack();
    return retval;
}

int ocall_sock_shutdown (int sockfd, int how)
{
    int retval = 0;
    ms_ocall_sock_shutdown_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_sockfd = sockfd;
    ms->ms_how = how;

    retval = sgx_ocall(OCALL_SOCK_SHUTDOWN, ms);

    sgx_reset_ustack();
    return retval;
}

int ocall_gettime (unsigned long * microsec)
{
    int retval = 0;
    ms_ocall_gettime_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    retval = sgx_ocall(OCALL_GETTIME, ms);
    if (!retval)
        *microsec = ms->ms_microsec;

    sgx_reset_ustack();
    return retval;
}

int ocall_sleep (unsigned long * microsec)
{
    int retval = 0;
    ms_ocall_sleep_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_microsec = microsec ? *microsec : 0;

    retval = sgx_ocall(OCALL_SLEEP, ms);
    if (microsec) {
        if (!retval)
            *microsec = 0;
        else if (retval == -EINTR)
            *microsec = ms->ms_microsec;
    }

    sgx_reset_ustack();
    return retval;
}

int ocall_poll (struct pollfd * fds, int nfds, int64_t * timeout)
{
    int retval = 0;
    unsigned int nfds_bytes = nfds * sizeof(struct pollfd);
    ms_ocall_poll_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_nfds = nfds;
    ms->ms_timeout = timeout ? *timeout : OCALL_NO_TIMEOUT;
    ms->ms_fds = sgx_copy_to_ustack(fds, nfds_bytes);

    if (!ms->ms_fds) {
        sgx_reset_ustack();
        return -EPERM;
    }

    retval = sgx_ocall(OCALL_POLL, ms);

    if (retval == -EINTR && timeout)
        *timeout = ms->ms_timeout;

    if (retval >= 0) {
        if (!sgx_copy_to_enclave(fds, nfds_bytes, ms->ms_fds, nfds_bytes)) {
            sgx_reset_ustack();
            return -EPERM;
        }
    }

    sgx_reset_ustack();
    return retval;
}

int ocall_rename (const char * oldpath, const char * newpath)
{
    int retval = 0;
    int oldlen = oldpath ? strlen(oldpath) + 1 : 0;
    int newlen = newpath ? strlen(newpath) + 1 : 0;
    ms_ocall_rename_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_oldpath = sgx_copy_to_ustack(oldpath, oldlen);
    ms->ms_newpath = sgx_copy_to_ustack(newpath, newlen);

    if (!ms->ms_oldpath || !ms->ms_newpath) {
        sgx_reset_ustack();
        return -EPERM;
    }

    retval = sgx_ocall(OCALL_RENAME, ms);

    sgx_reset_ustack();
    return retval;
}

int ocall_delete (const char * pathname)
{
    int retval = 0;
    int len = pathname ? strlen(pathname) + 1 : 0;
    ms_ocall_delete_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_pathname = sgx_copy_to_ustack(pathname, len);
    if (!ms->ms_pathname) {
        sgx_reset_ustack();
        return -EPERM;
    }

    retval = sgx_ocall(OCALL_DELETE, ms);

    sgx_reset_ustack();
    return retval;
}

int ocall_load_debug(const char * command)
{
    int retval = 0;
    int len = strlen(command) + 1;

    const char * ms = sgx_copy_to_ustack(command, len);
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    retval = sgx_ocall(OCALL_LOAD_DEBUG, (void *) ms);

    sgx_reset_ustack();
    return retval;
}
