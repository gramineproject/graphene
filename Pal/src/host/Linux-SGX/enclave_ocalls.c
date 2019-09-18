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

noreturn void ocall_exit(int exitcode, int is_exitgroup)
{
    ms_ocall_exit_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    ms->ms_exitcode     = exitcode;
    ms->ms_is_exitgroup = is_exitgroup;

    // There are two reasons for this loop:
    //  1. Ocalls can be interuppted.
    //  2. We can't trust the outside to actually exit, so we need to ensure
    //     that we never return even when the outside tries to trick us.
    while (true) {
        sgx_ocall(OCALL_EXIT, ms);
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

int ocall_create_process(const char* uri, int nargs, const char** args, int procfds[3],
                         unsigned int* pid) {
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

int ocall_futex(int* futex, int op, int val, int64_t timeout_us) {
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
    ms->ms_timeout_us = timeout_us;

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

        if (retval > 0 && !sgx_copy_to_enclave(buf, count, ms->ms_buf, retval)) {
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
    unsigned int copied = 0;
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
        if (retval > 0 && !sgx_copy_to_enclave(buf, count, ms->ms_buf, retval)) {
            sgx_reset_ustack();
            return -EPERM;
        }

        if (ms->ms_nfds > 0) {
            /* TOCTOU on ms_nfds is possible, but it is benign */
            copied = sgx_copy_to_enclave(fds, max_nfds_bytes, ms->ms_fds, ms->ms_nfds * sizeof(int));
            if (!copied) {
                sgx_reset_ustack();
                return -EPERM;
            }
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

    do {
        retval = sgx_ocall(OCALL_GETTIME, ms);
    } while(retval == -EINTR);
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

int ocall_poll(struct pollfd* fds, int nfds, int64_t timeout_us) {
    int retval = 0;
    unsigned int nfds_bytes = nfds * sizeof(struct pollfd);
    ms_ocall_poll_t * ms;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms) {
        sgx_reset_ustack();
        return -EPERM;
    }

    ms->ms_nfds = nfds;
    ms->ms_timeout_us = timeout_us;
    ms->ms_fds = sgx_copy_to_ustack(fds, nfds_bytes);

    if (!ms->ms_fds) {
        sgx_reset_ustack();
        return -EPERM;
    }

    retval = sgx_ocall(OCALL_POLL, ms);

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

/*
 * ocall_get_attestation() triggers remote attestation in untrusted PAL (see sgx_platform.c:
 * retrieve_verified_quote()). If the OCall returns successfully, the function returns
 * attestation data required for platform verification (i.e., sgx_attestation_t). Except the
 * QE report, most data fields of the attestation need to be copied into the enclave.
 *
 * @spid:        The client SPID registered with the IAS.
 * @subkey:      SPID subscription key.
 * @linkable:    Whether the SPID is linkable.
 * @report:      Local attestation report for the quoting enclave.
 * @nonce:       Randomly-generated nonce for freshness.
 * @attestation: Returns the attestation data (QE report, quote, IAS report, signature,
 *               and certificate chain).
 */
int ocall_get_attestation (const sgx_spid_t* spid, const char* subkey, bool linkable,
                           const sgx_arch_report_t* report, const sgx_quote_nonce_t* nonce,
                           sgx_attestation_t* attestation) {

    ms_ocall_get_attestation_t * ms;
    int retval = -EPERM;

    ms = sgx_alloc_on_ustack(sizeof(*ms));
    if (!ms)
        goto reset;

    memcpy(&ms->ms_spid,   spid,   sizeof(sgx_spid_t));
    ms->ms_subkey = sgx_copy_to_ustack(subkey, strlen(subkey) + 1);
    memcpy(&ms->ms_report, report, sizeof(sgx_arch_report_t));
    memcpy(&ms->ms_nonce,  nonce,  sizeof(sgx_quote_nonce_t));
    ms->ms_linkable = linkable;

    retval = sgx_ocall(OCALL_GET_ATTESTATION, ms);

    if (retval >= 0) {
        // First, try to copy the whole ms->ms_attestation inside
        if (!sgx_copy_to_enclave(attestation, sizeof(sgx_attestation_t), &ms->ms_attestation,
                                 sizeof(sgx_attestation_t))) {
            retval = -EACCES;
            goto reset;
        }

        // For calling ocall_unmap_untrusted, need to reset the untrusted stack
        sgx_reset_ustack();

        // Copy each field inside and free the untrusted buffers
        if (attestation->quote) {
            size_t len = attestation->quote_len;
            sgx_quote_t* quote = malloc(len);
            if (!sgx_copy_to_enclave(quote, len, attestation->quote, len))
                retval = -EACCES;
            ocall_unmap_untrusted(attestation->quote, ALLOC_ALIGNUP(len));
            attestation->quote = quote;
        }

        if (attestation->ias_report) {
            size_t len = attestation->ias_report_len;
            char* ias_report = malloc(len + 1);
            if (!sgx_copy_to_enclave(ias_report, len, attestation->ias_report, len))
                retval = -EACCES;
            ocall_unmap_untrusted(attestation->ias_report, ALLOC_ALIGNUP(len));
            ias_report[len] = 0; // Ensure null-ending
            attestation->ias_report = ias_report;
        }

        if (attestation->ias_sig) {
            size_t len = attestation->ias_sig_len;
            uint8_t* ias_sig = malloc(len);
            if (!sgx_copy_to_enclave(ias_sig, len, attestation->ias_sig, len))
                retval = -EACCES;
            ocall_unmap_untrusted(attestation->ias_sig, ALLOC_ALIGNUP(len));
            attestation->ias_sig = ias_sig;
        }

        if (attestation->ias_certs) {
            size_t len = attestation->ias_certs_len;
            char* ias_certs = malloc(len + 1);
            if (!sgx_copy_to_enclave(ias_certs, len, attestation->ias_certs, len))
                retval = -EACCES;
            ocall_unmap_untrusted(attestation->ias_certs, ALLOC_ALIGNUP(len));
            ias_certs[len] = 0; // Ensure null-ending
            attestation->ias_certs = ias_certs;
        }

        // At this point, no field should point to outside the enclave
        if (retval < 0) {
            if (attestation->quote)      free(attestation->quote);
            if (attestation->ias_report) free(attestation->ias_report);
            if (attestation->ias_sig)    free(attestation->ias_sig);
            if (attestation->ias_certs)  free(attestation->ias_certs);
        }

        goto out;
    }

reset:
    sgx_reset_ustack();
out:
    return retval;
}
