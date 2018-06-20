/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "ocall_types.h"
#include "ecall_types.h"
#include "sgx_internal.h"
#include "pal_security.h"
#include "pal_linux_error.h"

#include <asm/mman.h>
#include <asm/ioctls.h>
#include <asm/socket.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <math.h>
#include <asm/errno.h>

#ifndef SOL_IPV6
# define SOL_IPV6 41
#endif

#define ODEBUG(code, ms) do {} while (0)

static int sgx_ocall_exit(int rv)
{
    ODEBUG(OCALL_EXIT, NULL);
    if (rv != (int) ((uint8_t) rv)) {
        SGX_DBG(DBG_E, "Saturation error in exit code %d, getting rounded down to %u\n", rv, (uint8_t) rv);
        rv = 255;
    }
    INLINE_SYSCALL(exit, 1, rv);
    return 0;
}

static int sgx_ocall_print_string(void * pms)
{
    ms_ocall_print_string_t * ms = (ms_ocall_print_string_t *) pms;
    INLINE_SYSCALL(write, 3, 2, ms->ms_str, ms->ms_length);
    return 0;
}

static int sgx_ocall_alloc_untrusted(void * pms)
{
    ms_ocall_alloc_untrusted_t * ms = (ms_ocall_alloc_untrusted_t *) pms;
    void * addr;
    ODEBUG(OCALL_ALLOC_UNTRUSTED, ms);
    addr = (void *) INLINE_SYSCALL(mmap, 6, NULL, ms->ms_size,
                                   PROT_READ|PROT_WRITE,
                                   MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (IS_ERR_P(addr))
        return -PAL_ERROR_NOMEM;

    ms->ms_mem = addr;
    return 0;
}

static int sgx_ocall_map_untrusted(void * pms)
{
    ms_ocall_map_untrusted_t * ms = (ms_ocall_map_untrusted_t *) pms;
    void * addr;
    ODEBUG(OCALL_MAP_UNTRUSTED, ms);
    addr = (void *) INLINE_SYSCALL(mmap, 6, NULL, ms->ms_size,
                                   ms->ms_prot,
                                   MAP_FILE|MAP_SHARED,
                                   ms->ms_fd, ms->ms_offset);
    if (IS_ERR_P(addr))
        return -PAL_ERROR_NOMEM;

    ms->ms_mem = addr;
    return 0;
}

static int sgx_ocall_unmap_untrusted(void * pms)
{
    ms_ocall_unmap_untrusted_t * ms = (ms_ocall_unmap_untrusted_t *) pms;
    ODEBUG(OCALL_UNMAP_UNTRUSTED, ms);
    INLINE_SYSCALL(munmap, 2, ALLOC_ALIGNDOWN(ms->ms_mem),
                   ALLOC_ALIGNUP(ms->ms_mem + ms->ms_size) -
                   ALLOC_ALIGNDOWN(ms->ms_mem));
    return 0;
}

static int sgx_ocall_cpuid(void * pms)
{
    ms_ocall_cpuid_t * ms = (ms_ocall_cpuid_t *) pms;
    ODEBUG(OCALL_CPUID, ms);
    asm volatile ("cpuid"
                  : "=a"(ms->ms_values[0]),
                    "=b"(ms->ms_values[1]),
                    "=c"(ms->ms_values[2]),
                    "=d"(ms->ms_values[3])
                  : "a"(ms->ms_leaf), "c"(ms->ms_subleaf) : "memory");
    return 0;
}

static int sgx_ocall_open(void * pms)
{
    ms_ocall_open_t * ms = (ms_ocall_open_t *) pms;
    int ret;
    ODEBUG(OCALL_OPEN, ms);
    ret = INLINE_SYSCALL(open, 3, ms->ms_pathname, ms->ms_flags|O_CLOEXEC,
                         ms->ms_mode);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int sgx_ocall_close(void * pms)
{
    ms_ocall_close_t * ms = (ms_ocall_close_t *) pms;
    ODEBUG(OCALL_CLOSE, ms);
    INLINE_SYSCALL(close, 1, ms->ms_fd);
    return 0;
}

static int sgx_ocall_read(void * pms)
{
    ms_ocall_read_t * ms = (ms_ocall_read_t *) pms;
    int ret;
    ODEBUG(OCALL_READ, ms);
    ret = INLINE_SYSCALL(read, 3, ms->ms_fd, ms->ms_buf, ms->ms_count);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int sgx_ocall_write(void * pms)
{
    ms_ocall_write_t * ms = (ms_ocall_write_t *) pms;
    int ret;
    ODEBUG(OCALL_WRITE, ms);
    ret = INLINE_SYSCALL(write, 3, ms->ms_fd, ms->ms_buf, ms->ms_count);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int sgx_ocall_fstat(void * pms)
{
    ms_ocall_fstat_t * ms = (ms_ocall_fstat_t *) pms;
    int ret;
    ODEBUG(OCALL_FSTAT, ms);
    ret = INLINE_SYSCALL(fstat, 2, ms->ms_fd, &ms->ms_stat);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int sgx_ocall_fionread(void * pms)
{
    ms_ocall_fionread_t * ms = (ms_ocall_fionread_t *) pms;
    int ret, val;
    ODEBUG(OCALL_FIONREAD, ms);
    ret = INLINE_SYSCALL(ioctl, 3, ms->ms_fd, FIONREAD, &val);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : val;
}

static int sgx_ocall_fsetnonblock(void * pms)
{
    ms_ocall_fsetnonblock_t * ms = (ms_ocall_fsetnonblock_t *) pms;
    int ret, flags;
    ODEBUG(OCALL_FSETNONBLOCK, ms);

    ret = INLINE_SYSCALL(fcntl, 2, ms->ms_fd, F_GETFL);
    if (IS_ERR(ret))
        return -ERRNO(ret);

    flags = ret;
    if (ms->ms_nonblocking) {
        if (!(flags & O_NONBLOCK))
            ret = INLINE_SYSCALL(fcntl, 3, ms->ms_fd, F_SETFL,
                                 flags | O_NONBLOCK);
    } else {
        if (flags & O_NONBLOCK)
            ret = INLINE_SYSCALL(fcntl, 3, ms->ms_fd, F_SETFL,
                                 flags & ~O_NONBLOCK);
    }

    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : 0;
}

static int sgx_ocall_fchmod(void * pms)
{
    ms_ocall_fchmod_t * ms = (ms_ocall_fchmod_t *) pms;
    int ret;
    ODEBUG(OCALL_FCHMOD, ms);
    ret = INLINE_SYSCALL(fchmod, 2, ms->ms_fd, ms->ms_mode);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int sgx_ocall_fsync(void * pms)
{
    ms_ocall_fsync_t * ms = (ms_ocall_fsync_t *) pms;
    ODEBUG(OCALL_FSYNC, ms);
    INLINE_SYSCALL(fsync, 1, ms->ms_fd);
    return 0;
}

static int sgx_ocall_ftruncate(void * pms)
{
    ms_ocall_ftruncate_t * ms = (ms_ocall_ftruncate_t *) pms;
    int ret;
    ODEBUG(OCALL_FTRUNCATE, ms);
    ret = INLINE_SYSCALL(ftruncate, 2, ms->ms_fd, ms->ms_length);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int sgx_ocall_mkdir(void * pms)
{
    ms_ocall_mkdir_t * ms = (ms_ocall_mkdir_t *) pms;
    int ret;
    ODEBUG(OCALL_MKDIR, ms);
    ret = INLINE_SYSCALL(mkdir, 2, ms->ms_pathname, ms->ms_mode);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int sgx_ocall_getdents(void * pms)
{
    ms_ocall_getdents_t * ms = (ms_ocall_getdents_t *) pms;
    int ret;
    ODEBUG(OCALL_GETDENTS, ms);
    ret = INLINE_SYSCALL(getdents64, 3, ms->ms_fd, ms->ms_dirp, ms->ms_size);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int sgx_ocall_wake_thread(void * pms)
{
    ODEBUG(OCALL_WAKE_THREAD, pms);
    return pms ? interrupt_thread(pms) : clone_thread();
}

int sgx_create_process (const char * uri,
                        int nargs, const char ** args,
                        int * retfds);

static int sgx_ocall_create_process(void * pms)
{
    ms_ocall_create_process_t * ms = (ms_ocall_create_process_t *) pms;
    ODEBUG(OCALL_CREATE_PROCESS, ms);
    int ret = sgx_create_process(ms->ms_uri, ms->ms_nargs, ms->ms_args,
                                 ms->ms_proc_fds);
    if (ret < 0)
        return ret;
    ms->ms_pid = ret;
    return 0;
}

static int sgx_ocall_futex(void * pms)
{
    ms_ocall_futex_t * ms = (ms_ocall_futex_t *) pms;
    int ret;
    ODEBUG(OCALL_FUTEX, ms);
    struct timespec * ts = NULL;
    if (ms->ms_timeout != OCALL_NO_TIMEOUT) {
        ts = __alloca(sizeof(struct timespec));
        ts->tv_sec = ms->ms_timeout / 1000000;
        ts->tv_nsec = (ms->ms_timeout - ts->tv_sec * 1000000) * 1000;
    }
    ret = INLINE_SYSCALL(futex, 6, ms->ms_futex, ms->ms_op, ms->ms_val,
                         ts, NULL, 0);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int sgx_ocall_socketpair(void * pms)
{
    ms_ocall_socketpair_t * ms = (ms_ocall_socketpair_t *) pms;
    int ret;
    ODEBUG(OCALL_SOCKETPAIR, ms);
    ret = INLINE_SYSCALL(socketpair, 4, ms->ms_domain,
                         ms->ms_type|SOCK_CLOEXEC,
                         ms->ms_protocol, &ms->ms_sockfds);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int sock_getopt(int fd, struct sockopt * opt)
{
    return 0;
}

static int sgx_ocall_sock_listen(void * pms)
{
    ms_ocall_sock_listen_t * ms = (ms_ocall_sock_listen_t *) pms;
    int ret, fd;
    ODEBUG(OCALL_SOCK_LISTEN, ms);

    ret = INLINE_SYSCALL(socket, 3, ms->ms_domain,
                         ms->ms_type|SOCK_CLOEXEC,
                         ms->ms_protocol);
    if (IS_ERR(ret)) {
        ret = -PAL_ERROR_DENIED;
        goto err;
    }

    fd = ret;
    if (ms->ms_addr->sa_family == AF_INET6) {
        int ipv6only = 1;
        INLINE_SYSCALL(setsockopt, 5, fd, SOL_IPV6, IPV6_V6ONLY, &ipv6only,
                       sizeof(int));
    }
    /* must set the socket to be reuseable */
    int reuseaddr = 1;
    INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
                   sizeof(int));

    ret = INLINE_SYSCALL(bind, 3, fd, ms->ms_addr, ms->ms_addrlen);
    if (IS_ERR(ret)) {
        ret = unix_to_pal_error(ERRNO(ret));
        goto err_fd;
    }

    if (ms->ms_addr) {
        socklen_t addrlen;
        ret = INLINE_SYSCALL(getsockname, 3, fd, ms->ms_addr, &addrlen);
        if (IS_ERR(ret)) {
            ret = -PAL_ERROR_DENIED;
            goto err_fd;
        }
        ms->ms_addrlen = addrlen;
    }

    if (ms->ms_type & SOCK_STREAM) {
        ret = INLINE_SYSCALL(listen, 2, fd, DEFAULT_BACKLOG);
        if (IS_ERR(ret)) {
            ret = -PAL_ERROR_DENIED;
            goto err_fd;
        }
    }

    ret = sock_getopt(fd, &ms->ms_sockopt);
    if (ret < 0)
        goto err_fd;

    return fd;

err_fd:
    INLINE_SYSCALL(close, 1, fd);
err:
    return ret;
}

static int sgx_ocall_sock_accept(void * pms)
{
    ms_ocall_sock_accept_t * ms = (ms_ocall_sock_accept_t *) pms;
    int ret, fd;
    ODEBUG(OCALL_SOCK_ACCEPT, ms);
    socklen_t addrlen = ms->ms_addrlen;

    ret = INLINE_SYSCALL(accept4, 4, ms->ms_sockfd, ms->ms_addr,
                         &addrlen, O_CLOEXEC);
    if (IS_ERR(ret)) {
        ret = unix_to_pal_error(ERRNO(ret));
        goto err;
    }

    fd = ret;
    ret = sock_getopt(fd, &ms->ms_sockopt);
    if (ret < 0)
        goto err_fd;

    ms->ms_addrlen = addrlen;
    return fd;

err_fd:
    INLINE_SYSCALL(close, 1, fd);
err:
    return ret;
}

static int sgx_ocall_sock_connect(void * pms)
{
    ms_ocall_sock_connect_t * ms = (ms_ocall_sock_connect_t *) pms;
    int ret, fd;
    ODEBUG(OCALL_SOCK_CONNECT, ms);

    ret = INLINE_SYSCALL(socket, 3, ms->ms_domain,
                         ms->ms_type|SOCK_CLOEXEC,
                         ms->ms_protocol);
    if (IS_ERR(ret)) {
        ret = -PAL_ERROR_DENIED;
        goto err;
    }

    fd = ret;
    if (ms->ms_addr->sa_family == AF_INET6) {
        int ipv6only = 1;
        INLINE_SYSCALL(setsockopt, 5, fd, SOL_IPV6, IPV6_V6ONLY, &ipv6only,
                       sizeof(int));
    }

    if (ms->ms_bind_addr && ms->ms_bind_addr->sa_family) {
        ret = INLINE_SYSCALL(bind, 3, fd, ms->ms_bind_addr,
                             ms->ms_bind_addrlen);
        if (IS_ERR(ret)) {
            ret = unix_to_pal_error(ERRNO(ret));
            goto err_fd;
        }
    }

    ret = INLINE_SYSCALL(connect, 3, fd, ms->ms_addr, ms->ms_addrlen);

    if (IS_ERR(ret) && ERRNO(ret) == EINPROGRESS) {
        do {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0, };
            ret = INLINE_SYSCALL(ppoll, 4, &pfd, 1, NULL, NULL);
        } while (IS_ERR(ret) &&
                 ERRNO(ret) == -EWOULDBLOCK);
    }

    if (IS_ERR(ret)) {
        ret = unix_to_pal_error(ERRNO(ret));
        goto err_fd;
    }

    if (ms->ms_bind_addr && !ms->ms_bind_addr->sa_family) {
        socklen_t addrlen;
        ret = INLINE_SYSCALL(getsockname, 3, fd, ms->ms_bind_addr,
                             &addrlen);
        if (IS_ERR(ret)) {
            ret = -PAL_ERROR_DENIED;
            goto err_fd;
        }
        ms->ms_bind_addrlen = addrlen;
    }

    ret = sock_getopt(fd, &ms->ms_sockopt);
    if (ret < 0)
        goto err_fd;

    return fd;

err_fd:
    INLINE_SYSCALL(close, 1, fd);
err:
    return ret;
}

static int sgx_ocall_sock_recv(void * pms)
{
    ms_ocall_sock_recv_t * ms = (ms_ocall_sock_recv_t *) pms;
    int ret;
    ODEBUG(OCALL_SOCK_RECV, ms);
    struct sockaddr * addr = ms->ms_addr;
    socklen_t addrlen = ms->ms_addr ? ms->ms_addrlen : 0;

    if (ms->ms_sockfd == PAL_SEC()->mcast_srv)
        addr = NULL;

    ret = INLINE_SYSCALL(recvfrom, 6,
                         ms->ms_sockfd, ms->ms_buf, ms->ms_count, 0,
                         addr, addr ? &addrlen : NULL);

    if (!IS_ERR(ret) && addr)
        ms->ms_addrlen = addrlen;

    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int sgx_ocall_sock_send(void * pms)
{
    ms_ocall_sock_send_t * ms = (ms_ocall_sock_send_t *) pms;
    int ret;
    ODEBUG(OCALL_SOCK_SEND, ms);
    const struct sockaddr * addr = ms->ms_addr;
    socklen_t addrlen = ms->ms_addr ? ms->ms_addrlen : 0;

    if (ms->ms_sockfd == PAL_SEC()->mcast_srv) {
        struct sockaddr_in * mcast_addr = __alloca(sizeof(struct sockaddr_in));
        mcast_addr->sin_family = AF_INET;
        inet_pton4(MCAST_GROUP, sizeof(MCAST_GROUP),  &mcast_addr->sin_addr.s_addr);
        mcast_addr->sin_port = htons(PAL_SEC()->mcast_port);
        addr = (struct sockaddr *) mcast_addr;
        addrlen = sizeof(struct sockaddr_in);
    }

    ret = INLINE_SYSCALL(sendto, 6,
                         ms->ms_sockfd, ms->ms_buf, ms->ms_count, MSG_NOSIGNAL,
                         addr, addrlen);

    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int sgx_ocall_sock_recv_fd(void * pms)
{
    ms_ocall_sock_recv_fd_t * ms = (ms_ocall_sock_recv_fd_t *) pms;
    int ret;
    ODEBUG(OCALL_SOCK_RECV_FD, ms);

    struct msghdr hdr;
    struct iovec iov[1];

    // receive PAL_HANDLE contents in the body
    char cbuf[sizeof(struct cmsghdr) + ms->ms_nfds * sizeof(int)];

    iov[0].iov_base = ms->ms_buf;
    iov[0].iov_len = ms->ms_count;

    // clear body memory
    memset(&hdr, 0, sizeof(struct msghdr));

    // set message header values
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = cbuf;
    hdr.msg_controllen = sizeof(struct cmsghdr) + sizeof(int) *
                         ms->ms_nfds;
    hdr.msg_flags = 0;

    ret = INLINE_SYSCALL(recvmsg, 3, ms->ms_sockfd, &hdr, 0);

    if (!IS_ERR(ret)) {
        struct cmsghdr * chdr = CMSG_FIRSTHDR(&hdr);
        if (chdr &&
            chdr->cmsg_type == SCM_RIGHTS) {
            ms->ms_nfds = (chdr->cmsg_len - sizeof(struct cmsghdr)) /
                          sizeof(int);
            memcpy(ms->ms_fds, CMSG_DATA(chdr), sizeof(int) * ms->ms_nfds);
        } else {
            ms->ms_nfds = 0;
        }

        return ret;
    }

    return unix_to_pal_error(ERRNO(ret));
}

static int sgx_ocall_sock_send_fd(void * pms)
{
    ms_ocall_sock_send_fd_t * ms = (ms_ocall_sock_send_fd_t *) pms;
    int ret;
    ODEBUG(OCALL_SOCK_SEND_FD, ms);

    // Declare variables required for sending the message
    struct msghdr hdr; // message header
    struct cmsghdr * chdr; //control message header
    struct iovec iov[1]; // IO Vector

    /* Message Body Composition:
       IOVEC[0]: PAL_HANDLE
       IOVEC[1..n]: Additional handle member follow
       Control Message: file descriptors */

    // Control message buffer with added space for 2 fds (ie. max size
    // that it will have)
    char cbuf[sizeof(struct cmsghdr) + ms->ms_nfds * sizeof(int)];

    iov[0].iov_base = (void *) ms->ms_buf;
    iov[0].iov_len = ms->ms_count;

    hdr.msg_name = NULL;
    hdr.msg_namelen = 0;
    hdr.msg_iov = iov;
    hdr.msg_iovlen = 1;
    hdr.msg_flags = 0;

    hdr.msg_control = cbuf; // Control Message Buffer
    hdr.msg_controllen = sizeof(struct cmsghdr) + sizeof(int) * ms->ms_nfds;

    // Fill control message infomation for the file descriptors
    // Check hdr.msg_controllen >= sizeof(struct cmsghdr) to point to
    // cbuf, which is redundant based on the above code as we have
    // statically allocated memory.
    // or (struct cmsghdr*) cbuf
    chdr = CMSG_FIRSTHDR(&hdr); // Pointer to msg_control
    chdr->cmsg_level = SOL_SOCKET; // Originating Protocol
    chdr->cmsg_type = SCM_RIGHTS; // Protocol Specific Type
    // Length of control message = sizeof(struct cmsghdr) + nfds
    chdr->cmsg_len = CMSG_LEN(sizeof(int) * ms->ms_nfds);

    // Copy the fds below control header
    memcpy(CMSG_DATA(chdr), ms->ms_fds, sizeof(int) * ms->ms_nfds);

    // Also, Update main header with control message length (duplicate)
    hdr.msg_controllen = chdr->cmsg_len;

    ret = INLINE_SYSCALL(sendmsg, 3, ms->ms_sockfd, &hdr, MSG_NOSIGNAL);

    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int sgx_ocall_sock_setopt(void * pms)
{
    ms_ocall_sock_setopt_t * ms = (ms_ocall_sock_setopt_t *) pms;
    int ret;
    ODEBUG(OCALL_SOCK_SETOPT, ms);
    ret = INLINE_SYSCALL(setsockopt, 5,
                         ms->ms_sockfd, ms->ms_level, ms->ms_optname,
                         ms->ms_optval, ms->ms_optlen);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int sgx_ocall_sock_shutdown(void * pms)
{
    ms_ocall_sock_shutdown_t * ms = (ms_ocall_sock_shutdown_t *) pms;
    ODEBUG(OCALL_SOCK_SHUTDOWN, ms);
    INLINE_SYSCALL(shutdown, 2, ms->ms_sockfd, ms->ms_how);
    return 0;
}

static int sgx_ocall_gettime(void * pms)
{
    ms_ocall_gettime_t * ms = (ms_ocall_gettime_t *) pms;
    ODEBUG(OCALL_GETTIME, ms);
    struct timeval tv;
    INLINE_SYSCALL(gettimeofday, 2, &tv, NULL);
    ms->ms_microsec = tv.tv_sec * 1000000UL + tv.tv_usec;
    return 0;
}

static int sgx_ocall_sleep(void * pms)
{
    ms_ocall_sleep_t * ms = (ms_ocall_sleep_t *) pms;
    int ret;
    ODEBUG(OCALL_SLEEP, ms);
    if (!ms->ms_microsec) {
        INLINE_SYSCALL(sched_yield, 0);
        return 0;
    }
    struct timespec req, rem;
    req.tv_sec  = ms->ms_microsec / 1000000;
    req.tv_nsec = (ms->ms_microsec - req.tv_sec * 1000000) * 1000;
    ret = INLINE_SYSCALL(nanosleep, 2, &req, &rem);
    if (IS_ERR(ret) && ERRNO(ret) == EINTR)
        ms->ms_microsec = rem.tv_sec * 1000000 + rem.tv_nsec / 1000;
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int sgx_ocall_poll(void * pms)
{
    ms_ocall_poll_t * ms = (ms_ocall_poll_t *) pms;
    int ret;
    ODEBUG(OCALL_POLL, ms);
    struct timespec * ts = NULL;
    if (ms->ms_timeout != OCALL_NO_TIMEOUT) {
        ts = __alloca(sizeof(struct timespec));
        ts->tv_sec = ms->ms_timeout / 1000000;
        ts->tv_nsec = (ms->ms_timeout - ts->tv_sec * 1000000) * 1000;
    }
    ret = INLINE_SYSCALL(ppoll, 4, ms->ms_fds, ms->ms_nfds, ts, NULL);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int sgx_ocall_rename(void * pms)
{
    ms_ocall_rename_t * ms = (ms_ocall_rename_t *) pms;
    int ret;
    ODEBUG(OCALL_RENAME, ms);
    ret = INLINE_SYSCALL(rename, 2, ms->ms_oldpath, ms->ms_newpath);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int sgx_ocall_delete(void * pms)
{
    ms_ocall_delete_t * ms = (ms_ocall_delete_t *) pms;
    int ret;
    ODEBUG(OCALL_DELETE, ms);

    ret = INLINE_SYSCALL(unlink, 1, ms->ms_pathname);

    if (IS_ERR(ret) && ERRNO(ret) == EISDIR)
        ret = INLINE_SYSCALL(rmdir, 1, ms->ms_pathname);

    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

void load_gdb_command (const char * command);

static int sgx_ocall_load_debug(void * pms)
{
    const char * command = (const char *) pms;
    ODEBUG(OCALL_LOAD_DEBUG, (void *) command);
    load_gdb_command(command);
    return 0;
}

void * ocall_table[OCALL_NR] = {
        [OCALL_EXIT]            = (void *) sgx_ocall_exit,
        [OCALL_PRINT_STRING]    = (void *) sgx_ocall_print_string,
        [OCALL_ALLOC_UNTRUSTED] = (void *) sgx_ocall_alloc_untrusted,
        [OCALL_MAP_UNTRUSTED]   = (void *) sgx_ocall_map_untrusted,
        [OCALL_UNMAP_UNTRUSTED] = (void *) sgx_ocall_unmap_untrusted,
        [OCALL_CPUID]           = (void *) sgx_ocall_cpuid,
        [OCALL_OPEN]            = (void *) sgx_ocall_open,
        [OCALL_CLOSE]           = (void *) sgx_ocall_close,
        [OCALL_READ]            = (void *) sgx_ocall_read,
        [OCALL_WRITE]           = (void *) sgx_ocall_write,
        [OCALL_FSTAT]           = (void *) sgx_ocall_fstat,
        [OCALL_FIONREAD]        = (void *) sgx_ocall_fionread,
        [OCALL_FSETNONBLOCK]    = (void *) sgx_ocall_fsetnonblock,
        [OCALL_FCHMOD]          = (void *) sgx_ocall_fchmod,
        [OCALL_FSYNC]           = (void *) sgx_ocall_fsync,
        [OCALL_FTRUNCATE]       = (void *) sgx_ocall_ftruncate,
        [OCALL_MKDIR]           = (void *) sgx_ocall_mkdir,
        [OCALL_GETDENTS]        = (void *) sgx_ocall_getdents,
        [OCALL_WAKE_THREAD]     = (void *) sgx_ocall_wake_thread,
        [OCALL_CREATE_PROCESS]  = (void *) sgx_ocall_create_process,
        [OCALL_FUTEX]           = (void *) sgx_ocall_futex,
        [OCALL_SOCKETPAIR]      = (void *) sgx_ocall_socketpair,
        [OCALL_SOCK_LISTEN]     = (void *) sgx_ocall_sock_listen,
        [OCALL_SOCK_ACCEPT]     = (void *) sgx_ocall_sock_accept,
        [OCALL_SOCK_CONNECT]    = (void *) sgx_ocall_sock_connect,
        [OCALL_SOCK_RECV]       = (void *) sgx_ocall_sock_recv,
        [OCALL_SOCK_SEND]       = (void *) sgx_ocall_sock_send,
        [OCALL_SOCK_RECV_FD]    = (void *) sgx_ocall_sock_recv_fd,
        [OCALL_SOCK_SEND_FD]    = (void *) sgx_ocall_sock_send_fd,
        [OCALL_SOCK_SETOPT]     = (void *) sgx_ocall_sock_setopt,
        [OCALL_SOCK_SHUTDOWN]   = (void *) sgx_ocall_sock_shutdown,
        [OCALL_GETTIME]         = (void *) sgx_ocall_gettime,
        [OCALL_SLEEP]           = (void *) sgx_ocall_sleep,
        [OCALL_POLL]            = (void *) sgx_ocall_poll,
        [OCALL_RENAME]          = (void *) sgx_ocall_rename,
        [OCALL_DELETE]          = (void *) sgx_ocall_delete,
        [OCALL_LOAD_DEBUG]      = (void *) sgx_ocall_load_debug,
    };

#define EDEBUG(code, ms) do {} while (0)

int ecall_enclave_start (const char ** arguments, const char ** environments)
{
    ms_ecall_enclave_start_t ms;
    ms.ms_arguments = arguments;
    ms.ms_environments = environments;
    ms.ms_sec_info = PAL_SEC();
    EDEBUG(ECALL_ENCLAVE_START, &ms);
    return sgx_ecall(ECALL_ENCLAVE_START, &ms);
}

int ecall_thread_start (void)
{
    EDEBUG(ECALL_THREAD_START, NULL);
    return sgx_ecall(ECALL_THREAD_START, NULL);
}

void __abort(void) {
    INLINE_SYSCALL(exit_group, 1, -1);
}
