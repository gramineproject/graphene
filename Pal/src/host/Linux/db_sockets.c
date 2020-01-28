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

/*
 * db_socket.c
 *
 * This file contains operands for streams with URIs that start with
 * "tcp:", "tcp.srv:", "udp:", "udp.srv:".
 */

#include <linux/poll.h>
#include <linux/types.h>

#include "api.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_security.h"
typedef __kernel_pid_t pid_t;
#include <asm/errno.h>
#include <asm/fcntl.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/time.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#ifndef SOL_TCP
#define SOL_TCP 6
#endif

#ifndef TCP_NODELAY
#define TCP_NODELAY 1
#endif

#ifndef TCP_CORK
#define TCP_CORK 3
#endif

/* 96 bytes is the minimal size of buffer to store a IPv4/IPv6
   address */
#define PAL_SOCKADDR_SIZE 96

static size_t addr_size(const struct sockaddr* addr) {
    switch (addr->sa_family) {
        case AF_INET:
            return sizeof(struct sockaddr_in);
        case AF_INET6:
            return sizeof(struct sockaddr_in6);
        default:
            return 0;
    }
}

/* parsing the string of uri, and fill in the socket address structure.
   the latest pointer of uri, length of socket address are returned. */
static int inet_parse_uri(char** uri, struct sockaddr* addr, size_t* addrlen) {
    char* tmp = *uri;
    char* end;
    char* addr_str = NULL;
    char* port_str;
    int af;
    void* addr_buf;
    size_t addr_len;
    __be16* port_buf;
    size_t slen;

    if (tmp[0] == '[') {
        /* for IPv6, the address will be in the form of
           "[xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx]:port". */
        struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)addr;

        slen = sizeof(struct sockaddr_in6);
        memset(addr, 0, slen);

        end = strchr(tmp + 1, ']');
        if (!end || *(end + 1) != ':')
            goto inval;

        addr_str = tmp + 1;
        addr_len = end - tmp - 1;
        port_str = end + 2;
        for (end = port_str; *end >= '0' && *end <= '9'; end++)
            ;
        addr_in6->sin6_family = af = AF_INET6;
        addr_buf                   = &addr_in6->sin6_addr.s6_addr;
        port_buf                   = &addr_in6->sin6_port;
    } else {
        /* for IP, the address will be in the form of "x.x.x.x:port". */
        struct sockaddr_in* addr_in = (struct sockaddr_in*)addr;

        slen = sizeof(struct sockaddr_in);
        memset(addr, 0, slen);

        end = strchr(tmp, ':');
        if (!end)
            goto inval;

        addr_str = tmp;
        addr_len = end - tmp;
        port_str = end + 1;
        for (end = port_str; *end >= '0' && *end <= '9'; end++)
            ;
        addr_in->sin_family = af = AF_INET;
        addr_buf                 = &addr_in->sin_addr.s_addr;
        port_buf                 = &addr_in->sin_port;
    }

    if (af == AF_INET) {
        if (!inet_pton4(addr_str, addr_len, addr_buf))
            goto inval;
    } else {
        if (!inet_pton6(addr_str, addr_len, addr_buf))
            goto inval;
    }

    *port_buf = __htons(atoi(port_str));
    *uri      = *end ? end + 1 : NULL;

    if (addrlen)
        *addrlen = slen;

    return 0;

inval:
    return -PAL_ERROR_INVAL;
}

/* create the string of uri from the given socket address */
static int inet_create_uri(char* uri, size_t count, struct sockaddr* addr, size_t addrlen) {
    size_t len = 0;

    if (addr->sa_family == AF_INET) {
        if (addrlen != sizeof(struct sockaddr_in))
            return -PAL_ERROR_INVAL;

        struct sockaddr_in* addr_in = (struct sockaddr_in*)addr;
        char* addr                  = (char*)&addr_in->sin_addr.s_addr;

        /* for IP, the address will be in the form of "x.x.x.x:port". */
        len = snprintf(uri, count, "%u.%u.%u.%u:%u", (unsigned char)addr[0], (unsigned char)addr[1],
                       (unsigned char)addr[2], (unsigned char)addr[3], __ntohs(addr_in->sin_port));
    } else if (addr->sa_family == AF_INET6) {
        if (addrlen != sizeof(struct sockaddr_in6))
            return -PAL_ERROR_INVAL;

        struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)addr;
        unsigned short* addr          = (unsigned short*)&addr_in6->sin6_addr.s6_addr;

        /* for IPv6, the address will be in the form of
           "[xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx]:port". */
        len = snprintf(uri, count, "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]:%u", addr[0], addr[1],
                       addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                       __ntohs(addr_in6->sin6_port));
    } else {
        return -PAL_ERROR_INVAL;
    }

    if (len >= count)
        return -PAL_ERROR_TOOLONG;

    return len;
}

/* parse the uri for a socket stream. The uri might have both binding
   address and connecting address, or connecting address only. The form
   of uri will be either "bind-addr:bind-port:connect-addr:connect-port"
   or "addr:port". */
static int socket_parse_uri(char* uri, struct sockaddr** bind_addr, size_t* bind_addrlen,
                            struct sockaddr** dest_addr, size_t* dest_addrlen) {
    int ret;

    if (!bind_addr && !dest_addr)
        return 0;

    if (!uri || !(*uri)) {
        if (bind_addr)
            *bind_addr = NULL;
        if (bind_addrlen)
            *bind_addrlen = 0;
        if (dest_addr)
            *dest_addr = NULL;
        if (dest_addrlen)
            *dest_addrlen = 0;
        return 0;
    }

    /* at least parse uri once */
    if ((ret = inet_parse_uri(&uri, bind_addr ? *bind_addr : *dest_addr,
                              bind_addr ? bind_addrlen : dest_addrlen)) < 0)
        return ret;

    if (!(bind_addr && dest_addr))
        return 0;

    /* if you reach here, it can only be connection address */
    if (!uri || (ret = inet_parse_uri(&uri, *dest_addr, dest_addrlen)) < 0) {
        *dest_addr    = *bind_addr;
        *dest_addrlen = *bind_addrlen;
        *bind_addr    = NULL;
        *bind_addrlen = 0;
    }

    return 0;
}

/* fill in the PAL handle based on the file descriptors and address given. */
static inline PAL_HANDLE socket_create_handle(int type, int fd, int options,
                                              struct sockaddr* bind_addr, size_t bind_addrlen,
                                              struct sockaddr* dest_addr, size_t dest_addrlen) {
    PAL_HANDLE hdl =
        malloc(HANDLE_SIZE(sock) + (bind_addr ? bind_addrlen : 0) + (dest_addr ? dest_addrlen : 0));

    if (!hdl)
        return NULL;

    memset(hdl, 0, sizeof(struct pal_handle));
    init_handle_hdr(HANDLE_HDR(hdl), type);
    HANDLE_HDR(hdl)->flags |= RFD(0) | (type != pal_type_tcpsrv ? WFD(0) : 0);
    hdl->sock.fd = fd;
    void* addr   = (void*)hdl + HANDLE_SIZE(sock);
    if (bind_addr) {
        hdl->sock.bind = (PAL_PTR)addr;
        memcpy(addr, bind_addr, bind_addrlen);
        addr += bind_addrlen;
    } else {
        hdl->sock.bind = (PAL_PTR)NULL;
    }
    if (dest_addr) {
        hdl->sock.conn = (PAL_PTR)addr;
        memcpy(addr, dest_addr, dest_addrlen);
        addr += dest_addrlen;
    } else {
        hdl->sock.conn = (PAL_PTR)NULL;
    }

    hdl->sock.nonblocking = (options & PAL_OPTION_NONBLOCK) ? PAL_TRUE : PAL_FALSE;
    hdl->sock.linger      = 0;

    if (type == pal_type_tcpsrv) {
        hdl->sock.receivebuf = 0;
        hdl->sock.sendbuf    = 0;
    } else {
        int ret, val;
        socklen_t len = sizeof(int);

        ret                  = INLINE_SYSCALL(getsockopt, 5, fd, SOL_SOCKET, SO_RCVBUF, &val, &len);
        hdl->sock.receivebuf = IS_ERR(ret) ? 0 : val;

        ret               = INLINE_SYSCALL(getsockopt, 5, fd, SOL_SOCKET, SO_SNDBUF, &val, &len);
        hdl->sock.sendbuf = IS_ERR(ret) ? 0 : val;
    }

    hdl->sock.receivetimeout = 0;
    hdl->sock.sendtimeout    = 0;
    hdl->sock.tcp_cork       = PAL_FALSE;
    hdl->sock.tcp_keepalive  = PAL_FALSE;
    hdl->sock.tcp_nodelay    = PAL_FALSE;
    return hdl;
}

static bool check_zero(void* mem, size_t size) {
    void* p = mem;
    void* q = mem + size;

    while (p < q) {
        if (p <= q - sizeof(long)) {
            if (*(long*)p)
                return false;
            p += sizeof(long);
        } else if (p <= q - sizeof(int)) {
            if (*(int*)p)
                return false;
            p += sizeof(int);
        } else if (p <= q - sizeof(short)) {
            if (*(short*)p)
                return false;
            p += sizeof(short);
        } else {
            if (*(char*)p)
                return false;
            p++;
        }
    }

    return true;
}

/* check if an address is "Any" */
static bool check_any_addr(struct sockaddr* addr) {
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in* addr_in = (struct sockaddr_in*)addr;

        return addr_in->sin_port == 0 && check_zero(&addr_in->sin_addr, sizeof(addr_in->sin_addr));
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)addr;

        return addr_in6->sin6_port == 0 &&
               check_zero(&addr_in6->sin6_addr, sizeof(addr_in6->sin6_addr));
    }

    return false;
}

/* listen on a tcp socket */
static int tcp_listen(PAL_HANDLE* handle, char* uri, int create, int options) {
    struct sockaddr buffer;
    struct sockaddr* bind_addr = &buffer;
    size_t bind_addrlen;
    int ret, fd = -1;

    if ((ret = socket_parse_uri(uri, &bind_addr, &bind_addrlen, NULL, NULL)) < 0)
        return ret;

    assert(bind_addr);
    assert(bind_addrlen == addr_size(bind_addr));

#if ALLOW_BIND_ANY == 0
    /* the socket need to have a binding address, a null address or an
       any address is not allowed */
    if (check_any_addr(bind_addr))
        return -PAL_ERROR_INVAL;
#endif

    fd = INLINE_SYSCALL(socket, 3, bind_addr->sa_family, SOCK_STREAM | SOCK_CLOEXEC | options, 0);

    if (IS_ERR(fd))
        return -PAL_ERROR_DENIED;

    /* must set the socket to be reuseable */
    int reuseaddr = 1;
    ret = INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));
    if (IS_ERR(ret))
        return -PAL_ERROR_INVAL;

    if (bind_addr->sa_family == AF_INET6) {
        /* IPV6_V6ONLY socket option can only be set before first bind */
        int ipv6_v6only = create & PAL_CREATE_DUALSTACK ? 0 : 1;
        ret = INLINE_SYSCALL(setsockopt, 5, fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_v6only, sizeof(ipv6_v6only));
        if (IS_ERR(ret))
            return -PAL_ERROR_INVAL;
    }

    ret = INLINE_SYSCALL(bind, 3, fd, bind_addr, bind_addrlen);

    if (IS_ERR(ret)) {
        switch (ERRNO(ret)) {
            case EINVAL:
                ret = -PAL_ERROR_INVAL;
                goto failed;
            case EADDRINUSE:
                ret = -PAL_ERROR_STREAMEXIST;
                goto failed;
            default:
                ret = -PAL_ERROR_DENIED;
                goto failed;
        }
    }

    if (check_any_addr(bind_addr)) {
        /* call getsockname to get socket address */
        if ((ret = INLINE_SYSCALL(getsockname, 3, fd, bind_addr, &bind_addrlen)) < 0)
            goto failed;
    }

    ret = INLINE_SYSCALL(listen, 2, fd, DEFAULT_BACKLOG);
    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    *handle = socket_create_handle(pal_type_tcpsrv, fd, options, bind_addr, bind_addrlen, NULL, 0);
    if (!(*handle)) {
        ret = -PAL_ERROR_NOMEM;
        goto failed;
    }

    return 0;

failed:
    INLINE_SYSCALL(close, 1, fd);
    return ret;
}

/* accept a tcp connection */
static int tcp_accept(PAL_HANDLE handle, PAL_HANDLE* client) {
    if (!IS_HANDLE_TYPE(handle, tcpsrv) || !handle->sock.bind || handle->sock.conn)
        return -PAL_ERROR_NOTSERVER;

    if (handle->sock.fd == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    struct sockaddr* bind_addr = (struct sockaddr*)handle->sock.bind;
    size_t bind_addrlen        = addr_size(bind_addr);
    struct sockaddr buffer;
    socklen_t addrlen = sizeof(struct sockaddr);
    int ret           = 0;

    int newfd = INLINE_SYSCALL(accept4, 4, handle->sock.fd, &buffer, &addrlen, O_CLOEXEC);

    if (IS_ERR(newfd))
        switch (ERRNO(newfd)) {
            case EWOULDBLOCK:
                return -PAL_ERROR_TRYAGAIN;
            case ECONNABORTED:
                return -PAL_ERROR_STREAMNOTEXIST;
            default:
                return unix_to_pal_error(ERRNO(newfd));
        }

    struct sockaddr* dest_addr = &buffer;
    size_t dest_addrlen        = addrlen;

    *client = socket_create_handle(pal_type_tcp, newfd, 0, bind_addr, bind_addrlen, dest_addr,
                                   dest_addrlen);

    if (!(*client)) {
        ret = -PAL_ERROR_NOMEM;
        goto failed;
    }

    return 0;

failed:
    INLINE_SYSCALL(close, 1, newfd);
    return ret;
}

/* connect on a tcp socket */
static int tcp_connect(PAL_HANDLE* handle, char* uri, int options) {
    struct sockaddr buffer[3];
    struct sockaddr* bind_addr = buffer;
    struct sockaddr* dest_addr = buffer + 1;
    size_t bind_addrlen, dest_addrlen;
    int ret, fd = -1;

    /* accepting two kind of different uri:
       dest-ip:dest-port or bind-ip:bind-port:dest-ip:dest-port */
    if ((ret = socket_parse_uri(uri, &bind_addr, &bind_addrlen, &dest_addr, &dest_addrlen)) < 0)
        return ret;

    if (!dest_addr)
        return -PAL_ERROR_INVAL;

    if (bind_addr && bind_addr->sa_family != dest_addr->sa_family)
        return -PAL_ERROR_INVAL;

    fd = INLINE_SYSCALL(socket, 3, dest_addr->sa_family, SOCK_STREAM | SOCK_CLOEXEC | options, 0);
    if (IS_ERR(fd))
        return -PAL_ERROR_DENIED;

    if (bind_addr) {
        if (IS_ERR(ret)) {
            INLINE_SYSCALL(close, 1, fd);
            switch (ERRNO(ret)) {
                case EADDRINUSE:
                    ret = -PAL_ERROR_STREAMEXIST;
                    goto failed;
                case EADDRNOTAVAIL:
                    ret = -PAL_ERROR_ADDRNOTEXIST;
                    goto failed;
                default:
                    ret = unix_to_pal_error(ERRNO(ret));
                    goto failed;
            }
        }
    }

    ret = INLINE_SYSCALL(connect, 3, fd, dest_addr, dest_addrlen);

    if (IS_ERR(ret) && ERRNO(ret) == EINPROGRESS) {
        struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
        ret               = INLINE_SYSCALL(ppoll, 5, &pfd, 1, NULL, NULL, 0);
    }

    if (IS_ERR(ret)) {
        ret = unix_to_pal_error(ERRNO(ret));
        goto failed;
    }

    if (!bind_addr) {
        /* save some space to get socket address */
        bind_addr    = buffer + 2;
        bind_addrlen = sizeof(struct sockaddr);

        /* call getsockname to get socket address */
        if ((ret = INLINE_SYSCALL(getsockname, 3, fd, bind_addr, &bind_addrlen)) < 0)
            bind_addr = NULL;
    }

    *handle = socket_create_handle(pal_type_tcp, fd, options, bind_addr, bind_addrlen, dest_addr,
                                   dest_addrlen);

    if (!(*handle)) {
        ret = -PAL_ERROR_NOMEM;
        goto failed;
    }

    return 0;

failed:
    INLINE_SYSCALL(close, 1, fd);
    return ret;
}

/* 'open' operation of tcp stream */
static int tcp_open(PAL_HANDLE* handle, const char* type, const char* uri, int access, int share,
                    int create, int options) {
    if (!WITHIN_MASK(access, PAL_ACCESS_MASK) || !WITHIN_MASK(share, PAL_SHARE_MASK) ||
        !WITHIN_MASK(create, PAL_CREATE_MASK))
        return -PAL_ERROR_INVAL;

    size_t uri_len = strlen(uri) + 1;

    if (uri_len > PAL_SOCKADDR_SIZE)
        return -PAL_ERROR_TOOLONG;

    char uri_buf[PAL_SOCKADDR_SIZE];
    memcpy(uri_buf, uri, uri_len);

    if (!strcmp_static(type, URI_TYPE_TCP_SRV))
        return tcp_listen(handle, uri_buf, create, options);

    if (!strcmp_static(type, URI_TYPE_TCP))
        return tcp_connect(handle, uri_buf, options);

    return -PAL_ERROR_NOTSUPPORT;
}

/* 'read' operation of tcp stream */
static int64_t tcp_read(PAL_HANDLE handle, uint64_t offset, size_t len, void* buf) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (!IS_HANDLE_TYPE(handle, tcp) || !handle->sock.conn)
        return -PAL_ERROR_NOTCONNECTION;

    if (handle->sock.fd == PAL_IDX_POISON)
        return -PAL_ERROR_ENDOFSTREAM;

    struct msghdr hdr;
    struct iovec iov;
    iov.iov_base       = buf;
    iov.iov_len        = len;
    hdr.msg_name       = NULL;
    hdr.msg_namelen    = 0;
    hdr.msg_iov        = &iov;
    hdr.msg_iovlen     = 1;
    hdr.msg_control    = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags      = 0;

    int64_t bytes = INLINE_SYSCALL(recvmsg, 3, handle->sock.fd, &hdr, 0);

    if (IS_ERR(bytes))
        return unix_to_pal_error(ERRNO(bytes));

    if (!bytes)
        return -PAL_ERROR_ENDOFSTREAM;

    return bytes;
}

/* write' operation of tcp stream */
static int64_t tcp_write(PAL_HANDLE handle, uint64_t offset, size_t len, const void* buf) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (!IS_HANDLE_TYPE(handle, tcp) || !handle->sock.conn)
        return -PAL_ERROR_NOTCONNECTION;

    if (handle->sock.fd == PAL_IDX_POISON)
        return -PAL_ERROR_CONNFAILED;

    struct msghdr hdr;
    struct iovec iov;
    iov.iov_base       = (void*)buf;
    iov.iov_len        = len;
    hdr.msg_name       = NULL;
    hdr.msg_namelen    = 0;
    hdr.msg_iov        = &iov;
    hdr.msg_iovlen     = 1;
    hdr.msg_control    = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags      = 0;

    int64_t bytes = INLINE_SYSCALL(sendmsg, 3, handle->sock.fd, &hdr, MSG_NOSIGNAL);
    if (IS_ERR(bytes))
        bytes = unix_to_pal_error(ERRNO(bytes));

    return bytes;
}

/* used by 'open' operation of tcp stream for bound socket */
static int udp_bind(PAL_HANDLE* handle, char* uri, int create, int options) {
    struct sockaddr buffer;
    struct sockaddr* bind_addr = &buffer;
    size_t bind_addrlen;
    int ret = 0, fd = -1;

    if ((ret = socket_parse_uri(uri, &bind_addr, &bind_addrlen, NULL, NULL)) < 0)
        return ret;

    assert(bind_addr);
    assert(bind_addrlen == addr_size(bind_addr));

#if ALLOW_BIND_ANY == 0
    /* the socket need to have a binding address, a null address or an
       any address is not allowed */
    if (check_any_addr(bind_addr))
        return -PAL_ERROR_INVAL;
#endif

    fd = INLINE_SYSCALL(socket, 3, bind_addr->sa_family, SOCK_DGRAM | SOCK_CLOEXEC | options, 0);

    if (IS_ERR(fd))
        return -PAL_ERROR_DENIED;

    /* IPV6_V6ONLY socket option can only be set before first bind */
    if (bind_addr->sa_family == AF_INET6) {
        int ipv6_v6only = create & PAL_CREATE_DUALSTACK ? 0 : 1;
        ret = INLINE_SYSCALL(setsockopt, 5, fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_v6only, sizeof(ipv6_v6only));
        if (IS_ERR(ret))
            return -PAL_ERROR_INVAL;
    }

    ret = INLINE_SYSCALL(bind, 3, fd, bind_addr, bind_addrlen);

    if (IS_ERR(ret)) {
        switch (ERRNO(ret)) {
            case EADDRINUSE:
                ret = -PAL_ERROR_STREAMEXIST;
                goto failed;
            case EADDRNOTAVAIL:
                ret = -PAL_ERROR_ADDRNOTEXIST;
                goto failed;
            default:
                ret = unix_to_pal_error(ERRNO(ret));
                goto failed;
        }
    }

    *handle = socket_create_handle(pal_type_udpsrv, fd, options, bind_addr, bind_addrlen, NULL, 0);

    if (!(*handle)) {
        ret = -ENOMEM;
        goto failed;
    }

    return 0;

failed:
    INLINE_SYSCALL(close, 1, fd);
    return ret;
}

/* used by 'open' operation of tcp stream for connected socket */
static int udp_connect(PAL_HANDLE* handle, char* uri, int create, int options) {
    struct sockaddr buffer[2];
    struct sockaddr* bind_addr = buffer;
    struct sockaddr* dest_addr = buffer + 1;
    size_t bind_addrlen, dest_addrlen;
    int ret, fd = -1;

    if ((ret = socket_parse_uri(uri, &bind_addr, &bind_addrlen, &dest_addr, &dest_addrlen)) < 0)
        return ret;

#if ALLOW_BIND_ANY == 0
    /* the socket need to have a binding address, a null address or an
       any address is not allowed */
    if (bind_addr && check_any_addr(bind_addr))
        return -PAL_ERROR_INVAL;
#endif

    fd = INLINE_SYSCALL(socket, 3, dest_addr ? dest_addr->sa_family : AF_INET,
                        SOCK_DGRAM | SOCK_CLOEXEC | options, 0);

    if (IS_ERR(fd))
        return -PAL_ERROR_DENIED;

    if (bind_addr) {
        if (bind_addr->sa_family == AF_INET6) {
            /* IPV6_V6ONLY socket option can only be set before first bind */
            int ipv6_v6only = create & PAL_CREATE_DUALSTACK ? 0 : 1;
            ret = INLINE_SYSCALL(setsockopt, 5, fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_v6only,
                                 sizeof(ipv6_v6only));
            if (IS_ERR(ret))
                return -PAL_ERROR_INVAL;
        }

        ret = INLINE_SYSCALL(bind, 3, fd, bind_addr, bind_addrlen);

        if (IS_ERR(ret)) {
            switch (ERRNO(ret)) {
                case EADDRINUSE:
                    ret = -PAL_ERROR_STREAMEXIST;
                    goto failed;
                case EADDRNOTAVAIL:
                    ret = -PAL_ERROR_ADDRNOTEXIST;
                    goto failed;
                default:
                    ret = unix_to_pal_error(ERRNO(ret));
                    goto failed;
            }
        }
    }

    *handle = socket_create_handle(dest_addr ? pal_type_udp : pal_type_udpsrv, fd, options,
                                   bind_addr, bind_addrlen, dest_addr, dest_addrlen);

    if (!(*handle)) {
        ret = -ENOMEM;
        goto failed;
    }

    return 0;

failed:
    INLINE_SYSCALL(close, 1, fd);
    return ret;
}

static int udp_open(PAL_HANDLE* hdl, const char* type, const char* uri, int access, int share,
                    int create, int options) {
    if (!WITHIN_MASK(access, PAL_ACCESS_MASK) || !WITHIN_MASK(share, PAL_SHARE_MASK) ||
        !WITHIN_MASK(create, PAL_CREATE_MASK) || !WITHIN_MASK(options, PAL_OPTION_MASK))
        return -PAL_ERROR_INVAL;

    char buf[PAL_SOCKADDR_SIZE];
    size_t len = strlen(uri);

    if (len >= PAL_SOCKADDR_SIZE)
        return -PAL_ERROR_TOOLONG;

    memcpy(buf, uri, len + 1);

    if (!strcmp_static(type, URI_TYPE_UDP_SRV))
        return udp_bind(hdl, buf, create, options);

    if (!strcmp_static(type, URI_TYPE_UDP))
        return udp_connect(hdl, buf, create, options);

    return -PAL_ERROR_NOTSUPPORT;
}

static int64_t udp_receive(PAL_HANDLE handle, uint64_t offset, size_t len, void* buf) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (!IS_HANDLE_TYPE(handle, udp))
        return -PAL_ERROR_NOTCONNECTION;

    if (handle->sock.fd == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    struct msghdr hdr;
    struct iovec iov;
    iov.iov_base       = buf;
    iov.iov_len        = len;
    hdr.msg_name       = NULL;
    hdr.msg_namelen    = 0;
    hdr.msg_iov        = &iov;
    hdr.msg_iovlen     = 1;
    hdr.msg_control    = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags      = 0;

    int64_t bytes = INLINE_SYSCALL(recvmsg, 3, handle->sock.fd, &hdr, 0);

    if (IS_ERR(bytes))
        return unix_to_pal_error(ERRNO(bytes));

    return bytes;
}

static int64_t udp_receivebyaddr(PAL_HANDLE handle, uint64_t offset, size_t len, void* buf,
                                 char* addr, size_t addrlen) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (!IS_HANDLE_TYPE(handle, udpsrv))
        return -PAL_ERROR_NOTCONNECTION;

    if (handle->sock.fd == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    struct sockaddr conn_addr;
    socklen_t conn_addrlen = sizeof(struct sockaddr);

    struct msghdr hdr;
    struct iovec iov;
    iov.iov_base       = buf;
    iov.iov_len        = len;
    hdr.msg_name       = &conn_addr;
    hdr.msg_namelen    = conn_addrlen;
    hdr.msg_iov        = &iov;
    hdr.msg_iovlen     = 1;
    hdr.msg_control    = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags      = 0;

    int64_t bytes = INLINE_SYSCALL(recvmsg, 3, handle->sock.fd, &hdr, 0);

    if (IS_ERR(bytes))
        return unix_to_pal_error(ERRNO(bytes));

    char* addr_uri = strcpy_static(addr, URI_PREFIX_UDP, addrlen);
    if (!addr_uri)
        return -PAL_ERROR_OVERFLOW;

    int ret = inet_create_uri(addr_uri, addr + addrlen - addr_uri, &conn_addr, hdr.msg_namelen);
    if (ret < 0)
        return ret;

    return bytes;
}

static int64_t udp_send(PAL_HANDLE handle, uint64_t offset, size_t len, const void* buf) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (!IS_HANDLE_TYPE(handle, udp))
        return -PAL_ERROR_NOTCONNECTION;

    if (handle->sock.fd == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    struct msghdr hdr;
    struct iovec iov;
    iov.iov_base       = (void*)buf;
    iov.iov_len        = len;
    hdr.msg_name       = (void*)handle->sock.conn;
    hdr.msg_namelen    = addr_size((struct sockaddr*)handle->sock.conn);
    hdr.msg_iov        = &iov;
    hdr.msg_iovlen     = 1;
    hdr.msg_control    = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags      = 0;

    int64_t bytes = INLINE_SYSCALL(sendmsg, 3, handle->sock.fd, &hdr, MSG_NOSIGNAL);
    if (IS_ERR(bytes))
        bytes = unix_to_pal_error(ERRNO(bytes));

    return bytes;
}

static int64_t udp_sendbyaddr(PAL_HANDLE handle, uint64_t offset, size_t len, const void* buf,
                              const char* addr, size_t addrlen) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (!IS_HANDLE_TYPE(handle, udpsrv))
        return -PAL_ERROR_NOTCONNECTION;

    if (handle->sock.fd == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    if (!strstartswith_static(addr, URI_PREFIX_UDP))
        return -PAL_ERROR_INVAL;

    addr += static_strlen(URI_PREFIX_UDP);
    addrlen -= static_strlen(URI_PREFIX_UDP);

    char* addrbuf = __alloca(addrlen);
    memcpy(addrbuf, addr, addrlen);

    struct sockaddr conn_addr;
    size_t conn_addrlen;

    int ret = inet_parse_uri(&addrbuf, &conn_addr, &conn_addrlen);
    if (ret < 0)
        return ret;

    struct msghdr hdr;
    struct iovec iov;
    iov.iov_base       = (void*)buf;
    iov.iov_len        = len;
    hdr.msg_name       = &conn_addr;
    hdr.msg_namelen    = conn_addrlen;
    hdr.msg_iov        = &iov;
    hdr.msg_iovlen     = 1;
    hdr.msg_control    = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags      = 0;

    int64_t bytes = INLINE_SYSCALL(sendmsg, 3, handle->sock.fd, &hdr, MSG_NOSIGNAL);
    if (IS_ERR(bytes))
        bytes = unix_to_pal_error(ERRNO(bytes));

    return bytes;
}

static int socket_delete(PAL_HANDLE handle, int access) {
    if (handle->sock.fd == PAL_IDX_POISON)
        return 0;

    if (!IS_HANDLE_TYPE(handle, tcp) && access)
        return -PAL_ERROR_INVAL;

    if (IS_HANDLE_TYPE(handle, tcp) || IS_HANDLE_TYPE(handle, tcpsrv)) {
        int shutdown;
        switch (access) {
            case 0:
                shutdown = SHUT_RDWR;
                break;
            case PAL_DELETE_RD:
                shutdown = SHUT_RD;
                break;
            case PAL_DELETE_WR:
                shutdown = SHUT_WR;
                break;
            default:
                return -PAL_ERROR_INVAL;
        }

        INLINE_SYSCALL(shutdown, 2, handle->sock.fd, shutdown);
    }

    return 0;
}

struct __kernel_linger {
    int l_onoff;
    int l_linger;
};

static int socket_close(PAL_HANDLE handle) {
    if (handle->sock.fd != PAL_IDX_POISON) {
        INLINE_SYSCALL(close, 1, handle->sock.fd);
        handle->sock.fd = PAL_IDX_POISON;
    }

    if (handle->sock.bind)
        handle->sock.bind = (PAL_PTR)NULL;

    if (handle->sock.conn)
        handle->sock.conn = (PAL_PTR)NULL;

    return 0;
}

static int socket_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    int ret;

    if (handle->sock.fd == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    attr->handle_type           = HANDLE_HDR(handle)->type;
    attr->nonblocking           = handle->sock.nonblocking;
    attr->disconnected          = HANDLE_HDR(handle)->flags & ERROR(0);

    attr->socket.linger         = handle->sock.linger;
    attr->socket.receivebuf     = handle->sock.receivebuf;
    attr->socket.sendbuf        = handle->sock.sendbuf;
    attr->socket.receivetimeout = handle->sock.receivetimeout;
    attr->socket.sendtimeout    = handle->sock.sendtimeout;
    attr->socket.tcp_cork       = handle->sock.tcp_cork;
    attr->socket.tcp_keepalive  = handle->sock.tcp_keepalive;
    attr->socket.tcp_nodelay    = handle->sock.tcp_nodelay;

    /* get number of bytes available for reading (doesn't make sense for listening sockets) */
    attr->pending_size = 0;
    if (!IS_HANDLE_TYPE(handle, tcpsrv)) {
        int val;
        ret = INLINE_SYSCALL(ioctl, 3, handle->sock.fd, FIONREAD, &val);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        attr->pending_size = val;
    }

    /* query if there is data available for reading */
    struct pollfd pfd  = {.fd = handle->sock.fd, .events = POLLIN | POLLOUT, .revents = 0};
    struct timespec tp = {0, 0};
    ret = INLINE_SYSCALL(ppoll, 5, &pfd, 1, &tp, NULL, 0);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    attr->readable = ret == 1 && (pfd.revents & (POLLIN | POLLERR | POLLHUP)) == POLLIN;
    attr->writable = ret == 1 && (pfd.revents & (POLLOUT | POLLERR | POLLHUP)) == POLLOUT;
    return 0;
}

static int socket_attrsetbyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (handle->sock.fd == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    int fd = handle->sock.fd, ret, val;

    if (attr->nonblocking != handle->sock.nonblocking) {
        ret = INLINE_SYSCALL(fcntl, 3, fd, F_SETFL, attr->nonblocking ? O_NONBLOCK : 0);

        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        handle->sock.nonblocking = attr->nonblocking;
    }

    if (IS_HANDLE_TYPE(handle, tcpsrv)) {
        if (attr->socket.linger != handle->sock.linger) {
            struct __kernel_linger l;
            l.l_onoff  = attr->socket.linger ? 1 : 0;
            l.l_linger = attr->socket.linger;
            ret        = INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_LINGER, &l,
                                 sizeof(struct __kernel_linger));

            if (IS_ERR(ret))
                return unix_to_pal_error(ERRNO(ret));

            handle->sock.linger = attr->socket.linger;
        }

        if (attr->socket.receivebuf != handle->sock.receivebuf) {
            int val = attr->socket.receivebuf;
            ret     = INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(int));

            if (IS_ERR(ret))
                return unix_to_pal_error(ERRNO(ret));

            handle->sock.receivebuf = attr->socket.receivebuf;
        }

        if (attr->socket.sendbuf != handle->sock.sendbuf) {
            int val = attr->socket.sendbuf;
            ret     = INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(int));

            if (IS_ERR(ret))
                return unix_to_pal_error(ERRNO(ret));

            handle->sock.sendbuf = attr->socket.sendbuf;
        }

        if (attr->socket.receivetimeout != handle->sock.receivetimeout) {
            int val = attr->socket.receivetimeout;
            ret     = INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_RCVTIMEO, &val, sizeof(int));

            if (IS_ERR(ret))
                return unix_to_pal_error(ERRNO(ret));

            handle->sock.receivetimeout = attr->socket.receivetimeout;
        }

        if (attr->socket.sendtimeout != handle->sock.sendtimeout) {
            int val = attr->socket.sendtimeout;
            ret     = INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_SNDTIMEO, &val, sizeof(int));

            if (IS_ERR(ret))
                return unix_to_pal_error(ERRNO(ret));

            handle->sock.sendtimeout = attr->socket.sendtimeout;
        }
    }

    if (IS_HANDLE_TYPE(handle, tcp) || IS_HANDLE_TYPE(handle, tcpsrv)) {
        if (attr->socket.tcp_cork != handle->sock.tcp_cork) {
            val = attr->socket.tcp_cork ? 1 : 0;
            ret = INLINE_SYSCALL(setsockopt, 5, fd, SOL_TCP, TCP_CORK, &val, sizeof(int));

            if (IS_ERR(ret))
                return unix_to_pal_error(ERRNO(ret));

            handle->sock.tcp_cork = attr->socket.tcp_cork;
        }

        if (attr->socket.tcp_keepalive != handle->sock.tcp_keepalive) {
            val = attr->socket.tcp_keepalive ? 1 : 0;
            ret = INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(int));

            if (IS_ERR(ret))
                return unix_to_pal_error(ERRNO(ret));

            handle->sock.tcp_keepalive = attr->socket.tcp_keepalive;
        }

        if (attr->socket.tcp_nodelay != handle->sock.tcp_nodelay) {
            val = attr->socket.tcp_nodelay ? 1 : 0;
            ret = INLINE_SYSCALL(setsockopt, 5, fd, SOL_TCP, TCP_NODELAY, &val, sizeof(int));

            if (IS_ERR(ret))
                return unix_to_pal_error(ERRNO(ret));

            handle->sock.tcp_nodelay = attr->socket.tcp_nodelay;
        }
    }

    return 0;
}

static int socket_getname(PAL_HANDLE handle, char* buffer, size_t count) {
    size_t orig_count = count;
    int ret;

    const char* prefix = NULL;
    size_t prefix_len = 0;
    struct sockaddr* bind_addr = NULL;
    struct sockaddr* dest_addr = NULL;

    switch (PAL_GET_TYPE(handle)) {
        case pal_type_tcpsrv:
            prefix_len = static_strlen(URI_PREFIX_TCP_SRV);
            prefix = URI_PREFIX_TCP_SRV;
            bind_addr = (struct sockaddr*)handle->sock.bind;
            break;
        case pal_type_tcp:
            prefix_len = static_strlen(URI_PREFIX_TCP);
            prefix = URI_PREFIX_TCP;
            bind_addr = (struct sockaddr*)handle->sock.bind;
            dest_addr = (struct sockaddr*)handle->sock.conn;
            break;
        case pal_type_udpsrv:
            prefix_len = static_strlen(URI_PREFIX_UDP_SRV);
            prefix = URI_PREFIX_UDP_SRV;
            bind_addr = (struct sockaddr*)handle->sock.bind;
            break;
        case pal_type_udp:
            prefix_len = static_strlen(URI_PREFIX_UDP);
            prefix = URI_PREFIX_UDP;
            bind_addr = (struct sockaddr*)handle->sock.bind;
            dest_addr = (struct sockaddr*)handle->sock.conn;
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    if (count < prefix_len + 1) {
        return -PAL_ERROR_OVERFLOW;
    }

    memcpy(buffer, prefix, prefix_len + 1);
    buffer += prefix_len;
    count -= prefix_len;

    if (bind_addr) {
        if ((ret = inet_create_uri(buffer, count, bind_addr, addr_size(bind_addr))) < 0) {
            return ret;
        }

        buffer += ret;
        count -= ret;
    }

    if (dest_addr) {
        if (bind_addr) {
            if (count < 2) {
                return -PAL_ERROR_OVERFLOW;
            }

            *buffer++ = ':';
            *buffer = '\0';
            count--;
        }

        if ((ret = inet_create_uri(buffer, count, dest_addr, addr_size(dest_addr))) < 0) {
            return ret;
        }

        buffer += ret;
        count -= ret;
    }

    return orig_count - count;
}

struct handle_ops tcp_ops = {
    .getname        = &socket_getname,
    .open           = &tcp_open,
    .waitforclient  = &tcp_accept,
    .read           = &tcp_read,
    .write          = &tcp_write,
    .delete         = &socket_delete,
    .close          = &socket_close,
    .attrquerybyhdl = &socket_attrquerybyhdl,
    .attrsetbyhdl   = &socket_attrsetbyhdl,
};

struct handle_ops udp_ops = {
    .getname        = &socket_getname,
    .open           = &udp_open,
    .read           = &udp_receive,
    .write          = &udp_send,
    .delete         = &socket_delete,
    .close          = &socket_close,
    .attrquerybyhdl = &socket_attrquerybyhdl,
    .attrsetbyhdl   = &socket_attrsetbyhdl,
};

struct handle_ops udpsrv_ops = {
    .getname        = &socket_getname,
    .open           = &udp_open,
    .readbyaddr     = &udp_receivebyaddr,
    .writebyaddr    = &udp_sendbyaddr,
    .delete         = &socket_delete,
    .close          = &socket_close,
    .attrquerybyhdl = &socket_attrquerybyhdl,
    .attrsetbyhdl   = &socket_attrsetbyhdl,
};
