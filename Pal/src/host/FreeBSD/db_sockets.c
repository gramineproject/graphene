/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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

#include "pal_defs.h"
#include "pal_freebsd_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_freebsd.h"
#include "pal_debug.h"
#include "pal_security.h"
#include "pal_error.h"
#include "api.h"

#include <sys/types.h>
#include <poll.h>
typedef __kernel_pid_t pid_t;
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <sys/filio.h>

/* 96 bytes is the minimal size of buffer to store a IPv4/IPv6
   address */
#define PAL_SOCKADDR_SIZE   96

typedef uint16_t __be16;

#define SOL_TCP			6
#define TCP_CORK	TCP_NOPUSH

static inline int addr_size (struct sockaddr * addr)
{
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
static int inet_parse_uri (char ** uri, struct sockaddr * addr, int * addrlen)
{
    char * tmp = *uri, * end;
    char * addr_str = NULL, * port_str;
    int af;
    void * addr_buf;
    int addr_len;
    __be16 * port_buf;
    int slen;

    if (tmp[0] == '[') {
        /* for IPv6, the address will be in the form of
           "[xx:xx:xx:xx:xx:xx:xx:xx]:port". */
        struct sockaddr_in6 * addr_in6 = (struct sockaddr_in6 *) addr;

        slen = sizeof(struct sockaddr_in6);
        memset(addr, 0, slen);

        end = strchr(tmp + 1, ']');
        if (!end || *(end + 1) != ':')
            goto inval;

        addr_str = tmp + 1;
        addr_len = end - tmp + 1;
        port_str = end + 2;
        for (end = port_str ; *end >= '0' && *end <= '9' ; end++);
        addr_in6->sin6_family = af = AF_INET6;
        addr_buf = &addr_in6->sin6_addr.s6_addr;
        port_buf = &addr_in6->sin6_port;
    } else {
        /* for IP, the address will be in the form of "x.x.x.x:port". */
        struct sockaddr_in * addr_in = (struct sockaddr_in *) addr;

        slen = sizeof(struct sockaddr_in);
        memset(addr, 0, slen);

        end = strchr(tmp, ':');
        if (!end)
            goto inval;

        addr_str = tmp;
        addr_len = end - tmp;
        port_str = end + 1;
        for (end = port_str ; *end >= '0' && *end <= '9' ; end++);
        addr_in->sin_family = af = AF_INET;
        addr_buf = &addr_in->sin_addr.s_addr;
        port_buf = &addr_in->sin_port;
    }

    if (af == AF_INET) {
        if (inet_pton4(addr_str, addr_len, addr_buf) < 0)
            goto inval;
    } else {
        if (inet_pton6(addr_str, addr_len, addr_buf) < 0)
            goto inval;
    }

    *port_buf = __htons(atoi(port_str));
    *uri = *end ? end + 1 : NULL;

    if (addrlen)
        *addrlen = slen;

    return 0;

inval:
    return -PAL_ERROR_INVAL;
}

/* create the string of uri from the given socket address */
static int inet_create_uri (char * uri, int count, struct sockaddr * addr,
                            int addrlen)
{
    int len = 0;

    if (addr->sa_family == AF_INET) {
        if (addrlen != sizeof(struct sockaddr_in))
            return PAL_ERROR_INVAL;

        struct sockaddr_in * addr_in = (struct sockaddr_in *) addr;
        char * addr = (char *) &addr_in->sin_addr.s_addr;

        /* for IP, the address will be in the form of "x.x.x.x:port". */
        len = snprintf(uri, count, "%u.%u.%u.%u:%u",
                       (unsigned char) addr[0],
                       (unsigned char) addr[1],
                       (unsigned char) addr[2],
                       (unsigned char) addr[3],
                       __ntohs(addr_in->sin_port));
    } else if (addr->sa_family == AF_INET6) {
        if (addrlen != sizeof(struct sockaddr_in6))
            return PAL_ERROR_INVAL;

        struct sockaddr_in6 * addr_in6 = (struct sockaddr_in6 *) addr;
        short * addr = (short *) &addr_in6->sin6_addr.s6_addr;

        /* for IPv6, the address will be in the form of
           "[xx:xx:xx:xx:xx:xx:xx:xx]:port". */
        len = snprintf(uri, count, "[%x:%x:%x:%x:%x:%x:%x:%x]:%u",
                       addr[0], addr[1], addr[2], addr[3],
                       addr[4], addr[5], addr[6], addr[7],
                       __ntohs(addr_in6->sin6_port));
    } else {
        return -PAL_ERROR_INVAL;
    }

    return len;
}

/* parse the uri for a socket stream. The uri might have both binding
   address and connecting address, or connecting address only. The form
   of uri will be either "bind-addr:bind-port:connect-addr:connect-port"
   or "addr:port". */
static int socket_parse_uri (char * uri,
                             struct sockaddr ** bind_addr, int * bind_addrlen,
                             struct sockaddr ** dest_addr, int * dest_addrlen)
{
    int ret;

    if (!bind_addr && !dest_addr)
        return 0;

    if (!uri || !(*uri)) {
        if (bind_addr)
            *bind_addr = NULL;
        if (dest_addr)
            *dest_addr = NULL;
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
        *dest_addr = *bind_addr;
        *dest_addrlen = *bind_addrlen;
        *bind_addr = NULL;
        *bind_addrlen = 0;
    }

    return 0;
}

/* fill in the PAL handle based on the file descriptors and address given. */
static inline
PAL_HANDLE socket_create_handle (int type, int fd, int options,
                                 struct sockaddr * bind_addr, int bind_addrlen,
                                 struct sockaddr * dest_addr, int dest_addrlen)
{
    PAL_HANDLE hdl = malloc(HANDLE_SIZE(sock) + (bind_addr ? bind_addrlen : 0) +
                            (dest_addr ? dest_addrlen : 0));

    if (!hdl)
        return NULL;

    options = HOST_SOCKET_OPTIONS(options);

    memset(hdl, 0, sizeof(union pal_handle));
    PAL_GET_TYPE(hdl) = type;
    hdl->__in.flags |= RFD(0)|(type != pal_type_tcpsrv ? WFD(0) : 0);
    hdl->sock.fd = fd;
    void * addr = (void *) hdl + HANDLE_SIZE(sock);
    if (bind_addr) {
        hdl->sock.bind = addr;
        memcpy(addr, bind_addr, bind_addrlen);
        addr += bind_addrlen;
    } else {
        hdl->sock.bind = NULL;
    }
    if (dest_addr) {
        hdl->sock.conn = addr;
        memcpy(addr, dest_addr, dest_addrlen);
        addr += dest_addrlen;
    } else {
        hdl->sock.conn = NULL;
    }

    hdl->sock.nonblocking   = (options & SOCK_NONBLOCK) ?
                              PAL_TRUE : PAL_FALSE;

    hdl->sock.linger        = 0;

    if (type == pal_type_tcpsrv) {
        hdl->sock.receivebuf     = 0;
        hdl->sock.sendbuf        = 0;
    } else {
        int ret, val, len = sizeof(int);

        ret = INLINE_SYSCALL(getsockopt, 5, fd, SOL_SOCKET, SO_RCVBUF,
                             &val, &len);
        hdl->sock.receivebuf = IS_ERR(ret) ? 0 : val;

        ret = INLINE_SYSCALL(getsockopt, 5, fd, SOL_SOCKET, SO_SNDBUF,
                             &val, &len);
        hdl->sock.sendbuf = IS_ERR(ret) ? 0 : val;
    }

    hdl->sock.receivetimeout = 0;
    hdl->sock.sendtimeout    = 0;
    hdl->sock.tcp_cork       = PAL_FALSE;
    hdl->sock.tcp_keepalive  = PAL_FALSE;
    hdl->sock.tcp_nodelay    = PAL_FALSE;
    return hdl;
}

#if ALLOW_BIND_ANY == 0
static bool check_zero (void * mem, size_t size)
{
    void * p = mem, * q = mem + size;

    while (p < q) {
        if (p <= q - sizeof(long)) {
            if (*(long *) p)
                return false;
            p += sizeof(long);
        } else if (p <= q - sizeof(int)) {
            if (*(int *) p)
                return false;
            p += sizeof(int);
        } else if (p <= q - sizeof(short)) {
            if (*(short *) p)
                return false;
            p += sizeof(short);
        } else {
            if (*(char *) p)
                return false;
            p++;
        }
    }

    return true;
}

/* check if an address is "Any" */
static bool check_any_addr (struct sockaddr * addr)
{
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in * addr_in =
                        (struct sockaddr_in *) addr;

        return addr_in->sin_port == 0 &&
               check_zero(&addr_in->sin_addr,
                          sizeof(addr_in->sin_addr));
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 * addr_in6 =
                        (struct sockaddr_in6 *) addr;

        return addr_in6->sin6_port == 0 &&
               check_zero(&addr_in6->sin6_addr,
                          sizeof(addr_in6->sin6_addr));
    }

    return false;
}
#endif

/* listen on a tcp socket */
static int tcp_listen (PAL_HANDLE * handle, char * uri, int options)
{
    struct sockaddr buffer, * bind_addr = &buffer;
    int bind_addrlen;
    int ret, fd = -1;

    if ((ret = socket_parse_uri(uri, &bind_addr, &bind_addrlen,
                                NULL, NULL)) < 0)
        return ret;

#if ALLOW_BIND_ANY == 0
    /* the socket need to have a binding address, a null address or an
       any address is not allowed */
    if (addr_check_any(bind_addr))
       return -PAL_ERROR_INVAL;
#endif

    options = HOST_SOCKET_OPTIONS(options);
    /* the socket need to have a binding address, a null address or an
       any address is not allowed */
    if (!bind_addr || addr_check_any(bind_addr) == 0)
        return -PAL_ERROR_INVAL;

    fd = INLINE_SYSCALL(socket, 3, bind_addr->sa_family,
                        SOCK_STREAM|SOCK_CLOEXEC|options, 0);

    if (IS_ERR(fd))
        return -PAL_ERROR_DENIED;

    /* must set the socket to be reuseable */
    int reuseaddr = 1;
    INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr,
                   sizeof(int)); // maybe SO_REUSEPORT

    ret = INLINE_SYSCALL(bind, 3, fd, bind_addr, bind_addrlen);

    if (IS_ERR(ret)) {
        switch(ERRNO(ret)) {
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

    ret = INLINE_SYSCALL(listen, 2, fd, DEFAULT_BACKLOG);
    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    *handle = socket_create_handle(pal_type_tcpsrv, fd, options,
                                   bind_addr, bind_addrlen, NULL, 0);
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
static int tcp_accept (PAL_HANDLE handle, PAL_HANDLE * client)
{
    if (!IS_HANDLE_TYPE(handle, tcpsrv) ||
        !handle->sock.bind || handle->sock.conn)
        return -PAL_ERROR_NOTSERVER;

    if (handle->sock.fd == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    struct sockaddr * bind_addr = (struct sockaddr *) handle->sock.bind;
    int bind_addrlen = addr_size(bind_addr);
    struct sockaddr buffer;
    socklen_t addrlen = sizeof(struct sockaddr);
    int ret = 0;

    int newfd = INLINE_SYSCALL(accept4, 4, handle->sock.fd, &buffer,
                               &addrlen, SOCK_CLOEXEC);

    if (IS_ERR(newfd))
        switch(ERRNO(newfd)) {
            case EWOULDBLOCK:
                return -PAL_ERROR_TRYAGAIN;
            case ECONNABORTED:
                return -PAL_ERROR_STREAMNOTEXIST;
            default:
                return unix_to_pal_error(ERRNO(newfd));
        }

    struct sockaddr * dest_addr = &buffer;
    int dest_addrlen = addrlen;

    *client = socket_create_handle(pal_type_tcp, newfd, 0,
                                   bind_addr, bind_addrlen,
                                   dest_addr, dest_addrlen);

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
static int tcp_connect (PAL_HANDLE * handle, char * uri, int options)
{
    struct sockaddr buffer[3];
    struct sockaddr * bind_addr = buffer, * dest_addr = buffer + 1;
    int bind_addrlen, dest_addrlen;
    int ret, fd = -1;

    options = HOST_SOCKET_OPTIONS(options);
	
    /* accepting two kind of different uri:
       dest-ip:dest-port or bind-ip:bind-port:dest-ip:dest-port */
    if ((ret = socket_parse_uri(uri, &bind_addr, &bind_addrlen,
                                &dest_addr, &dest_addrlen)) < 0)
        return ret;

    if (!dest_addr)
        return -PAL_ERROR_INVAL;

    if (bind_addr && bind_addr->sa_family != dest_addr->sa_family)
        return -PAL_ERROR_INVAL;

#if ALLOW_BIND_ANY == 0
    /* the socket need to have a binding address, a null address or an
       any address is not allowed */
    if (bind_addr && addr_check_any(bind_addr))
       return -PAL_ERROR_INVAL;
#endif

    fd = INLINE_SYSCALL(socket, 3, dest_addr->sa_family,
                        SOCK_STREAM|SOCK_CLOEXEC|options, 0);
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

    if (IS_ERR(ret)) {
        ret = unix_to_pal_error(ERRNO(ret));
        goto failed;
    }

    if (!bind_addr) {
        /* save some space to get socket address */
        bind_addr = buffer + 2;
        bind_addrlen = sizeof(struct sockaddr);

        /* call getsockname to get socket address */
        if ((ret = INLINE_SYSCALL(getsockname, 3, fd,
                                  bind_addr, &bind_addrlen)) < 0)
            bind_addr = NULL;
    }

    *handle = socket_create_handle(pal_type_tcp, fd, options,
                                   bind_addr, bind_addrlen,
                                   dest_addr, dest_addrlen);

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
static int tcp_open (PAL_HANDLE *handle, const char * type, const char * uri,
                     int access, int share, int create, int options)
{
    int uri_len = strlen(uri) + 1;

    if (uri_len > PAL_SOCKADDR_SIZE)
        return -PAL_ERROR_TOOLONG;

    char uri_buf[PAL_SOCKADDR_SIZE];
    memcpy(uri_buf, uri, uri_len);

    if (strpartcmp_static(type, "tcp.srv:"))
        return tcp_listen(handle, uri_buf, options);

    if (strpartcmp_static(type, "tcp:"))
        return tcp_connect(handle, uri_buf, options);

    return -PAL_ERROR_NOTSUPPORT;
}

/* 'read' operation of tcp stream */
static int tcp_read (PAL_HANDLE handle, int offset, int len, void * buf)
{
    if (!IS_HANDLE_TYPE(handle, tcp) || !handle->sock.conn)
        return -PAL_ERROR_NOTCONNECTION;

    if (handle->sock.fd == PAL_IDX_POISON)
        return -PAL_ERROR_ENDOFSTREAM;

    struct msghdr hdr;
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = len;
    hdr.msg_name = NULL;
    hdr.msg_namelen = 0;
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags = 0;

    int bytes = INLINE_SYSCALL(recvmsg, 3, handle->sock.fd, &hdr, 0);

    if (IS_ERR(bytes))
        switch (ERRNO(bytes)) {
            case EWOULDBLOCK:
                return -PAL_ERROR_TRYAGAIN;
            default:
                return unix_to_pal_error(ERRNO(bytes));
        }

    if (!bytes)
        return -PAL_ERROR_ENDOFSTREAM;

    return bytes;
}

/* write' operation of tcp stream */
static int tcp_write (PAL_HANDLE handle, int offset, int len, const void * buf)
{
    if (!IS_HANDLE_TYPE(handle, tcp) || !handle->sock.conn)
        return -PAL_ERROR_NOTCONNECTION;

    if (handle->sock.fd == PAL_IDX_POISON)
        return -PAL_ERROR_CONNFAILED;

    struct msghdr hdr;
    struct iovec iov;
    iov.iov_base = (void *) buf;
    iov.iov_len = len;
    hdr.msg_name = NULL;
    hdr.msg_namelen = 0;
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags = 0;
    
    int bytes = INLINE_SYSCALL(sendmsg, 3, handle->sock.fd, &hdr, MSG_NOSIGNAL);

    if (IS_ERR(bytes))
        switch(ERRNO(bytes)) {
            case ECONNRESET:
            case EPIPE:
                return -PAL_ERROR_CONNFAILED;
            case EWOULDBLOCK:
                handle->__in.flags &= ~WRITEABLE(0);
                return -PAL_ERROR_TRYAGAIN;
            default:
                return unix_to_pal_error(ERRNO(bytes));
        }

    if (bytes == len)
        handle->__in.flags |= WRITEABLE(0);
    else
        handle->__in.flags &= ~WRITEABLE(0);

    return bytes;
}

/* used by 'open' operation of tcp stream for bound socket */
static int udp_bind (PAL_HANDLE * handle, char * uri, int options)
{
    struct sockaddr buffer, * bind_addr = &buffer;
    int bind_addrlen;
    int ret = 0, fd = -1;

    if ((ret = socket_parse_uri(uri, &bind_addr, &bind_addrlen,
                                NULL, NULL)) < 0)
        return ret;

    assert(bind_addr);
    assert(bind_addrlen == addr_size(bind_addr));

#if ALLOW_BIND_ANY == 0
    /* the socket need to have a binding address, a null address or an
       any address is not allowed */
    if (addr_check_any(bind_addr))
       return -PAL_ERROR_INVAL;
#endif

    options = HOST_SOCKET_OPTIONS(options);
    fd = INLINE_SYSCALL(socket, 3, bind_addr->sa_family,
                        SOCK_DGRAM|SOCK_CLOEXEC|options, 0);

    if (IS_ERR(fd))
        return -PAL_ERROR_DENIED;

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

    *handle = socket_create_handle(pal_type_udpsrv, fd, options,
                                   bind_addr, bind_addrlen, NULL, 0);

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
static int udp_connect (PAL_HANDLE * handle, char * uri, int options)
{
    struct sockaddr buffer[2];
    struct sockaddr * bind_addr = buffer, * dest_addr = buffer + 1;
    int bind_addrlen, dest_addrlen;
    int ret, fd = -1;

    if ((ret = socket_parse_uri(uri, &bind_addr, &bind_addrlen,
                                &dest_addr, &dest_addrlen)) < 0)
        return ret;

#if ALLOW_BIND_ANY == 0
    /* the socket need to have a binding address, a null address or an
       any address is not allowed */
    if (bind_addr && addr_check_any(bind_addr))
       return -PAL_ERROR_INVAL;
#endif

    options = HOST_SOCKET_OPTIONS(options);
	
    fd = INLINE_SYSCALL(socket, 3, dest_addr ? dest_addr->sa_family : AF_INET,
                        SOCK_DGRAM|SOCK_CLOEXEC|options, 0);

    if (IS_ERR(fd))
        return -PAL_ERROR_DENIED;

    if (bind_addr) {
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

    *handle = socket_create_handle(dest_addr ? pal_type_udp : pal_type_udpsrv,
                                   fd, options,
                                   bind_addr, bind_addrlen,
                                   dest_addr, dest_addrlen);

    if (!(*handle)) {
        ret = -ENOMEM;
        goto failed;
    }

    return 0;

failed:
    INLINE_SYSCALL(close, 1, fd);
    return ret;
}

static int udp_open (PAL_HANDLE *hdl, const char * type, const char * uri,
                     int access, int share, int create, int options)
{
    char buf[PAL_SOCKADDR_SIZE];
    int len = strlen(uri);

    if (len >= PAL_SOCKADDR_SIZE)
        return -PAL_ERROR_TOOLONG;

    memcpy(buf, uri, len + 1);
    options &= PAL_OPTION_MASK;

    if (!strpartcmp_static(type, "udp.srv:"))
        return udp_bind(hdl, buf, options);

    if (!strpartcmp_static(type, "udp:"))
        return udp_connect(hdl, buf, options);

    return -PAL_ERROR_NOTSUPPORT;
}

static int udp_receive (PAL_HANDLE handle, int offset, int len, void * buf)
{
    if (!IS_HANDLE_TYPE(handle, udp))
        return -PAL_ERROR_NOTCONNECTION;

    if (handle->sock.fd == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    struct msghdr hdr;
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = len;
    hdr.msg_name = NULL;
    hdr.msg_namelen = 0;
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags = 0;

    int bytes = INLINE_SYSCALL(recvmsg, 3, handle->sock.fd, &hdr, 0);

    if (IS_ERR(bytes))
        switch(ERRNO(bytes)) {
            case EWOULDBLOCK:
                return -PAL_ERROR_TRYAGAIN;
            case EINTR:
                return -PAL_ERROR_INTERRUPTED;
            default:
                return unix_to_pal_error(ERRNO(bytes));
        }

    return bytes;
}

static int udp_receivebyaddr (PAL_HANDLE handle, int offset, int len,
                              void * buf, char * addr, int addrlen)
{
    if (!IS_HANDLE_TYPE(handle, udpsrv))
        return -PAL_ERROR_NOTCONNECTION;

    if (handle->sock.fd == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    struct sockaddr conn_addr;
    socklen_t conn_addrlen = sizeof(struct sockaddr);

    struct msghdr hdr;
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = len;
    hdr.msg_name = &conn_addr;
    hdr.msg_namelen = conn_addrlen;
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags = 0;

    int bytes = INLINE_SYSCALL(recvmsg, 3, handle->sock.fd, &hdr, 0);

    if (IS_ERR(bytes))
        switch(ERRNO(bytes)) {
            case EWOULDBLOCK:
                return -PAL_ERROR_TRYAGAIN;
            case EINTR:
                return -PAL_ERROR_INTERRUPTED;
            case ECONNREFUSED:
                return -PAL_ERROR_STREAMNOTEXIST;
            default:
                return unix_to_pal_error(ERRNO(bytes));
        }

    char * tmp = strcpy_static(addr, "udp:", addrlen);
    if (!tmp)
        return -PAL_ERROR_OVERFLOW;

    inet_create_uri(tmp, addr + addrlen - tmp, &conn_addr, hdr.msg_namelen);

    return bytes;
}

static int udp_send (PAL_HANDLE handle, int offset, int len, const void * buf)
{
    if (!IS_HANDLE_TYPE(handle, udp))
        return -PAL_ERROR_NOTCONNECTION;

    if (handle->sock.fd == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    struct msghdr hdr;
    struct iovec iov;
    iov.iov_base = (void *) buf;
    iov.iov_len = len;
    hdr.msg_name = handle->sock.conn;
    hdr.msg_namelen = addr_size(handle->sock.conn);
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags = 0;

    int bytes = INLINE_SYSCALL(sendmsg, 3, handle->sock.fd, &hdr, MSG_NOSIGNAL);

    if (IS_ERR(bytes))
        switch(ERRNO(bytes)) {
            case EAGAIN:
                handle->__in.flags &= ~WRITEABLE(0);
                return -PAL_ERROR_TRYAGAIN;
            case ECONNRESET:
            case EPIPE:
                return -PAL_ERROR_CONNFAILED;
            default:
                return unix_to_pal_error(ERRNO(bytes));
        }

    if (bytes == len)
        handle->__in.flags |= WRITEABLE(0);
    else
        handle->__in.flags &= ~WRITEABLE(0);

    return bytes;
}

static int udp_sendbyaddr (PAL_HANDLE handle, int offset, int len,
                           const void * buf, const char * addr, int addrlen)
{
    if (!IS_HANDLE_TYPE(handle, udpsrv))
        return -PAL_ERROR_NOTCONNECTION;

    if (handle->sock.fd == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    if (strpartcmp_static(addr, "udp:"))
        return -PAL_ERROR_INVAL;

    addr += static_strlen("udp:");
    addrlen -= static_strlen("udp:");
    char * addrbuf = __alloca(addrlen + 1);
    memcpy(addrbuf, addr, addrlen + 1);

    struct sockaddr conn_addr;
    int conn_addrlen;

    int ret = inet_parse_uri(&addrbuf, &conn_addr, &conn_addrlen);
    if (ret < 0)
        return ret;

    struct msghdr hdr;
    struct iovec iov;
    iov.iov_base = (void *) buf;
    iov.iov_len = len;
    hdr.msg_name = &conn_addr;
    hdr.msg_namelen = conn_addrlen;
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags = 0;

    int bytes = INLINE_SYSCALL(sendmsg, 3, handle->sock.fd, &hdr, MSG_NOSIGNAL);

    if (IS_ERR(bytes))
        switch(ERRNO(bytes)) {
            case ECONNRESET:
            case EPIPE:
                return -PAL_ERROR_CONNFAILED;
            case EAGAIN:
                handle->__in.flags &= ~WRITEABLE(0);
            default:
                return unix_to_pal_error(ERRNO(bytes));
        }

    if (bytes == len)
        handle->__in.flags |= WRITEABLE(0);
    else
        handle->__in.flags &= ~WRITEABLE(0);

    return bytes;
}

static int socket_delete (PAL_HANDLE handle, int access)
{
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

static int socket_close (PAL_HANDLE handle)
{
    if (handle->sock.fd != PAL_IDX_POISON) {
        INLINE_SYSCALL(close, 1, handle->sock.fd);
        handle->sock.fd = PAL_IDX_POISON;
    }

    if (handle->sock.bind)
        handle->sock.bind = NULL;

    if (handle->sock.conn)
        handle->sock.conn = NULL;

    return 0;
}

static int socket_attrquerybyhdl (PAL_HANDLE handle, PAL_STREAM_ATTR  * attr)
{
    if (handle->sock.fd == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    int fd = handle->sock.fd, ret, val;

    if (handle->sock.conn) {
        /* try use ioctl FIONEAD to get the size of socket */
        ret = INLINE_SYSCALL(ioctl, 3, fd, FIONREAD, &val);
		
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        attr->pending_size = val;
        attr->readable = !!attr->pending_size > 0;
    } else {
        attr->readable = !attr->disconnected;
    }

    attr->handle_type           = handle->__in.type;
    attr->disconnected          = handle->__in.flags & ERROR(0);
    attr->nonblocking           = handle->sock.nonblocking;
    attr->writeable             = handle->__in.flags & WRITEABLE(0);
    attr->socket.linger         = handle->sock.linger;
    attr->socket.receivebuf     = handle->sock.receivebuf;
    attr->socket.sendbuf        = handle->sock.sendbuf;
    attr->socket.receivetimeout = handle->sock.receivetimeout;
    attr->socket.sendtimeout    = handle->sock.sendtimeout;
    attr->socket.tcp_cork       = handle->sock.tcp_cork;
    attr->socket.tcp_keepalive  = handle->sock.tcp_keepalive;
    attr->socket.tcp_nodelay    = handle->sock.tcp_nodelay;
    return 0;
}

static int socket_attrsetbyhdl (PAL_HANDLE handle, PAL_STREAM_ATTR  * attr)
{
    if (handle->sock.fd == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    int fd = handle->sock.fd, ret, val;

    if (attr->nonblocking != handle->sock.nonblocking) {
        ret = INLINE_SYSCALL(fcntl, 3, fd, F_SETFL,
                             attr->nonblocking ? O_NONBLOCK : 0);

        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        handle->sock.nonblocking = attr->nonblocking;
    }

    if (IS_HANDLE_TYPE(handle, tcpsrv)) {

        struct __kernel_linger {
            int l_onoff;
            int l_linger;
        };

        if (attr->socket.linger != handle->sock.linger) {

            struct __kernel_linger l;
            l.l_onoff = attr->socket.linger ? 1 : 0;
            l.l_linger = attr->socket.linger;
            ret = INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_LINGER,
                                 &l, sizeof(struct __kernel_linger));

            if (IS_ERR(ret))
                return unix_to_pal_error(ERRNO(ret));

            handle->sock.linger = attr->socket.linger;
        }

        if (attr->socket.receivebuf != handle->sock.receivebuf) {
            int val = attr->socket.receivebuf;
            ret = INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_RCVBUF,
                                 &val, sizeof(int));

            if (IS_ERR(ret))
                return unix_to_pal_error(ERRNO(ret));

            handle->sock.receivebuf = attr->socket.receivebuf;
        }

        if (attr->socket.sendbuf != handle->sock.sendbuf) {
            int val = attr->socket.sendbuf;
            ret = INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_SNDBUF,
                                 &val, sizeof(int));

            if (IS_ERR(ret))
                return unix_to_pal_error(ERRNO(ret));

            handle->sock.sendbuf = attr->socket.sendbuf;
        }

        if (attr->socket.receivetimeout != handle->sock.receivetimeout) {
            int val = attr->socket.receivetimeout;
            ret = INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_RCVTIMEO,
                                 &val, sizeof(int));

            if (IS_ERR(ret))
                return unix_to_pal_error(ERRNO(ret));

            handle->sock.receivetimeout = attr->socket.receivetimeout;
        }

        if (attr->socket.sendtimeout != handle->sock.sendtimeout) {
            int val = attr->socket.sendtimeout;
            ret = INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_SNDTIMEO,
                                 &val, sizeof(int));

            if (IS_ERR(ret))
                return unix_to_pal_error(ERRNO(ret));

            handle->sock.sendtimeout = attr->socket.sendtimeout;
        }
    }

    if (IS_HANDLE_TYPE(handle, tcp) || IS_HANDLE_TYPE(handle, tcpsrv)) {

        if (attr->socket.tcp_cork != handle->sock.tcp_cork) {
            val = attr->socket.tcp_cork ? 1 : 0;
            ret = INLINE_SYSCALL(setsockopt, 5, fd, SOL_TCP, TCP_CORK,
                                 &val, sizeof(int));

            if (IS_ERR(ret))
                return unix_to_pal_error(ERRNO(ret));

            handle->sock.tcp_cork = attr->socket.tcp_cork;
        }

        if (attr->socket.tcp_keepalive != handle->sock.tcp_keepalive) {
            val = attr->socket.tcp_keepalive ? 1 : 0;
            ret = INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_KEEPALIVE,
                                 &val, sizeof(int));

            if (IS_ERR(ret))
                return unix_to_pal_error(ERRNO(ret));

            handle->sock.tcp_keepalive = attr->socket.tcp_keepalive;
        }

        if (attr->socket.tcp_nodelay != handle->sock.tcp_nodelay) {
            val = attr->socket.tcp_nodelay ? 1 : 0;
            ret = INLINE_SYSCALL(setsockopt, 5, fd, SOL_TCP, TCP_NODELAY,
                                 &val, sizeof(int));

            if (IS_ERR(ret))
                return unix_to_pal_error(ERRNO(ret));

            handle->sock.tcp_nodelay = attr->socket.tcp_nodelay;
        }
    }

    return 0;
}
static int socket_getname (PAL_HANDLE handle, char * buffer, int count)
{
    int old_count = count;
    int ret;

    const char * prefix = NULL;
    int prefix_len = 0;
    struct sockaddr * bind_addr = NULL, * dest_addr = NULL;

    switch (PAL_GET_TYPE(handle)) {
        case pal_type_tcpsrv:
            prefix_len = 7;
            prefix = "tcp.srv";
            bind_addr = handle->sock.bind;
            break;
        case pal_type_tcp:
            prefix_len = 3;
            prefix = "tcp";
            bind_addr = handle->sock.bind;
            dest_addr = handle->sock.conn;
            break;
        case pal_type_udpsrv:
            prefix_len = 7;
            prefix = "udp.srv";
            bind_addr = handle->sock.bind;
            break;
        case pal_type_udp:
            prefix_len = 3;
            prefix = "udp";
            bind_addr = handle->sock.bind;
            dest_addr = handle->sock.conn;
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    if (prefix_len >= count)
        return -PAL_ERROR_OVERFLOW;

    memcpy(buffer, prefix, prefix_len + 1);
    buffer += prefix_len;
    count -= prefix_len;

    for (int i = 0 ; i < 2 ; i++) {
        struct sockaddr * addr = i ? dest_addr : bind_addr;
        if (addr) {
            if (count <= 1)
                return -PAL_ERROR_OVERFLOW;

            buffer[0] = ':';
            buffer[1] = 0;
            buffer++;
            count--;

            if ((ret = inet_create_uri(buffer, count, addr,
                                       addr_size(addr))) < 0)
                return ret;

            buffer += ret;
            count -= ret;
        }
    }

    return old_count - count;
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

static int mcast_s (PAL_HANDLE handle, int port)
{
    handle->mcast.srv = PAL_IDX_POISON;
    int ret = 0;

    int fd = INLINE_SYSCALL(socket, 3, AF_INET, SOCK_DGRAM, 0);

    if (IS_ERR(fd))
        return -PAL_ERROR_DENIED;

    struct in_addr local;
    local.s_addr  = INADDR_ANY;
    ret = INLINE_SYSCALL(setsockopt, 5, fd, IPPROTO_IP, IP_MULTICAST_IF,
                         &local, sizeof(local));
    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    handle->__in.flags |= WFD(1)|WRITEABLE(1);
    handle->mcast.srv = fd;
    return 0;
}

static int mcast_c (PAL_HANDLE handle, int port)
{
    handle->mcast.cli = PAL_IDX_POISON;
    int ret = 0;

    int fd = INLINE_SYSCALL(socket, 3, AF_INET, SOCK_DGRAM, 0);

    if (IS_ERR(fd))
        return -PAL_ERROR_DENIED;

    int reuse = 1;
    INLINE_SYSCALL(setsockopt, 5, fd, SOL_SOCKET, SO_REUSEPORT,
                   &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    ret = INLINE_SYSCALL(bind, 3, fd, &addr, sizeof(addr));

    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    struct in_addr local;
    local.s_addr = INADDR_ANY;
    ret = INLINE_SYSCALL(setsockopt, 5, fd, IPPROTO_IP, IP_MULTICAST_IF,
                         &local, sizeof(local));
    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    struct ip_mreq group;
    inet_pton4(GRAPHENE_MCAST_GROUP, sizeof(GRAPHENE_MCAST_GROUP) - 1,
               &group.imr_multiaddr.s_addr);
    group.imr_interface.s_addr = htonl(INADDR_ANY);
    ret = INLINE_SYSCALL(setsockopt, 5, fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &group, sizeof(group));
    if (IS_ERR(ret))
        return -PAL_ERROR_DENIED;

    handle->mcast.cli = fd;
    handle->mcast.nonblocking = PAL_FALSE;
    return 0;
}

PAL_HANDLE _DkBroadcastStreamOpen (void)
{
    if (!pal_sec.mcast_port) {
        unsigned short mcast_port;
        _DkFastRandomBitsRead(&mcast_port, sizeof(unsigned short));
        if (mcast_port < 1024)
            mcast_port += 1024;
        pal_sec.mcast_port = mcast_port > 1024 ? mcast_port : mcast_port + 1204;
    }

    PAL_HANDLE hdl = malloc(HANDLE_SIZE(mcast));
    SET_HANDLE_TYPE(hdl, mcast);
    mcast_s(hdl, pal_sec.mcast_port);
    mcast_c(hdl, pal_sec.mcast_port);
    hdl->mcast.port = pal_sec.mcast_port;
    return hdl;
}

static int mcast_send (PAL_HANDLE handle, int offset, int size,
                       const void * buf)
{
    if (handle->mcast.srv == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    inet_pton4(GRAPHENE_MCAST_GROUP, sizeof(GRAPHENE_MCAST_GROUP) - 1,
               &addr.sin_addr.s_addr);
    addr.sin_port = htons(handle->mcast.port);

    struct msghdr hdr;
    struct iovec iov;
    iov.iov_base = (void *) buf;
    iov.iov_len = size;
    hdr.msg_name = &addr;
    hdr.msg_namelen = sizeof(addr);
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags = 0;

    int bytes = INLINE_SYSCALL(sendmsg, 3, handle->mcast.srv, &hdr,
                               MSG_NOSIGNAL);

    if (IS_ERR(bytes))
        switch(ERRNO(bytes)) {
            case ECONNRESET:
            case EPIPE:
                return -PAL_ERROR_CONNFAILED;
            case EAGAIN:
                handle->__in.flags &= ~WRITEABLE(1);
            default:
                return unix_to_pal_error(ERRNO(bytes));
        }

    if (bytes == size)
        handle->__in.flags |= WRITEABLE(1);
    else
        handle->__in.flags &= ~WRITEABLE(1);

    return bytes;
}

static int mcast_receive (PAL_HANDLE handle, int offset, int size, void * buf)
{
    if (handle->mcast.cli == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    struct msghdr hdr;
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = size;
    hdr.msg_name = NULL;
    hdr.msg_namelen = 0;
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = NULL;
    hdr.msg_controllen = 0;
    hdr.msg_flags = 0;

    int bytes = INLINE_SYSCALL(recvmsg, 3, handle->mcast.cli, &hdr, 0);

    if (IS_ERR(bytes))
        return -PAL_ERROR_DENIED;

    return bytes;
}

static int mcast_close (PAL_HANDLE handle)
{
    if (handle->mcast.srv != PAL_IDX_POISON) {
        INLINE_SYSCALL(close, 1, handle->mcast.srv);
        handle->mcast.srv = PAL_IDX_POISON;
    }
    if (handle->mcast.cli != PAL_IDX_POISON) {
        INLINE_SYSCALL(close, 1, handle->mcast.cli);
        handle->mcast.cli = PAL_IDX_POISON;
    }
    return 0;
}

static int mcast_attrquerybyhdl (PAL_HANDLE handle, PAL_STREAM_ATTR * attr)
{
    int ret, val;

    if (handle->mcast.cli == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;
    ret = INLINE_SYSCALL(ioctl, 3, handle->mcast.cli, FIONREAD, &val);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    attr->handle_type  = pal_type_mcast;
    attr->disconnected = handle->__in.flags & (ERROR(0)|ERROR(1));
    attr->nonblocking  = handle->mcast.nonblocking;
    attr->readable     = !!val;
    attr->writeable    = handle->__in.flags & WRITEABLE(1);
    attr->runnable     = PAL_FALSE;
    attr->pending_size = val;
    return 0;
}

static int mcast_attrsetbyhdl (PAL_HANDLE handle, PAL_STREAM_ATTR * attr)
{
    if (handle->mcast.cli == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    int ret;
    PAL_BOL * nonblocking = &handle->mcast.nonblocking;

    if (attr->nonblocking != *nonblocking) {
        ret = INLINE_SYSCALL(fcntl, 3, handle->mcast.cli, F_SETFL,
                             *nonblocking ? O_NONBLOCK : 0);

        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        *nonblocking = attr->nonblocking;
    }

    return 0;
}

struct handle_ops mcast_ops = {
        .write              = &mcast_send,
        .read               = &mcast_receive,
        .close              = &mcast_close,
        .attrquerybyhdl     = &mcast_attrquerybyhdl,
        .attrsetbyhdl       = &mcast_attrsetbyhdl,
    };
