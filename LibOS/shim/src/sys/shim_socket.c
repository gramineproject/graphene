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
 * shim_socket.c
 *
 * Implementation of system call "socket", "bind", "accept4", "listen",
 * "connect", "sendto", "recvfrom", "sendmsg", "recvmsg" and "shutdown" and
 * "getsockname", "getpeername".
 */

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_handle.h>
#include <shim_fs.h>
#include <shim_utils.h>
#include <shim_checkpoint.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>

#include <linux/fcntl.h>
#include <linux/in.h>
#include <linux/in6.h>

#include <asm/socket.h>

/*
 * User-settable options (used with setsockopt).
 */
#define TCP_NODELAY         1   /* Don't delay send to coalesce packets  */
#define TCP_MAXSEG          2   /* Set maximum segment size  */
#define TCP_CORK            3   /* Control sending of partial frames  */
#define TCP_KEEPIDLE        4   /* Start keeplives after this period */
#define TCP_KEEPINTVL       5   /* Interval between keepalives */
#define TCP_KEEPCNT         6   /* Number of keepalives before death */
#define TCP_SYNCNT          7   /* Number of SYN retransmits */
#define TCP_LINGER2         8   /* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT    9   /* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP    10  /* Bound advertised window */
#define TCP_INFO            11  /* Information about this connection. */
#define TCP_QUICKACK        12  /* Bock/reenable quick ACKs.  */
#define TCP_CONGESTION      13  /* Congestion control algorithm.  */
#define TCP_MD5SIG          14  /* TCP MD5 Signature (RFC2385) */

#define AF_UNSPEC       0

#define SOCK_URI_SIZE   108

static int rebase_on_lo __attribute_migratable = -1;

static int minimal_addrlen (int domain)
{
    switch(domain) {
        case AF_INET:
            return sizeof(struct sockaddr_in);
        case AF_INET6:
            return sizeof(struct sockaddr_in6);
        default:
            return sizeof(struct sockaddr);
    }
}

static int init_port_rebase (void)
{
    if (rebase_on_lo != -1)
        return 0;

    char cfg[CONFIG_MAX];
    int rebase = 0;

    if (!root_config ||
        get_config(root_config, "net.port.rebase_on_lo", cfg, CONFIG_MAX) <= 0) {
        rebase_on_lo = 0;
        return 0;
    }

    for (const char * p = cfg ; *p ; p++) {
        if (*p < '0' || *p > '9' || rebase > 32767) {
            rebase_on_lo = 0;
            return 0;
        }
        rebase = rebase * 10 + (*p - '0');
    }

    rebase_on_lo = rebase;
    return 0;
}

static int inet_parse_addr (int domain, int type, const char * uri,
                            struct addr_inet * bind,
                            struct addr_inet * conn);

static int __process_pending_options (struct shim_handle * hdl);

int shim_do_socket (int family, int type, int protocol)
{
    struct shim_handle * hdl = get_new_handle();
    if (!hdl)
        return -ENOMEM;

    struct shim_sock_handle * sock = &hdl->info.sock;
    hdl->type = TYPE_SOCK;
    set_handle_fs(hdl, &socket_builtin_fs);
    hdl->flags = type & SOCK_NONBLOCK ? O_NONBLOCK : 0;
    hdl->acc_mode = 0;
    sock->domain    = family;
    sock->sock_type = type & ~(SOCK_NONBLOCK|SOCK_CLOEXEC);
    sock->protocol  = protocol;

    int ret = -ENOSYS;

    switch (sock->domain) {
        case AF_UNIX:             //Local communication
        case AF_INET:             //IPv4 Internet protocols          ip(7)
        case AF_INET6:            //IPv6 Internet protocols
            break;

        default:
            debug("shim_socket: unknown socket domain %d\n",
                  sock->domain);
            goto err;
    }

    switch (sock->sock_type) {
        case SOCK_STREAM:         //TCP
            break;
        case SOCK_DGRAM:          //UDP
            hdl->acc_mode = MAY_READ|MAY_WRITE;
            break;

        default:
            debug("shim_socket: unknown socket type %d\n",
                  sock->sock_type);
            goto err;
    }

    sock->sock_state = SOCK_CREATED;
    ret = set_new_fd_handle(hdl, type & SOCK_CLOEXEC ? FD_CLOEXEC : 0, NULL);
err:
    put_handle(hdl);
    return ret;
}

static int unix_create_uri (char * uri, int count, enum shim_sock_state state,
                            unsigned int pipeid)
{
    int bytes = 0;

    switch (state) {
        case SOCK_CREATED:
        case SOCK_BOUNDCONNECTED:
        case SOCK_SHUTDOWN:
            return -ENOTCONN;

        case SOCK_BOUND:
        case SOCK_LISTENED:
        case SOCK_ACCEPTED:
            bytes = snprintf(uri, count, "pipe.srv:%u", pipeid);
            break;

        case SOCK_CONNECTED:
            bytes = snprintf(uri, count, "pipe:%u", pipeid);
            break;

        default:
            return -ENOTCONN;
    }

    return bytes == count ? -ENAMETOOLONG : bytes;
}

static void inet_rebase_port (bool reverse, int domain, struct addr_inet * addr,
                              bool local)
{
    init_port_rebase();

    if (rebase_on_lo) {
        if (domain == AF_INET) {
            unsigned char * ad = (unsigned char *) &addr->addr.v4.s_addr;
            if (!local && memcmp(ad, "\177\0\0\1", 4))
                return;
        }

        if (domain == AF_INET6) {
            unsigned short * ad = (void *) &addr->addr.v6.s6_addr;
            if (!local && memcmp(ad, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1", 16))
                return;
        }
    }

    if (reverse)
        addr->port = addr->ext_port - rebase_on_lo;
    else
        addr->ext_port = addr->port + rebase_on_lo;
}

static int inet_translate_addr (int domain, char * uri, int count,
                                struct addr_inet * addr)
{
    if (domain == AF_INET) {
        unsigned char * ad = (unsigned char *) &addr->addr.v4.s_addr;
        int bytes = snprintf(uri, count, "%u.%u.%u.%u:%u",
                             ad[0], ad[1], ad[2], ad[3],
                             addr->ext_port);
        return bytes == count ? -ENAMETOOLONG : bytes;
    }

    if (domain == AF_INET6) {
        unsigned short * ad = (void *) &addr->addr.v6.s6_addr;
        int bytes = snprintf(uri, count,
                             "[%04x:%04x:%x:%04x:%04x:%04x:%04x:%04x]:%u",
                             __ntohs(ad[0]), __ntohs(ad[1]),
                             __ntohs(ad[2]), __ntohs(ad[3]),
                             __ntohs(ad[4]), __ntohs(ad[5]),
                             __ntohs(ad[6]), __ntohs(ad[7]),
                             addr->ext_port);
        return bytes == count ? -ENAMETOOLONG : bytes;
    }

    return -EPROTONOSUPPORT;
}

static int inet_create_uri (int domain, char * uri, int count, int sock_type,
                            enum shim_sock_state state,
                            struct addr_inet * bind, struct addr_inet * conn)
{
    int bytes = 0, ret;

    if (sock_type == SOCK_STREAM) {
        switch (state) {
            case SOCK_CREATED:
            case SOCK_SHUTDOWN:
                return -ENOTCONN;

            case SOCK_BOUND:
            case SOCK_LISTENED:
                if (count < 9)
                    return -ENAMETOOLONG;
                memcpy(uri, "tcp.srv:", 9);
                ret = inet_translate_addr(domain, uri + 8, count - 8, bind);
                return ret < 0 ? ret : ret + 8;

            case SOCK_BOUNDCONNECTED:
                if (count < 5)
                    return -ENAMETOOLONG;
                memcpy(uri, "tcp:", 5);
                bytes = 4;
                ret = inet_translate_addr(domain, uri + bytes, count - bytes,
                                          bind);
                if (ret < 0)
                    return ret;
                uri[bytes + ret] = ':';
                bytes += ret + 1;
                ret = inet_translate_addr(domain, uri + bytes, count - bytes,
                                          conn);
                return ret < 0 ? ret : ret + bytes;

            case SOCK_CONNECTED:
            case SOCK_ACCEPTED:
                if (count < 5)
                    return -ENAMETOOLONG;
                memcpy(uri, "tcp:", 5);
                ret = inet_translate_addr(domain, uri + 4, count - 4, conn);
                return ret < 0 ? ret : ret + 4;
        }
    }

    if (sock_type == SOCK_DGRAM) {
        switch (state) {
            case SOCK_CREATED:
            case SOCK_SHUTDOWN:
                return -ENOTCONN;

            case SOCK_LISTENED:
            case SOCK_ACCEPTED:
                return -EOPNOTSUPP;

            case SOCK_BOUNDCONNECTED:
                if (count < 9)
                    return -ENAMETOOLONG;
                memcpy(uri, "tcp.srv:", 9);
                bytes = 8;
                ret = inet_translate_addr(domain, uri + bytes, count - bytes,
                                          bind);
                if (ret < 0)
                    return ret;
                uri[bytes + ret] = ':';
                bytes += ret + 1;
                ret = inet_translate_addr(domain, uri + bytes, count - bytes,
                                          conn);
                return ret < 0 ? ret : ret + bytes;

            case SOCK_BOUND:
                if (count < 9)
                    return -ENAMETOOLONG;
                memcpy(uri, "udp.srv:", 9);
                ret = inet_translate_addr(domain, uri + 8, count - 8, bind);
                return ret < 0 ? ret : ret + 9;

            case SOCK_CONNECTED:
                if (count < 5)
                    return -ENAMETOOLONG;
                memcpy(uri, "udp:", 5);
                ret = inet_translate_addr(domain, uri + 4, count - 4, conn);
                return ret < 0 ? ret : ret + 4;
        }
    }

    return -EPROTONOSUPPORT;
}

static inline void unix_copy_addr (struct sockaddr * saddr,
                                   struct shim_dentry * dent)
{
    struct sockaddr_un * un = (struct sockaddr_un *) saddr;
    un->sun_family = AF_UNIX;
    int size;
    const char * path = dentry_get_path(dent, true, &size);
    memcpy(un->sun_path, path, size + 1);
}

static int inet_check_addr (int domain, struct sockaddr * addr, int addrlen)
{
    if (domain == AF_INET) {
        if (addr->sa_family != AF_INET)
            return -EAFNOSUPPORT;
        if (addrlen != sizeof(struct sockaddr_in))
            return -EINVAL;
        return 0;
    }

    if (domain == AF_INET6) {
        if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
            return -EAFNOSUPPORT;
        if (addrlen != minimal_addrlen(addr->sa_family))
            return -EINVAL;
        return 0;
    }

    return -EINVAL;
}

static int inet_copy_addr (int domain, struct sockaddr * saddr,
                           const struct addr_inet * addr)
{
    if (domain == AF_INET) {
        struct sockaddr_in * in = (struct sockaddr_in *) saddr;
        in->sin_family = AF_INET;
        in->sin_port = __htons(addr->port);
        in->sin_addr = addr->addr.v4;
        return sizeof(struct sockaddr_in);
    }

    if (domain == AF_INET6) {
        struct sockaddr_in6 * in6 = (struct sockaddr_in6 *) saddr;
        in6->sin6_family = AF_INET6;
        in6->sin6_port = __htons(addr->port);
        in6->sin6_addr = addr->addr.v6;
        return sizeof(struct sockaddr_in6);
    }

    return sizeof(struct sockaddr);
}

static void inet_save_addr (int domain, struct addr_inet * addr,
                            const struct sockaddr * saddr)
{
    if (domain == AF_INET) {
        const struct sockaddr_in * in = (const struct sockaddr_in *) saddr;
        addr->port = __ntohs(in->sin_port);
        addr->addr.v4 = in->sin_addr;
        return;
    }

    if (domain == AF_INET6) {
        if (saddr->sa_family == AF_INET) {
            const struct sockaddr_in * in = (const struct sockaddr_in *) saddr;
            addr->port = __ntohs(in->sin_port);
            ((uint32_t *) &addr->addr.v6.s6_addr)[0] = 0;
            ((uint32_t *) &addr->addr.v6.s6_addr)[1] = 0;
            ((uint32_t *) &addr->addr.v6.s6_addr)[2] = 0xffff0000;
            ((uint32_t *) &addr->addr.v6.s6_addr)[3] = in->sin_addr.s_addr;
        } else {
            const struct sockaddr_in6 * in6 = (const struct sockaddr_in6 *) saddr;
            addr->port = __ntohs(in6->sin6_port);
            addr->addr.v6 = in6->sin6_addr;
        }
        return;
    }
}

static inline bool inet_comp_addr (int domain, const struct addr_inet * addr,
                                   const struct sockaddr * saddr)
{
    if (domain == AF_INET) {
        const struct sockaddr_in * in = (const struct sockaddr_in *) saddr;
        return addr->port == __ntohs(in->sin_port) &&
               !memcmp(&addr->addr.v4, &in->sin_addr,
                       sizeof(struct in_addr));
    }
    if (domain == AF_INET6) {
        const struct sockaddr_in6 * in6 = (const struct sockaddr_in6 *) saddr;
        return addr->port == __ntohs(in6->sin6_port) &&
               !memcmp(&addr->addr.v6, &in6->sin6_addr,
                       sizeof(struct in6_addr));
    }
    return false;
}

static int create_socket_uri (struct shim_handle * hdl)
{
    struct shim_sock_handle * sock = &hdl->info.sock;

    if (sock->domain == AF_UNIX) {
        char uri_buf[32];
        int bytes = unix_create_uri(uri_buf, 32, sock->sock_state,
                                    sock->addr.un.pipeid);
        if (bytes < 0)
            return bytes;

        qstrsetstr(&hdl->uri, uri_buf, bytes);
        return 0;
    }

    if (sock->domain == AF_INET || sock->domain == AF_INET6) {
        char uri_buf[SOCK_URI_SIZE];
        int bytes = inet_create_uri(sock->domain, uri_buf, SOCK_URI_SIZE,
                                    sock->sock_type, sock->sock_state,
                                    &sock->addr.in.bind, &sock->addr.in.conn);
        if (bytes < 0)
            return bytes;

        qstrsetstr(&hdl->uri, uri_buf, bytes);
        return 0;
    }

    return -EPROTONOSUPPORT;
}

int shim_do_bind (int sockfd, struct sockaddr * addr, socklen_t addrlen)
{
    if (!addr || test_user_memory(addr, addrlen, false))
        return -EFAULT;

    struct shim_handle * hdl = get_fd_handle(sockfd, NULL, NULL);
    int ret = -EINVAL;
    if (!hdl)
        return -EBADF;

    if (hdl->type != TYPE_SOCK) {
        put_handle(hdl);
        return -ENOTSOCK;
    }

    struct shim_sock_handle * sock = &hdl->info.sock;
    lock(hdl->lock);
    enum shim_sock_state state = sock->sock_state;

    if (state != SOCK_CREATED) {
        debug("shim_bind: bind on a bound socket\n");
        goto out;
    }

    if (sock->domain == AF_UNIX) {
        if (addrlen != sizeof(struct sockaddr_un)) 
            goto out;

        struct sockaddr_un * saddr = (struct sockaddr_un *) addr;
        char * spath = saddr->sun_path;
        struct shim_dentry * dent = NULL;

        if ((ret = path_lookupat(NULL, spath, LOOKUP_CREATE, &dent, NULL)) < 0) {
            // DEP 7/3/17: We actually want either 0 or -ENOENT, as the
            // expected case is that the name is free (and we get the dent to
            // populate the name)
            if (ret != -ENOENT || !dent)
                goto out;
        }

        if (dent->state & DENTRY_VALID &&
            !(dent->state & DENTRY_NEGATIVE)) {
            ret = -EADDRINUSE;
            goto out;
        }

        struct shim_unix_data * data = malloc(sizeof(struct shim_unix_data));

        data->pipeid = dent->rel_path.hash >> 32;
        sock->addr.un.pipeid = data->pipeid;
        sock->addr.un.data = data;
        sock->addr.un.dentry = dent;

    } else if (sock->domain == AF_INET || sock->domain == AF_INET6) {
        if ((ret = inet_check_addr(sock->domain, addr, addrlen)) < 0)
            goto out;
        inet_save_addr(sock->domain, &sock->addr.in.bind, addr);
        inet_rebase_port(false, sock->domain, &sock->addr.in.bind, true);
    }

    sock->sock_state = SOCK_BOUND;

    if ((ret = create_socket_uri(hdl)) < 0) 
        goto out;

    PAL_HANDLE pal_hdl = DkStreamOpen(qstrgetstr(&hdl->uri),
                                      0, 0, 0,
                                      hdl->flags & O_NONBLOCK);

    if (!pal_hdl) {
        ret = (PAL_NATIVE_ERRNO == PAL_ERROR_STREAMEXIST) ? -EADDRINUSE : -PAL_ERRNO;
        debug("bind: invalid handle returned\n");
        goto out;
    }

    if (sock->domain == AF_UNIX) {
        struct shim_dentry * dent = sock->addr.un.dentry;

        dent->state ^= DENTRY_NEGATIVE;
        dent->state |= DENTRY_VALID|DENTRY_RECENTLY;
        dent->fs = &socket_builtin_fs;
        dent->data = sock->addr.un.data;
    }

    if (sock->domain == AF_INET || sock->domain == AF_INET6) {
        char uri[SOCK_URI_SIZE];

        if (!DkStreamGetName(pal_hdl, uri, SOCK_URI_SIZE)) {
            ret = -PAL_ERRNO;
            goto out;
        }

        if ((ret = inet_parse_addr(sock->domain, sock->sock_type, uri,
                                   &sock->addr.in.bind, NULL)) < 0)
            goto out;

        inet_rebase_port(true, sock->domain, &sock->addr.in.bind, true);
    }


    hdl->pal_handle = pal_hdl;
    __process_pending_options(hdl);
    ret = 0;

out:
    if (ret < 0) {
        sock->sock_state = state;
        sock->error = -ret;

        if (sock->domain == AF_UNIX) {
            if (sock->addr.un.dentry)
                put_dentry(sock->addr.un.dentry);

            if (sock->addr.un.data) {
                free(sock->addr.un.data);
                sock->addr.un.data = NULL;
            }
        }
    }

    unlock(hdl->lock);
    put_handle(hdl);
    return ret;
}

static int inet_parse_addr (int domain, int type, const char * uri,
                            struct addr_inet * bind,
                            struct addr_inet * conn)
{
    char * ip_str, * port_str, * next_str;
    int ip_len = 0;

    if (!(next_str = strchr(uri, ':')))
        return -EINVAL;

    enum { UDP, UDPSRV, TCP, TCPSRV } prefix;
    int n = (next_str++) - uri;

    if (!memcmp(uri, "udp", n))
        prefix = UDP;
    else if (!memcmp(uri, "udp.srv", n))
        prefix = UDPSRV;
    else if (!memcmp(uri, "tcp", n))
        prefix = TCP;
    else if (!memcmp(uri, "tcp.srv", n))
        prefix = TCPSRV;
    else
        return -EINVAL;

    if ((prefix == UDP || prefix == UDPSRV) && type != SOCK_DGRAM)
        return -EINVAL;

    if ((prefix == TCP || prefix == TCPSRV) && type != SOCK_STREAM)
        return -EINVAL;

    for  (int round = 0 ; (ip_str = next_str) ; round++) {
        if (ip_str[0] == '[') {
            ip_str++;
            if (domain != AF_INET6)
                return -EINVAL;
            if (!(port_str = strchr(ip_str, ']')))
                return -EINVAL;
            ip_len = port_str - ip_str;
            port_str++;
            if (*port_str != ':')
                return -EINVAL;
        } else {
            if (domain != AF_INET)
                return -EINVAL;
            if (!(port_str = strchr(ip_str, ':')))
                return -EINVAL;
            ip_len = port_str - ip_str;
        }

        port_str++;
        next_str = strchr(port_str, ':');
        if (next_str)
            next_str++;

        struct addr_inet * addr = round ? conn : bind;

        if (domain == AF_INET) {
            inet_pton4(ip_str, ip_len, &addr->addr.v4);
            addr->ext_port = atoi(port_str);
        }

        if (domain == AF_INET6) {
            inet_pton6(ip_str, ip_len, &addr->addr.v6);
            addr->ext_port = atoi(port_str);
        }
    }

    return 0;
}

struct un_conn {
    unsigned int pipeid;
    unsigned char path_size;
    char path[];
} __attribute__((packed));

int shim_do_listen (int sockfd, int backlog)
{
    if (backlog < 0)
        return -EINVAL;

    struct shim_handle * hdl = get_fd_handle(sockfd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    if (hdl->type != TYPE_SOCK) {
        put_handle(hdl);
        return -ENOTSOCK;
    }

    struct shim_sock_handle * sock = &hdl->info.sock;

    if (sock->sock_type != SOCK_STREAM) {
        debug("shim_listen: not a stream socket\n");
        put_handle(hdl);
        return -EINVAL;
    }

    lock(hdl->lock);

    enum shim_sock_state state = sock->sock_state;
    int ret = -EINVAL;

    if (state != SOCK_BOUND) {
        debug("shim_listen: listen on unbound socket\n");
        goto out;
    }

    hdl->acc_mode = MAY_READ;
    sock->sock_state = SOCK_LISTENED;

    ret = 0;

out:
    if (ret < 0)
        sock->sock_state = state;

    unlock(hdl->lock);
    put_handle(hdl);
    return ret;
}

/* Connect with the TCP socket is always in the client.
 *
 * With UDP, the connection is make to the socket specific for a
 * destination. A process with a connected UDP socket can call
 * connect again for that socket for one of two reasons: 1. To
 * specify a new IP address and port 2. To unconnect the socket.
 */
int shim_do_connect (int sockfd, struct sockaddr * addr, int addrlen)
{
    if (!addr || test_user_memory(addr, addrlen, false))
        return -EFAULT;

    struct shim_handle * hdl = get_fd_handle(sockfd, NULL, NULL);

    if (!hdl)
        return -EBADF;

    if (hdl->type != TYPE_SOCK) {
        put_handle(hdl);
        return -ENOTSOCK;
    }

    struct shim_sock_handle * sock = &hdl->info.sock;
    lock(hdl->lock);
    enum shim_sock_state state = sock->sock_state;
    int ret = -EINVAL;

    if (state == SOCK_CONNECTED) {
        if (addr->sa_family == AF_UNSPEC) {
            sock->sock_state = SOCK_CREATED;
            if (sock->sock_type == SOCK_STREAM && hdl->pal_handle) {
                DkStreamDelete(hdl->pal_handle, 0);
                DkObjectClose(hdl->pal_handle);
                hdl->pal_handle = NULL;
            }
            debug("shim_connect: reconnect on a stream socket\n");
            ret = 0;
            goto out;
        }

        debug("shim_connect: reconnect on a stream socket\n");
        ret = -EISCONN;
        goto out;
    }

    if (state != SOCK_BOUND &&
        state != SOCK_CREATED) {
        debug("shim_connect: connect on invalid socket\n");
        goto out;
    }

    if (sock->domain == AF_UNIX) {
        if (addrlen != sizeof(struct sockaddr_un))
            goto out;

        struct sockaddr_un * saddr = (struct sockaddr_un *) addr;
        char * spath = saddr->sun_path;
        struct shim_dentry * dent;

        if ((ret = path_lookupat(NULL, spath, LOOKUP_CREATE, &dent, NULL)) < 0)
            goto out;

        struct shim_unix_data * data = dent->data;

        if (!(dent->state & DENTRY_VALID) || dent->state & DENTRY_NEGATIVE) {
            data = malloc(sizeof(struct shim_unix_data));
            data->pipeid = dent->rel_path.hash >> 32;
        } else if (dent->fs != &socket_builtin_fs) {
            ret = -ECONNREFUSED;
            goto out;
        }

        sock->addr.un.pipeid = data->pipeid;
        sock->addr.un.data = data;
        sock->addr.un.dentry = dent;
        get_dentry(dent);
    }

    if (state == SOCK_BOUND) {
        /* if the socket is bound, the stream needs to be shut and rebound. */
        assert(hdl->pal_handle);
        DkStreamDelete(hdl->pal_handle, 0);
        DkObjectClose(hdl->pal_handle);
        hdl->pal_handle = NULL;
    }

    if (sock->domain != AF_UNIX) {
        if ((ret = inet_check_addr(sock->domain, addr, addrlen)) < 0)
            goto out;
        inet_save_addr(sock->domain, &sock->addr.in.conn, addr);
        inet_rebase_port(false, sock->domain, &sock->addr.in.conn, false);
    }

    sock->sock_state = (state == SOCK_BOUND) ? SOCK_BOUNDCONNECTED :
                                               SOCK_CONNECTED;

    if ((ret = create_socket_uri(hdl)) < 0)
        goto out;

    PAL_HANDLE pal_hdl = DkStreamOpen(qstrgetstr(&hdl->uri),
                                      0, 0, 0,
                                      hdl->flags & O_NONBLOCK);

    if (!pal_hdl) {
        ret = (PAL_NATIVE_ERRNO == PAL_ERROR_DENIED) ? -ECONNREFUSED : -PAL_ERRNO;
        goto out;
    }

    hdl->pal_handle = pal_hdl;

    if (sock->domain == AF_UNIX) {
        struct shim_dentry * dent = sock->addr.un.dentry;
        lock(dent->lock);
        dent->state ^= DENTRY_NEGATIVE;
        dent->state |= DENTRY_VALID|DENTRY_RECENTLY;
        dent->fs = &socket_builtin_fs;
        dent->data = sock->addr.un.data;
        unlock(dent->lock);
    }

    if (sock->domain == AF_INET || sock->domain == AF_INET6) {
        char uri[SOCK_URI_SIZE];

        if (!DkStreamGetName(pal_hdl, uri, SOCK_URI_SIZE)) {
            ret = -PAL_ERRNO;
            goto out;
        }

        if ((ret = inet_parse_addr(sock->domain, sock->sock_type, uri,
                                   &sock->addr.in.bind,
                                   &sock->addr.in.conn)) < 0)
            goto out;

        inet_rebase_port(true, sock->domain, &sock->addr.in.bind, true);
        inet_rebase_port(true, sock->domain, &sock->addr.in.conn, false);
    }

    hdl->acc_mode = MAY_READ|MAY_WRITE;
    __process_pending_options(hdl);
    ret = 0;

out:
    if (ret < 0) {
        sock->sock_state = state;
        sock->error = -ret;

        if (sock->domain == AF_UNIX) {
            if (sock->addr.un.dentry)
                put_dentry(sock->addr.un.dentry);

            if (sock->addr.un.data) {
                free(sock->addr.un.data);
                sock->addr.un.data = NULL;
            }
        }
    }

    unlock(hdl->lock);
    put_handle(hdl);
    return ret;
}

int __do_accept (struct shim_handle * hdl, int flags, struct sockaddr * addr,
                 socklen_t * addrlen)
{
    if (hdl->type != TYPE_SOCK)
        return -ENOTSOCK;

    struct shim_sock_handle * sock = &hdl->info.sock;
    int ret;
    PAL_HANDLE accepted = NULL;

    if (sock->sock_type != SOCK_STREAM) {
        debug("shim_accept: not a stream socket\n");
        return -EOPNOTSUPP;
    }

    if (addr) {
        if (!addrlen || test_user_memory(addrlen, sizeof(*addrlen), false))
            return -EINVAL;

        if (*addrlen < minimal_addrlen(sock->domain))
            return -EINVAL;

        if (test_user_memory(addr, *addrlen, true))
            return -EINVAL;
    }

    lock(hdl->lock);

    if (sock->sock_state != SOCK_LISTENED) {
        debug("shim_accpet: invalid socket\n");
        ret = -EINVAL;
        goto out;
    }

    accepted = DkStreamWaitForClient(hdl->pal_handle);
    if (!accepted) {
        ret = -PAL_ERRNO;
        goto out;
    }

    if (flags & O_NONBLOCK) {
        PAL_STREAM_ATTR attr;

        if (!DkStreamAttributesQuerybyHandle(accepted, &attr)) {
            ret = -PAL_ERRNO;
            goto out;
        }

        attr.nonblocking = PAL_TRUE;

        if (!DkStreamAttributesSetbyHandle(accepted, &attr)) {
            ret = -PAL_ERRNO;
            goto out;
        }
    }

    struct shim_handle * cli = get_new_handle();
    if (!cli) {
        ret = -ENOMEM;
        goto out;
    }

    struct shim_sock_handle * cli_sock = &cli->info.sock;
    cli->type       = TYPE_SOCK;
    set_handle_fs(cli, &socket_builtin_fs);
    cli->acc_mode = MAY_READ|MAY_WRITE;
    cli->flags      = O_RDWR|flags;
    cli->pal_handle = accepted;
    accepted = NULL;

    cli_sock->domain     = sock->domain;
    cli_sock->sock_type  = sock->sock_type;
    cli_sock->protocol   = sock->protocol;
    cli_sock->sock_state = SOCK_ACCEPTED;

    if (sock->domain == AF_UNIX) {
        cli_sock->addr.un.pipeid = sock->addr.un.pipeid;
        if (sock->addr.un.dentry) {
            get_dentry(sock->addr.un.dentry);
            cli_sock->addr.un.dentry = sock->addr.un.dentry;
        }

        qstrsetstr(&cli->uri, qstrgetstr(&hdl->uri), hdl->uri.len);

        if (addr) {
            unix_copy_addr(addr, sock->addr.un.dentry);

            if (addrlen)
                *addrlen = sizeof(struct sockaddr_un);
        }
    }

    if (sock->domain == AF_INET || sock->domain == AF_INET6) {
        char uri[SOCK_URI_SIZE];
        int uri_len;

        if (!(uri_len = DkStreamGetName(cli->pal_handle, uri, SOCK_URI_SIZE))) {
            ret = -PAL_ERRNO;
            goto out_cli;
        }

        if ((ret = inet_parse_addr(cli_sock->domain, cli_sock->sock_type, uri,
                                   &cli_sock->addr.in.bind,
                                   &cli_sock->addr.in.conn)) < 0)
            goto out_cli;

        qstrsetstr(&cli->uri, uri, uri_len);

        inet_rebase_port(true, cli_sock->domain, &cli_sock->addr.in.bind, true);
        inet_rebase_port(true, cli_sock->domain, &cli_sock->addr.in.conn, false);

        if (addr) {
            inet_copy_addr(sock->domain, addr, &sock->addr.in.conn);

            if (addrlen) {
                assert(sock->domain == AF_INET || sock->domain == AF_INET6);
                *addrlen = minimal_addrlen(sock->domain);
            }
        }
    }

    ret = set_new_fd_handle(cli, flags & O_CLOEXEC ? FD_CLOEXEC : 0, NULL);
out_cli:
    put_handle(cli);
out:
    if (ret < 0)
        sock->error = -ret;
    if (accepted)
        DkObjectClose(accepted);
    unlock(hdl->lock);
    return ret;
}

int shim_do_accept (int fd, struct sockaddr * addr, socklen_t * addrlen)
{
    int flags;
    struct shim_handle * hdl = get_fd_handle(fd, &flags, NULL);
    if (!hdl)
        return -EBADF;

    int ret = __do_accept(hdl, flags & O_CLOEXEC,
                          addr, addrlen);
    put_handle(hdl);
    return ret;
}

int shim_do_accept4 (int fd, struct sockaddr * addr, socklen_t * addrlen,
                     int flags)
{
    struct shim_handle * hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret = __do_accept(hdl,
                          (flags & SOCK_CLOEXEC ? O_CLOEXEC : 0) |
                          (flags & SOCK_NONBLOCK ? O_NONBLOCK : 0),
                          addr, addrlen);
    put_handle(hdl);
    return ret;
}

static ssize_t do_sendmsg (int fd, struct iovec * bufs, int nbufs, int flags,
                           const struct sockaddr * addr, socklen_t addrlen)
{
    struct shim_handle * hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret = -ENOTSOCK;
    if (hdl->type != TYPE_SOCK)
        goto out;

    struct shim_sock_handle * sock = &hdl->info.sock;

    ret = -EFAULT;
    if (addr && test_user_memory((void *) addr, addrlen, false))
        goto out;

    if (!bufs || test_user_memory(bufs, sizeof(*bufs) * nbufs, false))
        goto out;

    for (int i = 0 ; i < nbufs ; i++) {
        if (!bufs[i].iov_base ||
            test_user_memory(bufs[i].iov_base, bufs[i].iov_len, false))
            goto out;
    }

    lock(hdl->lock);

    PAL_HANDLE pal_hdl = hdl->pal_handle;
    char * uri = NULL;

    /* Data gram sock need not be conneted or bound at all */
    if (sock->sock_type == SOCK_STREAM &&
        sock->sock_state != SOCK_CONNECTED &&
        sock->sock_state != SOCK_BOUNDCONNECTED &&
        sock->sock_state != SOCK_ACCEPTED) {
        ret = -ENOTCONN;
        goto out_locked;
    }

    if (sock->sock_type == SOCK_DGRAM &&
        sock->sock_state == SOCK_SHUTDOWN) {
        ret = -ENOTCONN;
        goto out_locked;
    }

    if (!(hdl->acc_mode & MAY_WRITE)) {
        ret = -ECONNRESET;
        goto out_locked;
    }

    if (sock->sock_type == SOCK_DGRAM &&
        sock->sock_state != SOCK_BOUNDCONNECTED &&
        sock->sock_state != SOCK_CONNECTED) {
        if (!addr) {
            ret = -EDESTADDRREQ;
            goto out_locked;
        }

        if (sock->sock_state == SOCK_CREATED && !pal_hdl) {
            pal_hdl = DkStreamOpen("udp:", 0, 0, 0,
                                   hdl->flags & O_NONBLOCK);
            if (!pal_hdl) {
                ret = -PAL_ERRNO;
                goto out_locked;
            }

            hdl->pal_handle = pal_hdl;
        }

        if (addr && addr->sa_family != sock->domain) {
            ret = -EINVAL;
            goto out_locked;
        }

        uri = __alloca(SOCK_URI_SIZE);
    }

    unlock(hdl->lock);

    if (uri) {
        struct addr_inet addr_buf;
        inet_save_addr(sock->domain, &addr_buf, addr);
        inet_rebase_port(false, sock->domain, &addr_buf, false);
        memcpy(uri, "udp:", 5);
        if ((ret = inet_translate_addr(sock->domain, uri + 4, SOCK_URI_SIZE - 4,
                                       &addr_buf)) < 0) {
            lock(hdl->lock);
            goto out_locked;
        }

        debug("next packet send to %s\n", uri);
    }

    int bytes = 0;
    ret = 0;

    for (int i = 0 ; i < nbufs ; i++) {
        ret = DkStreamWrite(pal_hdl, 0, bufs[i].iov_len, bufs[i].iov_base,
                            uri);

        if (!ret) {
            ret = (PAL_NATIVE_ERRNO == PAL_ERROR_STREAMEXIST) ?
                  - ECONNABORTED : -PAL_ERRNO;
            break;
        }

        bytes += ret;
    }

    if (bytes)
        ret = bytes;
    if (ret < 0) {
        lock(hdl->lock);
        goto out_locked;
    }
    goto out;

out_locked:
    if (ret < 0)
        sock->error = -ret;

    unlock(hdl->lock);
out:
    put_handle(hdl);
    return ret;
}

ssize_t shim_do_sendto (int sockfd, const void * buf, size_t len, int flags,
                        const struct sockaddr * addr, socklen_t addrlen)
{
    struct iovec iovbuf;
    iovbuf.iov_base = (void *) buf;
    iovbuf.iov_len = len;

    return do_sendmsg(sockfd, &iovbuf, 1, flags, addr, addrlen);
}

ssize_t shim_do_sendmsg (int sockfd, struct msghdr * msg, int flags)
{
    return do_sendmsg(sockfd, msg->msg_iov, msg->msg_iovlen, flags,
                      msg->msg_name, msg->msg_namelen);
}

int shim_do_sendmmsg (int sockfd, struct mmsghdr * msg, int vlen, int flags)
{
    int i, total = 0;

    for (i = 0 ; i * sizeof(struct mmsghdr) < vlen ; i++) {
        struct msghdr * m = &msg[i].msg_hdr;

        int bytes = do_sendmsg(sockfd, m->msg_iov, m->msg_iovlen, flags,
                               m->msg_name, m->msg_namelen);
        if (bytes < 0)
            return total ? : bytes;

        msg[i].msg_len = bytes;
        total++;
    }

    return total;
}

static ssize_t do_recvmsg (int fd, struct iovec * bufs, int nbufs, int flags,
                           struct sockaddr * addr, socklen_t * addrlen)
{
    struct shim_handle * hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret = -ENOTSOCK;
    if (hdl->type != TYPE_SOCK)
        goto out;

    struct shim_sock_handle * sock = &hdl->info.sock;

    if (addr) {
        ret = -EINVAL;
        if (!addrlen || test_user_memory(addrlen, sizeof(*addrlen), false))
            goto out;

        if (*addrlen < minimal_addrlen(sock->domain))
            goto out;

        if (test_user_memory(addr, *addrlen, true))
            goto out;
    }

    ret = -EFAULT;
    if (!bufs || test_user_memory(bufs, sizeof(*bufs) * nbufs, false))
        goto out;

    for (int i = 0 ; i < nbufs ; i++) {
        if (!bufs[i].iov_base ||
            test_user_memory(bufs[i].iov_base, bufs[i].iov_len, true))
            goto out;
    }

    lock(hdl->lock);

    PAL_HANDLE pal_hdl = hdl->pal_handle;
    char * uri = NULL;

    if (sock->sock_type == SOCK_STREAM &&
        sock->sock_state != SOCK_CONNECTED &&
        sock->sock_state != SOCK_BOUNDCONNECTED &&
        sock->sock_state != SOCK_ACCEPTED) {
        ret = -ENOTCONN;
        goto out_locked;
    }

    if (!(hdl->acc_mode & MAY_READ)) {
        ret = 0;
        goto out_locked;
    }

    if (addr && sock->sock_type == SOCK_DGRAM &&
        sock->sock_state != SOCK_CONNECTED &&
        sock->sock_state != SOCK_BOUNDCONNECTED) {
        if (sock->sock_state == SOCK_CREATED) {
            ret = -EINVAL;
            goto out_locked;
        }

        uri = __alloca(SOCK_URI_SIZE);
    }

    unlock(hdl->lock);

    bool address_received = false;
    int bytes = 0;
    ret = 0;

    for (int i = 0 ; i < nbufs ; i++) {
        ret = DkStreamRead(pal_hdl, 0, bufs[i].iov_len, bufs[i].iov_base,
                           uri, uri ? SOCK_URI_SIZE : 0);

        if (!ret) {
            ret = (PAL_NATIVE_ERRNO == PAL_ERROR_STREAMNOTEXIST) ?
                  - ECONNABORTED : -PAL_ERRNO;
            break;
        }

        bytes += ret;

        if (!addr || !bytes || address_received)
            continue;

        if (sock->domain == AF_UNIX) {
            unix_copy_addr(addr, sock->addr.un.dentry);
            *addrlen = sizeof(struct sockaddr_un);
        }

        if (sock->domain == AF_INET || sock->domain == AF_INET6) {
            if (uri) {
                struct addr_inet conn;

                if ((ret = inet_parse_addr(sock->domain, sock->sock_type, uri,
                                           &conn, NULL)) < 0) {
                    lock(hdl->lock);
                    goto out_locked;
                }

                debug("last packet received from %s\n", uri);

                inet_rebase_port(true, sock->domain, &conn, false);
                inet_copy_addr(sock->domain, addr, &conn);
            } else {
                inet_copy_addr(sock->domain, addr, &sock->addr.in.conn);
            }

            *addrlen = (sock->domain == AF_INET) ?
                       sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        }

        address_received = false;
    }

    if (bytes)
        ret = bytes;
    if (ret < 0) {
        lock(hdl->lock);
        goto out_locked;
    }
    goto out;

out_locked:
    if (ret < 0)
        sock->error = -ret;

    unlock(hdl->lock);
out:
    put_handle(hdl);
    return ret;
}

ssize_t shim_do_recvfrom (int sockfd, void * buf, size_t len, int flags,
                          struct sockaddr * addr, socklen_t * addrlen)
{
    struct iovec iovbuf;
    iovbuf.iov_base = (void *) buf;
    iovbuf.iov_len = len;

    return do_recvmsg(sockfd, &iovbuf, 1, flags, addr, addrlen);
}

ssize_t shim_do_recvmsg (int sockfd, struct msghdr * msg, int flags)
{
    return do_recvmsg(sockfd, msg->msg_iov, msg->msg_iovlen, flags,
                      msg->msg_name, &msg->msg_namelen);
}

int shim_do_recvmmsg (int sockfd, struct mmsghdr * msg, int vlen, int flags,
                      struct __kernel_timespec * timeout)
{
    int i, total = 0;

    for (i = 0 ; i * sizeof(struct mmsghdr) < vlen ; i++) {
        struct msghdr * m = &msg[i].msg_hdr;

        int bytes = do_recvmsg(sockfd, m->msg_iov, m->msg_iovlen, flags,
                               m->msg_name, &m->msg_namelen);
        if (bytes < 0)
            return total ? : bytes;

        msg[i].msg_len = bytes;
        total++;
    }

    return total;
}

#define SHUT_RD     0
#define SHUT_WR     1
#define SHUT_RDWR   2

int shim_do_shutdown (int sockfd, int how)
{
    struct shim_handle * hdl = get_fd_handle(sockfd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret = 0;
    struct shim_sock_handle * sock = &hdl->info.sock;

    if (hdl->type != TYPE_SOCK) {
        ret = -ENOTSOCK;
        goto out;
    }

    lock(hdl->lock);

    if (sock->sock_state != SOCK_LISTENED &&
        sock->sock_state != SOCK_ACCEPTED &&
        sock->sock_state != SOCK_CONNECTED &&
        sock->sock_state != SOCK_BOUNDCONNECTED) {
        ret = -ENOTCONN;
        goto out_locked;
    }

    switch (how) {
        case SHUT_RD:
            DkStreamDelete(hdl->pal_handle, PAL_DELETE_RD);
            hdl->acc_mode &= ~MAY_READ;
            break;
        case SHUT_WR:
            DkStreamDelete(hdl->pal_handle, PAL_DELETE_WR);
            hdl->acc_mode &= ~MAY_WRITE;
            break;
        case SHUT_RDWR:
            DkStreamDelete(hdl->pal_handle, 0);
            hdl->acc_mode = 0;
            sock->sock_state = SOCK_SHUTDOWN;
            break;
    }

    ret = 0;
out_locked:
    if (ret < 0)
        sock->error = -ret;

    unlock(hdl->lock);
out:
    put_handle(hdl);
    return ret;
}

int shim_do_getsockname (int sockfd, struct sockaddr * addr, int * addrlen)
{
    if (!addr || !addrlen)
        return -EFAULT;

    if (*addrlen <= 0)
        return -EINVAL;

    if (test_user_memory(addr, *addrlen, true))
        return -EFAULT;

    struct shim_handle * hdl = get_fd_handle(sockfd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret = -EINVAL;

    if (hdl->type != TYPE_SOCK) {
        ret = -ENOTSOCK;
        goto out;
    }

    struct shim_sock_handle * sock = &hdl->info.sock;
    lock(hdl->lock);

    struct sockaddr saddr;
    int len = inet_copy_addr(sock->domain, &saddr, &sock->addr.in.bind);

    if (len < *addrlen)
        len = *addrlen;

    memcpy(addr, &saddr, len);
    *addrlen = len;
    ret = 0;
    unlock(hdl->lock);
out:
    put_handle(hdl);
    return ret;
}

int shim_do_getpeername (int sockfd, struct sockaddr * addr, int * addrlen)
{
    if (!addr || !addrlen)
        return -EFAULT;

    if (*addrlen <= 0)
        return -EINVAL;

    if (test_user_memory(addr, *addrlen, true))
        return -EFAULT;

    struct shim_handle * hdl = get_fd_handle(sockfd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret = -EINVAL;

    if (hdl->type != TYPE_SOCK) {
        ret = -ENOTSOCK;
        goto out;
    }

    struct shim_sock_handle * sock = &hdl->info.sock;
    lock(hdl->lock);

    /* Data gram sock need not be conneted or bound at all */
    if (sock->sock_type == SOCK_STREAM &&
        sock->sock_state != SOCK_CONNECTED &&
        sock->sock_state != SOCK_BOUNDCONNECTED &&
        sock->sock_state != SOCK_ACCEPTED) {
        ret = -ENOTCONN;
        goto out_locked;
    }

    if (sock->sock_type == SOCK_DGRAM &&
        sock->sock_state != SOCK_CONNECTED &&
        sock->sock_state != SOCK_BOUNDCONNECTED) {
        ret = -ENOTCONN;
        goto out_locked;
    }

    struct sockaddr saddr;
    int len = inet_copy_addr (sock->domain, &saddr, &sock->addr.in.conn);

    if (len < *addrlen)
        len = *addrlen;

    memcpy(addr, &saddr, len);
    *addrlen = len;
    ret = 0;
out_locked:
    unlock(hdl->lock);
out:
    put_handle(hdl);
    return ret;
}

struct __kernel_linger {
    int l_onoff;
    int l_linger;
};

static int __do_setsockopt (struct shim_handle * hdl, int level, int optname,
                            char * optval, int optlen, PAL_STREAM_ATTR * attr)
{
    int intval = *((int *) optval);
    PAL_BOL bolval = intval ? PAL_TRUE : PAL_FALSE;

    if (level == SOL_SOCKET) {
        switch(optname) {
            case SO_ACCEPTCONN:
            case SO_DOMAIN:
            case SO_ERROR:
            case SO_PROTOCOL:
            case SO_TYPE:
                return -EPERM;
            case SO_KEEPALIVE:
            case SO_LINGER:
            case SO_RCVBUF:
            case SO_SNDBUF:
            case SO_RCVTIMEO:
            case SO_SNDTIMEO:
            case SO_REUSEADDR:
                goto query;
            default:
                goto unknown;
        }
    }

    if (level == SOL_TCP) {
        switch(optname) {
            case TCP_CORK:
            case TCP_NODELAY:
                goto query;
            default:
                goto unknown;
        }
    }

unknown:
    return -ENOPROTOOPT;

query:
    if (!attr) {
        attr = __alloca(sizeof(PAL_STREAM_ATTR));

        if (!DkStreamAttributesQuerybyHandle(hdl->pal_handle, attr))
            return -PAL_ERRNO;
    }

    if (level == SOL_SOCKET) {
        switch(optname) {
            case SO_KEEPALIVE:
                if (bolval != attr->socket.tcp_keepalive) {
                    attr->socket.tcp_keepalive = bolval;
                    goto set;
                }
                break;
            case SO_LINGER: {
                struct __kernel_linger * l = (struct __kernel_linger *) optval;
                int linger = l->l_onoff ? l->l_linger : 0;
                if (linger != (int) attr->socket.linger) {
                    attr->socket.linger = linger;
                    goto set;
                }
                break;
            }
            case SO_RCVBUF:
                if (intval != (int) attr->socket.receivebuf) {
                    attr->socket.receivebuf = intval;
                    goto set;
                }
                break;
            case SO_SNDBUF:
                if (intval != (int) attr->socket.sendbuf) {
                    attr->socket.sendbuf = intval;
                    goto set;
                }
                break;
            case SO_RCVTIMEO:
                if (intval != (int) attr->socket.receivetimeout) {
                    attr->socket.receivetimeout = intval;
                    goto set;
                }
                break;
            case SO_SNDTIMEO:
                if (intval != (int) attr->socket.sendtimeout) {
                    attr->socket.sendtimeout = intval;
                    goto set;
                }
                break;
            case SO_REUSEADDR:
                break;
        }
    }

    if (level == SOL_TCP) {
        switch(optname) {
            case TCP_CORK:
                if (bolval != attr->socket.tcp_cork) {
                    attr->socket.tcp_cork = bolval;
                    goto set;
                }
                break;
            case TCP_NODELAY:
                if (bolval != attr->socket.tcp_nodelay) {
                    attr->socket.tcp_nodelay = bolval;
                    goto set;
                }
                break;
        }
    }

    return 0;

set:
    if (!DkStreamAttributesSetbyHandle(hdl->pal_handle, attr))
        return -PAL_ERRNO;

    return 0;
}

static int __process_pending_options (struct shim_handle * hdl)
{
    struct shim_sock_handle * sock = &hdl->info.sock;

    if (!sock->pending_options)
        return 0;

    PAL_STREAM_ATTR attr;

    if (!DkStreamAttributesQuerybyHandle(hdl->pal_handle, &attr))
        return -PAL_ERRNO;

    struct shim_sock_option * o = sock->pending_options;

    while (o) {
        PAL_STREAM_ATTR tmp = attr;

        int ret = __do_setsockopt(hdl, o->level, o->optname, o->optval,
                                  o->optlen, &tmp);

        if (!ret)
            attr = tmp;

        struct shim_sock_option * next = o->next;
        free(o);
        o = next;
    }

    return 0;
}

int shim_do_setsockopt (int fd, int level, int optname, char * optval,
                        int optlen)
{
    if (!optval)
        return -EFAULT;

    struct shim_handle * hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret = 0;

    if (hdl->type != TYPE_SOCK) {
        ret = -ENOTSOCK;
        goto out;
    }

    struct shim_sock_handle * sock = &hdl->info.sock;
    lock(hdl->lock);

    if (!hdl->pal_handle) {
        struct shim_sock_option * o = malloc(sizeof(struct shim_sock_option) +
                                             optlen);
        if (!o) {
            ret = -ENOMEM;
            goto out_locked;
        }

        struct shim_sock_option ** next = &sock->pending_options;
        while (*next)
            next = &(*next)->next;

        o->next     = NULL;
        *next       = o;
        o->level    = level;
        o->optname  = optname;
        o->optlen   = optlen;
        memcpy(&o->optval, optval, optlen);
        goto out_locked;
    }

    ret = __do_setsockopt(hdl, level, optname, optval, optlen, NULL);

out_locked:
    unlock(hdl->lock);
out:
    put_handle(hdl);
    return ret;
}

int shim_do_getsockopt (int fd, int level, int optname, char * optval,
                        int * optlen)
{
    if (!optval || !optlen)
        return -EFAULT;

    struct shim_handle * hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret = 0;

    if (hdl->type != TYPE_SOCK) {
        ret = -ENOTSOCK;
        goto out;
    }

    struct shim_sock_handle * sock = &hdl->info.sock;
    lock(hdl->lock);

    int * intval = (int *) optval;

    if (level == SOL_SOCKET) {
        switch(optname) {
            case SO_ACCEPTCONN:
                *intval = (sock->sock_state == SOCK_LISTENED) ? 1 : 0;
                goto out;
            case SO_DOMAIN:
                *intval = sock->domain;
                goto out;
            case SO_ERROR:
                *intval = sock->error;
                goto out;
            case SO_PROTOCOL:
                switch(sock->protocol) {
                    case SOCK_STREAM:
                        *intval = IPPROTO_SCTP;
                        break;
                    case SOCK_DGRAM:
                        *intval = IPPROTO_UDP;
                        break;
                    default:
                        goto unknown;
                }
                goto out;
            case SO_TYPE:
                *intval = sock->sock_type;
                goto out;
            case SO_KEEPALIVE:
            case SO_LINGER:
            case SO_RCVBUF:
            case SO_SNDBUF:
            case SO_RCVTIMEO:
            case SO_SNDTIMEO:
            case SO_REUSEADDR:
                goto query;
            default:
                goto unknown;
        }
    }

    if (level == SOL_TCP) {
        switch(optname) {
            case TCP_CORK:
            case TCP_NODELAY:
                goto query;
            default:
                goto unknown;
        }
    }

unknown:
    ret = -ENOPROTOOPT;
    goto out;

query:
    {
        PAL_STREAM_ATTR attr;

        if (!DkStreamAttributesQuerybyHandle(hdl->pal_handle, &attr)) {
            ret = -PAL_ERRNO;
            goto out;
        }

        if (level == SOL_SOCKET) {
            switch(optname) {
                case SO_KEEPALIVE:
                    *intval = attr.socket.tcp_keepalive ? 1 : 0;
                    break;
                case SO_LINGER: {
                    struct __kernel_linger * l =
                            (struct __kernel_linger *) optval;
                    l->l_onoff = attr.socket.linger ? 1 : 0;
                    l->l_linger = attr.socket.linger;
                    break;
                }
                case SO_RCVBUF:
                    *intval = attr.socket.receivebuf;
                    break;
                case SO_SNDBUF:
                    *intval = attr.socket.sendbuf;
                    break;
                case SO_RCVTIMEO:
                    *intval = attr.socket.receivetimeout;
                    break;
                case SO_SNDTIMEO:
                    *intval = attr.socket.sendtimeout;
                    break;
                case SO_REUSEADDR:
                    *intval = 1;
                    break;
            }
        }

        if (level == SOL_TCP) {
            switch(optname) {
                case TCP_CORK:
                    *intval = attr.socket.tcp_cork ? 1 : 0;
                    break;
                case TCP_NODELAY:
                    *intval = attr.socket.tcp_nodelay ? 1 : 0;
                    break;
            }
        }
    }

out:
    unlock(hdl->lock);
    put_handle(hdl);
    return ret;
}
