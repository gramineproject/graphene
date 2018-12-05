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
#include "pal.h"
#include "pal_internal.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "api.h"

/* 96 bytes is the minimal size of buffer to store a IPv4/IPv6
   address */
#define PAL_SOCKADDR_SIZE   96

/* listen on a tcp socket */
static int tcp_listen (PAL_HANDLE * handle, char * uri, int create)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* accept a tcp connection */
static int tcp_accept (PAL_HANDLE handle, PAL_HANDLE *client)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* connect on a tcp socket */
static int tcp_connect (PAL_HANDLE * handle, char * uri, int create)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
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

    if (!strpartcmp_static(type, "tcp.srv:"))
        return tcp_listen(handle, uri_buf, create);

    if (!strpartcmp_static(type, "tcp:"))
        return tcp_connect(handle, uri_buf, create);

    return -PAL_ERROR_NOTSUPPORT;
}

/* 'read' operation of tcp stream */
static int64_t tcp_read (PAL_HANDLE handle, uint64_t offset, uint64_t len, void * buf)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* write' operation of tcp stream */
static int64_t tcp_write (PAL_HANDLE handle, uint64_t offset, uint64_t len, const void * buf)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* used by 'open' operation of tcp stream for bound socket */
static int udp_bind (PAL_HANDLE *handle, char * uri, int create)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* used by 'open' operation of tcp stream for connected socket */
static int udp_connect (PAL_HANDLE * handle, char * uri)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int udp_open (PAL_HANDLE *hdl, const char * type, const char * uri,
                     int access, int share, int create, int options)
{
    char buf[PAL_SOCKADDR_SIZE];
    int len = strlen(uri);

    if (len >= PAL_SOCKADDR_SIZE)
        return -PAL_ERROR_TOOLONG;

    memcpy(buf, uri, len + 1);

    if (strpartcmp_static(type, "udp.srv:"))
        return udp_bind(hdl, buf, create);

    if (strpartcmp_static(type, "udp:"))
        return udp_connect(hdl, buf);

    return -PAL_ERROR_NOTSUPPORT;
}

static int64_t udp_receive (PAL_HANDLE handle, uint64_t offset, uint64_t len, void * buf)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t udp_receivebyaddr (PAL_HANDLE handle, uint64_t offset, uint64_t len,
                              void * buf, char * addr, int addrlen)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t udp_send (PAL_HANDLE handle, uint64_t offset, uint64_t len, const void * buf)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t udp_sendbyaddr (PAL_HANDLE handle, uint64_t offset, uint64_t len,
                               const void * buf, const char * addr, int addrlen)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int socket_delete (PAL_HANDLE handle, int access)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int socket_close (PAL_HANDLE handle)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int socket_attrquerybyhdl (PAL_HANDLE handle, PAL_STREAM_ATTR  * attr)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int socket_getname (PAL_HANDLE handle, char * buffer, int count)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
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
    };

struct handle_ops udp_ops = {
        .getname        = &socket_getname,
        .open           = &udp_open,
        .read           = &udp_receive,
        .write          = &udp_send,
        .delete         = &socket_delete,
        .close          = &socket_close,
        .attrquerybyhdl = &socket_attrquerybyhdl,
    };

struct handle_ops udpsrv_ops = {
        .getname        = &socket_getname,
        .open           = &udp_open,
        .readbyaddr     = &udp_receivebyaddr,
        .writebyaddr    = &udp_sendbyaddr,
        .delete         = &socket_delete,
        .close          = &socket_close,
        .attrquerybyhdl = &socket_attrquerybyhdl,
    };

PAL_HANDLE _DkBroadcastStreamOpen (void)
{
    return NULL;
}

static int64_t mcast_send (PAL_HANDLE handle, uint64_t offset, uint64_t size,
                           const void * buf)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t mcast_receive (PAL_HANDLE handle, uint64_t offset, uint64_t size, void * buf)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int mcast_close (PAL_HANDLE handle)
{
    return -PAL_ERROR_NOTIMPLEMENTED;
}

struct handle_ops mcast_ops = {
        .write          = &mcast_send,
        .read           = &mcast_receive,
        .close          = &mcast_close,
    };
