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
 * db_stream.c
 *
 * This file contains APIs to open, read, write and get attribute of
 * streams.
 */

#include "pal_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "api.h"

/* Stream handler table: this table corresponds to all the
   handle type supported by PAL. Threads, Semaphores and Events
   are not streams, so they need no handler */
extern struct handle_ops file_ops;
extern struct handle_ops pipe_ops;
extern struct handle_ops pipeprv_ops;
extern struct handle_ops dev_ops;
extern struct handle_ops dir_ops;
extern struct handle_ops tcp_ops;
extern struct handle_ops udp_ops;
extern struct handle_ops udpsrv_ops;
extern struct hadnle_ops udppacket_ops;
extern struct handle_ops thread_ops;
extern struct handle_ops proc_ops;
extern struct handle_ops mutex_ops;
extern struct handle_ops event_ops;
extern struct handle_ops gipc_ops;
extern struct handle_ops mcast_ops;

const struct handle_ops * pal_handle_ops [PAL_HANDLE_TYPE_BOUND] = {
            [pal_type_file]      = &file_ops,
            [pal_type_pipe]      = &pipe_ops,
            [pal_type_pipesrv]   = &pipe_ops,
            [pal_type_pipecli]   = &pipe_ops,
            [pal_type_pipeprv]   = &pipeprv_ops,
            [pal_type_dev]       = &dev_ops,
            [pal_type_dir]       = &dir_ops,
            [pal_type_tcp]       = &tcp_ops,
            [pal_type_tcpsrv]    = &tcp_ops,
            [pal_type_udp]       = &udp_ops,
            [pal_type_udpsrv]    = &udpsrv_ops,
            [pal_type_process]   = &proc_ops,
            [pal_type_mcast]     = &mcast_ops,
            [pal_type_thread]    = &thread_ops,
            [pal_type_mutex]     = &mutex_ops,
            [pal_type_event]     = &event_ops,
            [pal_type_gipc]      = &gipc_ops,
        };

/* parse_stream_uri scan the uri, seperate prefix and search for
   stream handler which will open or access the stream */
int parse_stream_uri (const char ** uri, const char ** prefix,
                      struct handle_ops ** ops)
{
    const char * p, * u = (*uri);

    for (p = u ; (*p) && (*p) != ':' ; p++);

    if ((*p) != ':')
        return -PAL_ERROR_INVAL;

    struct handle_ops * hops = NULL;

    switch (p - u) {
        case 3:
            if (strpartcmp_static(u, "dir"))
                hops = &dir_ops;
            else if (strpartcmp_static(u, "tcp"))
                hops = &tcp_ops;
            else if (strpartcmp_static(u, "udp"))
                hops = &udp_ops;
            else if (strpartcmp_static(u, "dev"))
                hops = &dev_ops;
            break;

        case 4:
            if (strpartcmp_static(u, "file"))
                hops = &file_ops;
            else if (strpartcmp_static(u, "pipe"))
                hops = &pipe_ops;
            else if (strpartcmp_static(u, "gipc"))
                hops = &gipc_ops;
            break;

        case 7:
            if (strpartcmp_static(u, "tcp.srv"))
                hops = &tcp_ops;
            else if (strpartcmp_static(u, "udp.srv"))
                hops = &udp_ops;
            break;

        case 8:
            if (strpartcmp_static(u, "pipe.srv"))
                hops = &pipe_ops;
            break;

        default:
            break;
    }

    if (!hops)
        return -PAL_ERROR_NOTSUPPORT;

    *uri = p + 1;

    if (prefix)
        *prefix = u;

    if (ops)
        *ops = hops;

    return 0;
}

/* _DkStreamOpen for internal use. Open stream based on uri.
   access/share/create/options are the same flags defined for
   DkStreamOpen. */
int _DkStreamOpen (PAL_HANDLE * handle, const char * uri,
                   int access, int share, int create, int options)
{
    struct handle_ops * ops = NULL;
    const char * type = NULL;

    log_stream(uri);

    int ret = parse_stream_uri(&uri, &type, &ops);

    if (ret < 0)
        return ret;

    assert(ops && ops->open);
    return ops->open(handle, type, uri, access, share, create, options);
}

/* PAL call DkStreamOpen: Open stream based on uri, as given access/share/
   create/options flags. DkStreamOpen return a PAL_HANDLE to access the
   stream, or return NULL. Error code is notified. */
PAL_HANDLE
DkStreamOpen (PAL_STR uri, PAL_FLG access, PAL_FLG share, PAL_FLG create,
              PAL_FLG options)
{
    ENTER_PAL_CALL(DkStreamOpen);

    PAL_HANDLE handle = NULL;
    int ret = _DkStreamOpen(&handle, uri, access, share, create, options);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(NULL);
    }

    assert(handle);
    assert(PAL_GET_TYPE(handle));

    TRACE_HEAP(handle);
    LEAVE_PAL_CALL_RETURN(handle);
}

int _DkStreamWaitForClient(PAL_HANDLE handle, PAL_HANDLE * client)
{
    if (UNKNOWN_HANDLE(handle))
        return -PAL_ERROR_BADHANDLE;

    const struct handle_ops * ops = HANDLE_OPS(handle);

    /* No ops or ops->delete being defined, inferring the handle can never
       be deleted */
    if (!ops || !ops->waitforclient)
        return -PAL_ERROR_NOTSERVER;

    return ops->waitforclient(handle, client);
}

PAL_HANDLE
DkStreamWaitForClient (PAL_HANDLE handle)
{
    ENTER_PAL_CALL(DkStreamWaitForClient);

    PAL_HANDLE client;
    int ret = _DkStreamWaitForClient(handle, &client);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        client = NULL;
    }

    TRACE_HEAP(client);
    LEAVE_PAL_CALL_RETURN(client);
}

/* _DkStreamDelete for internal use. This function will explicit delete
   the stream. For example, file will be deleted, socket witll be
   disconnected, etc */
int _DkStreamDelete (PAL_HANDLE handle, int access)
{
    if (UNKNOWN_HANDLE(handle))
        return -PAL_ERROR_BADHANDLE;

    const struct handle_ops * ops = HANDLE_OPS(handle);

    /* No ops or ops->delete being defined, inferring the handle can never
       be deleted */
    if (!ops || !ops->delete)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->delete(handle, access);
}

/* PAL call DkStreamDelete: Explicitly delete stream as given handle. No
   return value, error code is notified. */
void DkStreamDelete (PAL_HANDLE handle, PAL_FLG access)
{
    ENTER_PAL_CALL(DkStreamDelete);

    if (!handle) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL();
    }

    int ret = _DkStreamDelete(handle, access);

    if (ret < 0)
        _DkRaiseFailure(-ret);

    LEAVE_PAL_CALL();
}

/* _DkStreamRead for internal use. Read from stream as absolute offset.
   The actual behavior of stream read is defined by handler */
int64_t _DkStreamRead (PAL_HANDLE handle, uint64_t offset, uint64_t count,
                       void * buf, char * addr, int addrlen)
{
    if (UNKNOWN_HANDLE(handle))
        return -PAL_ERROR_BADHANDLE;

    const struct handle_ops * ops = HANDLE_OPS(handle);

    /* if ops or ops->read is not defined, it infers that the stream can
       never be read */
    if (!ops)
        return -PAL_ERROR_NOTSUPPORT;

    if (!count)
        return -PAL_ERROR_ZEROSIZE;

    int64_t ret;

    if (addr) {
        if (!ops->readbyaddr)
            return -PAL_ERROR_NOTSUPPORT;

        ret = ops->readbyaddr(handle, offset, count, buf, addr, addrlen);
    } else {
        if (!ops->read)
            return -PAL_ERROR_NOTSUPPORT;

        ret = ops->read(handle, offset, count, buf);
    }

    return ret ? ret : -PAL_ERROR_ENDOFSTREAM;
}

/* PAL call DkStreamRead: Read from stream at absolute offset. Return number
   of bytes if succeeded, or 0 for failure. Error code is notified. */
PAL_NUM
DkStreamRead (PAL_HANDLE handle, PAL_NUM offset, PAL_NUM count,
              PAL_PTR buffer, PAL_PTR source, PAL_NUM size)
{
    ENTER_PAL_CALL(DkStreamRead);

    if (!handle || !buffer) {
        _DkRaiseFailure(-PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(0);
    }

    int64_t ret = _DkStreamRead(handle, offset, count, (void *) buffer,
                                size ? (char *) source : NULL,
                                source ? size : 0);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        ret = 0;
    }

    LEAVE_PAL_CALL_RETURN(ret);
}

/* _DkStreamWrite for internal use, write to stream at absolute offset.
   The actual behavior of stream write is defined by handler */
int64_t _DkStreamWrite (PAL_HANDLE handle, uint64_t offset, uint64_t count,
                        const void * buf, const char * addr, int addrlen)
{
    if (UNKNOWN_HANDLE(handle))
        return -PAL_ERROR_BADHANDLE;

    const struct handle_ops * ops = HANDLE_OPS(handle);

    if (!ops)
        return -PAL_ERROR_NOTSUPPORT;

    if (!count)
        return -PAL_ERROR_ZEROSIZE;

    int64_t ret;

    if (addr) {
        if (!ops->writebyaddr)
            return -PAL_ERROR_NOTSUPPORT;

        ret = ops->writebyaddr(handle, offset, count, buf, addr, addrlen);
    } else {
        if (!ops->write)
            return -PAL_ERROR_NOTSUPPORT;

        ret = ops->write(handle, offset, count, buf);
    }

    return ret ? ret : -PAL_ERROR_ENDOFSTREAM;
}

/* PAL call DkStreamWrite: Write to stream at absolute offset. Return number
   of bytes if succeeded, or 0 for failure. Error code is notified. */
PAL_NUM
DkStreamWrite (PAL_HANDLE handle, PAL_NUM offset, PAL_NUM count,
               PAL_PTR buffer, PAL_STR dest)
{
    ENTER_PAL_CALL(DkStreamWrite);

    if (!handle || !buffer) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(0);
    }

    int64_t ret = _DkStreamWrite(handle, offset, count, (void *) buffer, dest,
                                 dest ? strlen(dest) : 0);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        ret = 0;
    }

    LEAVE_PAL_CALL_RETURN(ret);
}

/* _DkStreamAttributesQuery of internal use. The function query attribute
   of streams by their URI */
int _DkStreamAttributesQuery (const char * uri, PAL_STREAM_ATTR * attr)
{
    struct handle_ops * ops = NULL;
    const char * type = NULL;

    int ret = parse_stream_uri (&uri, &type, &ops);

    if (ret < 0)
        return ret;

    if (!ops->attrquery)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->attrquery(type, uri, attr);
}

/* PAL call DkStreamAttributeQuery: query attribute of a stream by its
   URI, attr is memory given by user space. Return the pointer of attr
   if succeeded, or NULL if failed. Error code is notified */
PAL_BOL
DkStreamAttributesQuery (PAL_STR uri, PAL_STREAM_ATTR * attr)
{
    ENTER_PAL_CALL(DkStreamAttributesQuery);

    if (!uri || !attr) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    log_stream(uri);

    PAL_STREAM_ATTR attr_buf;

    int ret = _DkStreamAttributesQuery(uri, &attr_buf);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    memcpy(attr, &attr_buf, sizeof(PAL_STREAM_ATTR));
    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}

/* _DkStreamAttributesQuerybyHandle for internal use. Query attribute
   of streams by their handle */
int _DkStreamAttributesQuerybyHandle (PAL_HANDLE hdl, PAL_STREAM_ATTR * attr)
{
    if (UNKNOWN_HANDLE(hdl))
        return -PAL_ERROR_BADHANDLE;

    const struct handle_ops * ops = HANDLE_OPS(hdl);

    assert(ops);

    /* if ops->attrquerybyhdl is not defined, the stream cannot be queried */
    if (!ops->attrquerybyhdl)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->attrquerybyhdl(hdl, attr);
}

/* PAL call DkStreamAttributesQuerybyHandle: Query attribute of a stream by
   its handle, attr is memory given by user space. Return the pointer of attr
   if succeeded, or NULL if failed. Error code is notified */
PAL_BOL
DkStreamAttributesQuerybyHandle (PAL_HANDLE handle, PAL_STREAM_ATTR * attr)
{
    ENTER_PAL_CALL(DkStreamAttributesQuerybyHandle);

    if (!handle || !attr) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    int ret = _DkStreamAttributesQuerybyHandle(handle, attr);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}

/* PAL call DkStreamAttributesSetbyHandle: Set attribute of a stream by
   its handle, attr is memory given by user space. Return the pointer of attr
   if succeeded, or NULL if failed. Error code is notified */
PAL_BOL
DkStreamAttributesSetbyHandle (PAL_HANDLE handle, PAL_STREAM_ATTR * attr)
{
    ENTER_PAL_CALL(DkStreamAttributesSetbyHandle);

    if (!handle || !attr) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    if (UNKNOWN_HANDLE(handle)) {
        _DkRaiseFailure(PAL_ERROR_BADHANDLE);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    const struct handle_ops * ops = HANDLE_OPS(handle);

    assert(ops);

    if (!ops->attrsetbyhdl) {
        _DkRaiseFailure(PAL_ERROR_NOTSUPPORT);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    int ret = ops->attrsetbyhdl(handle, attr);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}

int _DkStreamGetName (PAL_HANDLE handle, char * buffer, int size)
{
    const struct handle_ops * ops = HANDLE_OPS(handle);
    assert(ops);

    /* if ops->getname is not defined, the stream cannot be queried */
    if (!ops->getname)
        return -PAL_ERROR_NOTSUPPORT;

    int ret = ops->getname(handle, buffer, size - 1);

    if (ret < 0)
        return ret;

    ((char *)buffer)[ret] = 0;
    return ret;
}

/* PAL call DkStreamAttributesSetbyHandle: Set attribute of a stream by
   its handle, attr is memory given by user space. Return the pointer of attr
   if succeeded, or NULL if failed. Error code is notified */
PAL_NUM DkStreamGetName (PAL_HANDLE handle, PAL_PTR buffer, PAL_NUM size)
{
    ENTER_PAL_CALL(DkStreamGetName);

    if (!handle || !buffer || !size) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(0);
    }

    if (UNKNOWN_HANDLE(handle)) {
        _DkRaiseFailure(PAL_ERROR_BADHANDLE);
        LEAVE_PAL_CALL_RETURN(0);
    }

    int ret = _DkStreamGetName(handle, (void *) buffer, size);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        ret = 0;
    }

    LEAVE_PAL_CALL_RETURN(ret);
}

/* _DkStreamMap for internal use. Map specific handle to certain memory,
   with given protection, offset and size */
int _DkStreamMap (PAL_HANDLE handle, void ** paddr, int prot, uint64_t offset,
                  uint64_t size)
{
    void * addr = *paddr;
    int ret;

    const struct handle_ops * ops = HANDLE_OPS(handle);

    /* if ops or ops->map is not defined, the stream cannot be mapped */
    if (!ops || !ops->map)
        return -PAL_ERROR_NOTSUPPORT;

    if ((ret = ops->map(handle, &addr, prot, offset, size)) < 0)
        return ret;

    *paddr = addr;
    return 0;
}

/* PAL call DkStreamMap: Map a stream of a given handle to certain memery
   space. prot/offset/size are the protection, offset and size of the memory
   mapping. Return the address if succeeded or NULL if failed. Error code
   is notified. */
PAL_PTR
DkStreamMap (PAL_HANDLE handle, PAL_PTR addr, PAL_FLG prot, PAL_NUM offset,
             PAL_NUM size)
{
    ENTER_PAL_CALL(DkStreamMap);
    void * map_addr = (void *) addr;

    if (!handle) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN((PAL_PTR) NULL);
    }

    /* Check that all addresses and sizes are aligned */
    if ((addr && !ALLOC_ALIGNED(addr)) || !size || !ALLOC_ALIGNED(size) ||
        !ALLOC_ALIGNED(offset)) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN((PAL_PTR) NULL);
    }


    if (map_addr && _DkCheckMemoryMappable((void *) map_addr, size)) {
        _DkRaiseFailure(PAL_ERROR_DENIED);
        LEAVE_PAL_CALL_RETURN((PAL_PTR) NULL);
    }

    int ret = _DkStreamMap(handle, &map_addr, prot, offset, size);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        map_addr = NULL;
    }

    LEAVE_PAL_CALL_RETURN((PAL_PTR) map_addr);
}

/* PAL call DkStreamUnmap: Unmap memory mapped at an address. The memory has
   to be a stream map, and it got unmapped as a whole memory area. No
   return value. Error code is notified */
void DkStreamUnmap (PAL_PTR addr, PAL_NUM size)
{
    ENTER_PAL_CALL(DkStreamUnmap);

    if (!addr || !ALLOC_ALIGNED((void *) addr) || !size || !ALLOC_ALIGNED(size)) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL();
    }

    if (_DkCheckMemoryMappable((void *) addr, size)) {
        _DkRaiseFailure(PAL_ERROR_DENIED);
        LEAVE_PAL_CALL();
    }

    int ret = _DkStreamUnmap((void *) addr, size);

    if (ret < 0)
        _DkRaiseFailure(-ret);

    LEAVE_PAL_CALL();
}

/* _DkStreamSetLength for internal use. This function truncate the stream
   to certain length. This call might not be support for certain streams */
int64_t _DkStreamSetLength (PAL_HANDLE handle, uint64_t length)
{
    if (UNKNOWN_HANDLE(handle))
        return -PAL_ERROR_BADHANDLE;

    const struct handle_ops * ops = HANDLE_OPS(handle);

    if (!ops || !ops->setlength)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->setlength(handle, length);
}

/* PAL call DkStreamSetLength: Truncate the stream at certain length.
   Return the length if succeeded or 0 if failed. Error code is notified. */
PAL_NUM
DkStreamSetLength (PAL_HANDLE handle, PAL_NUM length)
{
    ENTER_PAL_CALL(DkStreamSetLength);

    if (!handle) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(0);
    }

    int64_t ret = _DkStreamSetLength(handle, length);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        ret = 0;
    }

    LEAVE_PAL_CALL_RETURN(ret);
}

/* _DkStreamFlush for internal use. This function sync up the handle with
   devices. Some streams may not support this operations. */
int _DkStreamFlush (PAL_HANDLE handle)
{
    if (UNKNOWN_HANDLE(handle))
        return -PAL_ERROR_BADHANDLE;

    const struct handle_ops * ops = HANDLE_OPS(handle);

    if (!ops || !ops->flush)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->flush(handle);
}

/* PAL call DkStreamFlush: Sync up a stream of a given handle. No return
   value. Error code is notified. */
PAL_BOL DkStreamFlush (PAL_HANDLE handle)
{
    ENTER_PAL_CALL(DkStreamFlush);

    if (!handle) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    int ret = _DkStreamFlush(handle);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}

/* PAL call DkSendHandle: Write to a process handle.
   Return 1 on success and 0 on failure */
PAL_BOL DkSendHandle(PAL_HANDLE handle, PAL_HANDLE cargo)
{
    ENTER_PAL_CALL(DkSendHandle);

    // Return error if any of the handle is NULL
    if (!handle || !cargo) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    // Call the internal function after validating input args
    int ret = _DkSendHandle(handle, cargo);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}

/* PAL call DkRecvHandle: Read a handle to a pipe/process handle.
   Return the received PAL_HANDLE by reference and 0 on success and 
   negative number on failure */
/* 1. Should i take the received PAL_HANDLE as an input argument and 
      pass by reference or return it rather? 
    Ans - We are not aware of the size of the variable members to return
   2. Would the recieved PAL_HANDLE start functioning automatically in
      the new process environment? Should we initialize/modify some 
      attibutes of the handle?
    Ans - Yes, Initialize and make it compatibile in the target process
   3. Should malloc_copy be done or the process shares the same references?
    Ans - Variables members have to allocated data again.
*/
PAL_HANDLE DkReceiveHandle (PAL_HANDLE handle)
{
    ENTER_PAL_CALL(DkReceiveHandle);

    // return error if any of the handle is NULL
    if(!handle) {
        _DkRaiseFailure(PAL_ERROR_INVAL);
        LEAVE_PAL_CALL_RETURN(NULL);
    }

    // create a reference for the received PAL_HANDLE
    PAL_HANDLE cargo = NULL;
    // call the internal function after validating input args
    int ret = _DkReceiveHandle(handle, &cargo);

    // notify failure would have been called from other functions
    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(NULL);
    }

    assert(cargo);
    assert(PAL_GET_TYPE(cargo));
    LEAVE_PAL_CALL_RETURN(cargo);
}

PAL_BOL DkStreamChangeName (PAL_HANDLE hdl, PAL_STR uri)
{
    ENTER_PAL_CALL(DkStreamChangeName);

    struct handle_ops * ops = NULL;
    const char * type = NULL;
    int ret;

    if (uri) {
        ret = parse_stream_uri(&uri, &type, &ops);

        if (ret < 0) {
            _DkRaiseFailure(-ret);
            LEAVE_PAL_CALL_RETURN(PAL_FALSE);
        }
    }

    const struct handle_ops * hops = HANDLE_OPS(hdl);

    if (!hops || !hops->rename || (ops && hops != ops)) {
        _DkRaiseFailure(PAL_ERROR_NOTSUPPORT);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    ret = hops->rename(hdl, type, uri);

    if (ret < 0) {
        _DkRaiseFailure(-ret);
        LEAVE_PAL_CALL_RETURN(PAL_FALSE);
    }

    LEAVE_PAL_CALL_RETURN(PAL_TRUE);
}

/* _DkStreamRealpath is used to obtain the real path of a stream. Some
   streams may not have a real path. */
const char * _DkStreamRealpath (PAL_HANDLE hdl)
{
    const struct handle_ops * ops = HANDLE_OPS(hdl);

    if (!ops || !ops->getrealpath)
        return NULL;

    return ops->getrealpath(hdl);
}
