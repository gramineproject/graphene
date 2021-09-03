/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs to open, read, write and get attribute of streams.
 */

#include "api.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"

/* Stream handler table: this table corresponds to all the handle type supported by PAL. Threads
 * are not streams, so they need no handler. */
extern struct handle_ops g_file_ops;
extern struct handle_ops g_pipe_ops;
extern struct handle_ops g_pipeprv_ops;
extern struct handle_ops g_dev_ops;
extern struct handle_ops g_dir_ops;
extern struct handle_ops g_tcp_ops;
extern struct handle_ops g_udp_ops;
extern struct handle_ops g_udpsrv_ops;
extern struct handle_ops g_thread_ops;
extern struct handle_ops g_proc_ops;
extern struct handle_ops g_event_ops;
extern struct handle_ops g_eventfd_ops;

const struct handle_ops* g_pal_handle_ops[PAL_HANDLE_TYPE_BOUND] = {
    [PAL_TYPE_FILE]    = &g_file_ops,
    [PAL_TYPE_PIPE]    = &g_pipe_ops,
    [PAL_TYPE_PIPESRV] = &g_pipe_ops,
    [PAL_TYPE_PIPECLI] = &g_pipe_ops,
    [PAL_TYPE_PIPEPRV] = &g_pipeprv_ops,
    [PAL_TYPE_DEV]     = &g_dev_ops,
    [PAL_TYPE_DIR]     = &g_dir_ops,
    [PAL_TYPE_TCP]     = &g_tcp_ops,
    [PAL_TYPE_TCPSRV]  = &g_tcp_ops,
    [PAL_TYPE_UDP]     = &g_udp_ops,
    [PAL_TYPE_UDPSRV]  = &g_udpsrv_ops,
    [PAL_TYPE_PROCESS] = &g_proc_ops,
    [PAL_TYPE_THREAD]  = &g_thread_ops,
    [PAL_TYPE_EVENT]   = &g_event_ops,
    [PAL_TYPE_EVENTFD] = &g_eventfd_ops,
};

/* parse_stream_uri scan the uri, seperate prefix and search for
   stream handler which will open or access the stream */
static int parse_stream_uri(const char** uri, char** prefix, struct handle_ops** ops) {
    const char* p;
    const char* u = *uri;

    for (p = u; (*p) && (*p) != ':'; p++)
        ;

    if ((*p) != ':')
        return -PAL_ERROR_INVAL;

    ++p;

    struct handle_ops* hops = NULL;

    switch (p - u) {
        case 4: ;
            static_assert(static_strlen(URI_PREFIX_DIR) == 4, "URI_PREFIX_DIR has unexpected length");
            static_assert(static_strlen(URI_PREFIX_TCP) == 4, "URI_PREFIX_TCP has unexpected length");
            static_assert(static_strlen(URI_PREFIX_UDP) == 4, "URI_PREFIX_UDP has unexpected length");
            static_assert(static_strlen(URI_PREFIX_DEV) == 4, "URI_PREFIX_DEV has unexpected length");

            if (strstartswith(u, URI_PREFIX_DIR))
                hops = &g_dir_ops;
            else if (strstartswith(u, URI_PREFIX_TCP))
                hops = &g_tcp_ops;
            else if (strstartswith(u, URI_PREFIX_UDP))
                hops = &g_udp_ops;
            else if (strstartswith(u, URI_PREFIX_DEV))
                hops = &g_dev_ops;
            break;

        case 5: ;
            static_assert(static_strlen(URI_PREFIX_FILE) == 5, "URI_PREFIX_FILE has unexpected length");
            static_assert(static_strlen(URI_PREFIX_PIPE) == 5, "URI_PREFIX_PIPE has unexpected length");

            if (strstartswith(u, URI_PREFIX_FILE))
                hops = &g_file_ops;
            else if (strstartswith(u, URI_PREFIX_PIPE))
                hops = &g_pipe_ops;
            break;

        case 8: ;
            static_assert(static_strlen(URI_PREFIX_TCP_SRV) == 8, "URI_PREFIX_TCP_SRV has unexpected length");
            static_assert(static_strlen(URI_PREFIX_UDP_SRV) == 8, "URI_PREFIX_UDP_SRV has unexpected length");
            static_assert(static_strlen(URI_PREFIX_EVENTFD) == 8, "URI_PREFIX_EVENTFD has unexpected length");

            if (strstartswith(u, URI_PREFIX_TCP_SRV))
                hops = &g_tcp_ops;
            else if (strstartswith(u, URI_PREFIX_UDP_SRV))
                hops = &g_udp_ops;
            else if (strstartswith(u, URI_PREFIX_EVENTFD))
                hops = &g_eventfd_ops;
            break;

        case 9: ;
            static_assert(static_strlen(URI_PREFIX_PIPE_SRV) == 9, "URI_PREFIX_PIPE_SRV has unexpected length");

            if (strstartswith(u, URI_PREFIX_PIPE_SRV))
                hops = &g_pipe_ops;
            break;

        default:
            break;
    }

    if (!hops)
        return -PAL_ERROR_NOTSUPPORT;

    *uri = p;

    if (prefix) {
        *prefix = malloc_copy(u, p - u);
        if (!*prefix)
            return -PAL_ERROR_NOMEM;
        /* We don't want ':' in prefix, replacing that with nullbyte which also ends the string. */
        (*prefix)[p - 1 - u] = '\0';
    }

    if (ops)
        *ops = hops;

    return 0;
}

/* _DkStreamOpen for internal use. Open stream based on uri. access/share/create/options are the
 * same flags defined for DkStreamOpen. */
int _DkStreamOpen(PAL_HANDLE* handle, const char* uri, int access, int share, int create,
                  int options) {
    struct handle_ops* ops = NULL;
    char* type = NULL;

    assert(0 <= access && access < PAL_ACCESS_BOUND);
    assert(WITHIN_MASK(share,   PAL_SHARE_MASK));
    assert(WITHIN_MASK(create,  PAL_CREATE_MASK));
    assert(WITHIN_MASK(options, PAL_OPTION_MASK));

    int ret = parse_stream_uri(&uri, &type, &ops);
    if (ret < 0)
        return ret;

    assert(ops && ops->open);
    ret = ops->open(handle, type, uri, access, share, create, options);
    free(type);
    return ret;
}

/* PAL call DkStreamOpen: Open stream based on uri, as given access/share/
   create/options flags. DkStreamOpen return a PAL_HANDLE to access the
   stream in `handle` argument.

   FIXME: Currently `share` must match 1-1 to Linux open() `mode` argument. This isn't really
   portable and will cause problems when implementing other PALs.
 */
int DkStreamOpen(PAL_STR uri, PAL_FLG access, PAL_FLG share, PAL_FLG create, PAL_FLG options,
                 PAL_HANDLE* handle) {
    *handle = NULL;
    return _DkStreamOpen(handle, uri, access, share, create, options);
}

static int _DkStreamWaitForClient(PAL_HANDLE handle, PAL_HANDLE* client) {
    if (UNKNOWN_HANDLE(handle))
        return -PAL_ERROR_BADHANDLE;

    const struct handle_ops* ops = HANDLE_OPS(handle);
    if (!ops)
        return -PAL_ERROR_BADHANDLE;

    if (!ops->waitforclient)
        return -PAL_ERROR_NOTSERVER;

    return ops->waitforclient(handle, client);
}

int DkStreamWaitForClient(PAL_HANDLE handle, PAL_HANDLE* client) {
    *client = NULL;
    return _DkStreamWaitForClient(handle, client);
}

/* _DkStreamDelete for internal use. This function will explicit delete
   the stream. For example, file will be deleted, socket witll be
   disconnected, etc */
int _DkStreamDelete(PAL_HANDLE handle, int access) {
    assert(access == 0 || access == PAL_DELETE_RD || access == PAL_DELETE_WR);

    const struct handle_ops* ops = HANDLE_OPS(handle);

    if (!ops)
        return -PAL_ERROR_BADHANDLE;

    if (!ops->delete)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->delete(handle, access);
}

int DkStreamDelete(PAL_HANDLE handle, PAL_FLG access) {
    if (!handle) {
        return -PAL_ERROR_INVAL;
    }

    return _DkStreamDelete(handle, access);
}

/* _DkStreamRead for internal use. Read from stream as absolute offset.
   The actual behavior of stream read is defined by handler */
int64_t _DkStreamRead(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buf, char* addr,
                      int addrlen) {
    const struct handle_ops* ops = HANDLE_OPS(handle);

    if (!ops)
        return -PAL_ERROR_BADHANDLE;

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

    return ret;
}

int DkStreamRead(PAL_HANDLE handle, PAL_NUM offset, PAL_NUM* count, PAL_PTR buffer, PAL_PTR source,
                 PAL_NUM size) {
    if (!handle || !buffer) {
        return -PAL_ERROR_INVAL;
    }

    int64_t ret = _DkStreamRead(handle, offset, *count, (void*)buffer, size ? (char*)source : NULL,
                                source ? size : 0);

    if (ret < 0) {
        return ret;
    }

    *count = ret;
    return 0;
}

/* _DkStreamWrite for internal use, write to stream at absolute offset.
   The actual behavior of stream write is defined by handler */
int64_t _DkStreamWrite(PAL_HANDLE handle, uint64_t offset, uint64_t count, const void* buf,
                       const char* addr, int addrlen) {
    const struct handle_ops* ops = HANDLE_OPS(handle);

    if (!ops)
        return -PAL_ERROR_BADHANDLE;

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

    return ret;
}

int DkStreamWrite(PAL_HANDLE handle, PAL_NUM offset, PAL_NUM* count, PAL_PTR buffer, PAL_STR dest) {
    if (!handle || !buffer) {
        return -PAL_ERROR_INVAL;
    }

    int64_t ret = _DkStreamWrite(handle, offset, *count, (void*)buffer, dest,
                                 dest ? strlen(dest) : 0);

    if (ret < 0) {
        return ret;
    }

    *count = ret;
    return 0;
}

/* _DkStreamAttributesQuery of internal use. The function query attribute
   of streams by their URI */
int _DkStreamAttributesQuery(const char* uri, PAL_STREAM_ATTR* attr) {
    struct handle_ops* ops = NULL;
    char* type = NULL;

    int ret = parse_stream_uri(&uri, &type, &ops);
    if (ret < 0)
        return ret;

    if (!ops->attrquery) {
        ret = -PAL_ERROR_NOTSUPPORT;
        goto out;
    }

    ret = ops->attrquery(type, uri, attr);
out:
    free(type);
    return ret;
}

int DkStreamAttributesQuery(PAL_STR uri, PAL_STREAM_ATTR* attr) {
    if (!uri || !attr) {
        return -PAL_ERROR_INVAL;
    }

    PAL_STREAM_ATTR attr_buf;

    int ret = _DkStreamAttributesQuery(uri, &attr_buf);

    if (ret < 0) {
        return ret;
    }

    memcpy(attr, &attr_buf, sizeof(PAL_STREAM_ATTR));
    return 0;
}

/* _DkStreamAttributesQueryByHandle for internal use. Query attribute
   of streams by their handle */
int _DkStreamAttributesQueryByHandle(PAL_HANDLE hdl, PAL_STREAM_ATTR* attr) {
    const struct handle_ops* ops = HANDLE_OPS(hdl);

    if (!ops)
        return -PAL_ERROR_BADHANDLE;

    if (!ops->attrquerybyhdl)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->attrquerybyhdl(hdl, attr);
}

int DkStreamAttributesQueryByHandle(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (!handle || !attr) {
        return -PAL_ERROR_INVAL;
    }

    return _DkStreamAttributesQueryByHandle(handle, attr);
}

int DkStreamAttributesSetByHandle(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (!handle || !attr) {
        return -PAL_ERROR_INVAL;
    }

    const struct handle_ops* ops = HANDLE_OPS(handle);
    if (!ops) {
        return -PAL_ERROR_BADHANDLE;
    }

    if (!ops->attrsetbyhdl) {
        return -PAL_ERROR_NOTSUPPORT;
    }

    return ops->attrsetbyhdl(handle, attr);
}

int _DkStreamGetName(PAL_HANDLE handle, char* buffer, size_t size) {
    const struct handle_ops* ops = HANDLE_OPS(handle);

    if (!ops)
        return -PAL_ERROR_BADHANDLE;

    if (!ops->getname)
        return -PAL_ERROR_NOTSUPPORT;

    int ret = ops->getname(handle, buffer, size ? size - 1 : 0);

    if (ret < 0)
        return ret;

    buffer[ret] = 0;
    return ret;
}

int DkStreamGetName(PAL_HANDLE handle, PAL_PTR buffer, PAL_NUM size) {
    if (!handle || !buffer || !size) {
        return -PAL_ERROR_INVAL;
    }

    return _DkStreamGetName(handle, (void*)buffer, size);
}

/* _DkStreamMap for internal use. Map specific handle to certain memory,
   with given protection, offset and size */
int _DkStreamMap(PAL_HANDLE handle, void** paddr, int prot, uint64_t offset, uint64_t size) {
    assert(IS_ALLOC_ALIGNED(offset));
    void* addr = *paddr;
    int ret;

    assert(WITHIN_MASK(prot, PAL_PROT_MASK));

    const struct handle_ops* ops = HANDLE_OPS(handle);

    if (!ops)
        return -PAL_ERROR_BADHANDLE;

    if (!ops->map)
        return -PAL_ERROR_NOTSUPPORT;

    if ((ret = ops->map(handle, &addr, prot, offset, size)) < 0)
        return ret;

    *paddr = addr;
    return 0;
}

int DkStreamMap(PAL_HANDLE handle, PAL_PTR* addr, PAL_FLG prot, PAL_NUM offset, PAL_NUM size) {
    assert(addr);
    void* map_addr = *addr;

    /* TODO: we must not allow NULL addresses here, but sendfile() in LibOS does it -- it must be
     *       re-written and then this function should enforce `map_addr != NULL` */

    if (!handle) {
        return -PAL_ERROR_INVAL;
    }

    if (map_addr && !IS_ALLOC_ALIGNED_PTR(map_addr)) {
        return -PAL_ERROR_INVAL;
    }
    if (!size || !IS_ALLOC_ALIGNED(size) || !IS_ALLOC_ALIGNED(offset)) {
        return -PAL_ERROR_INVAL;
    }

    if (map_addr && _DkCheckMemoryMappable(map_addr, size)) {
        return -PAL_ERROR_DENIED;
    }

    return _DkStreamMap(handle, addr, prot, offset, size);
}

int DkStreamUnmap(PAL_PTR addr, PAL_NUM size) {
    if (!addr || !IS_ALLOC_ALIGNED_PTR(addr) || !size || !IS_ALLOC_ALIGNED(size)) {
        return -PAL_ERROR_INVAL;
    }

    if (_DkCheckMemoryMappable((void*)addr, size)) {
        return -PAL_ERROR_DENIED;
    }

    return _DkStreamUnmap((void*)addr, size);
}

/* _DkStreamSetLength for internal use. This function truncate the stream
   to certain length. This call might not be support for certain streams */
int64_t _DkStreamSetLength(PAL_HANDLE handle, uint64_t length) {
    const struct handle_ops* ops = HANDLE_OPS(handle);

    if (!ops)
        return -PAL_ERROR_BADHANDLE;

    if (!ops->setlength)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->setlength(handle, length);
}

int DkStreamSetLength(PAL_HANDLE handle, PAL_NUM length) {
    if (!handle) {
        return -PAL_ERROR_INVAL;
    }

    int64_t ret = _DkStreamSetLength(handle, length);

    if (ret < 0) {
        return ret;
    }

    assert((uint64_t)ret == length);
    return 0;
}

/* _DkStreamFlush for internal use. This function sync up the handle with
   devices. Some streams may not support this operations. */
int _DkStreamFlush(PAL_HANDLE handle) {
    if (UNKNOWN_HANDLE(handle))
        return -PAL_ERROR_BADHANDLE;

    const struct handle_ops* ops = HANDLE_OPS(handle);

    if (!ops)
        return -PAL_ERROR_BADHANDLE;

    if (!ops->flush)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->flush(handle);
}

int DkStreamFlush(PAL_HANDLE handle) {
    if (!handle) {
        return -PAL_ERROR_INVAL;
    }

    return _DkStreamFlush(handle);
}

int DkSendHandle(PAL_HANDLE handle, PAL_HANDLE cargo) {
    // Return error if any of the handle is NULL
    if (!handle || !cargo) {
        return -PAL_ERROR_INVAL;
    }

    return _DkSendHandle(handle, cargo);
}

int DkReceiveHandle(PAL_HANDLE handle, PAL_HANDLE* cargo) {
    // return error if any of the handle is NULL
    if (!handle) {
        return -PAL_ERROR_INVAL;
    }

    *cargo = NULL;
    return _DkReceiveHandle(handle, cargo);
}

int DkStreamChangeName(PAL_HANDLE hdl, PAL_STR uri) {
    struct handle_ops* ops = NULL;
    char* type = NULL;
    int ret;

    if (uri) {
        ret = parse_stream_uri(&uri, &type, &ops);
        if (ret < 0) {
            return ret;
        }
    }

    const struct handle_ops* hops = HANDLE_OPS(hdl);

    if (!hops || !hops->rename || (ops && hops != ops)) {
        ret = -PAL_ERROR_NOTSUPPORT;
        goto out;
    }

    ret = hops->rename(hdl, type, uri);
out:
    free(type);
    return ret;
}

/* _DkStreamRealpath is used to obtain the real path of a stream. Some
   streams may not have a real path. */
const char* _DkStreamRealpath(PAL_HANDLE hdl) {
    const struct handle_ops* ops = HANDLE_OPS(hdl);

    if (!ops || !ops->getrealpath)
        return NULL;

    return ops->getrealpath(hdl);
}

int DkDebugLog(PAL_PTR buffer, PAL_NUM size) {
    return _DkDebugLog(buffer, size);
}
