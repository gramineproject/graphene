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
    [pal_type_file]    = &g_file_ops,
    [pal_type_pipe]    = &g_pipe_ops,
    [pal_type_pipesrv] = &g_pipe_ops,
    [pal_type_pipecli] = &g_pipe_ops,
    [pal_type_pipeprv] = &g_pipeprv_ops,
    [pal_type_dev]     = &g_dev_ops,
    [pal_type_dir]     = &g_dir_ops,
    [pal_type_tcp]     = &g_tcp_ops,
    [pal_type_tcpsrv]  = &g_tcp_ops,
    [pal_type_udp]     = &g_udp_ops,
    [pal_type_udpsrv]  = &g_udpsrv_ops,
    [pal_type_process] = &g_proc_ops,
    [pal_type_thread]  = &g_thread_ops,
    [pal_type_event]   = &g_event_ops,
    [pal_type_eventfd] = &g_eventfd_ops,
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

    assert(WITHIN_MASK(access,  PAL_ACCESS_MASK));
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
    assert(current_context_is_libos());
    current_context_set_pal();

    *handle = NULL;
    int ret = _DkStreamOpen(handle, uri, access, share, create, options);

    current_context_set_libos();
    return ret;
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
    assert(current_context_is_libos());
    current_context_set_pal();

    *client = NULL;
    int ret = _DkStreamWaitForClient(handle, client);

    current_context_set_libos();
    return ret;
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
    assert(current_context_is_libos());
    current_context_set_pal();

    if (!handle) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    int ret = _DkStreamDelete(handle, access);

    current_context_set_libos();
    return ret;
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
    assert(current_context_is_libos());
    current_context_set_pal();

    if (!handle || !buffer) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    int64_t ret = _DkStreamRead(handle, offset, *count, (void*)buffer, size ? (char*)source : NULL,
                                source ? size : 0);

    if (ret < 0) {
        current_context_set_libos();
        return ret;
    }

    *count = ret;

    current_context_set_libos();
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
    assert(current_context_is_libos());
    current_context_set_pal();

    if (!handle || !buffer) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    int64_t ret = _DkStreamWrite(handle, offset, *count, (void*)buffer, dest,
                                 dest ? strlen(dest) : 0);

    if (ret < 0) {
        current_context_set_libos();
        return ret;
    }

    *count = ret;

    current_context_set_libos();
    return 0;
}

/* _DkStreamAttributesQuery of internal use. The function query attribute
   of streams by their URI */
int _DkStreamAttributesQuery(const char* uri, PAL_STREAM_ATTR* attr) {
    struct handle_ops* ops = NULL;
    char* type             = NULL;

    int ret = parse_stream_uri(&uri, &type, &ops);

    if (ret < 0)
        return ret;

    if (!ops->attrquery)
        return -PAL_ERROR_NOTSUPPORT;

    ret = ops->attrquery(type, uri, attr);
    free(type);
    return ret;
}

int DkStreamAttributesQuery(PAL_STR uri, PAL_STREAM_ATTR* attr) {
    assert(current_context_is_libos());
    current_context_set_pal();

    if (!uri || !attr) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    PAL_STREAM_ATTR attr_buf;

    int ret = _DkStreamAttributesQuery(uri, &attr_buf);

    if (ret < 0) {
        current_context_set_libos();
        return ret;
    }

    memcpy(attr, &attr_buf, sizeof(PAL_STREAM_ATTR));

    current_context_set_libos();
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
    assert(current_context_is_libos());
    current_context_set_pal();

    if (!handle || !attr) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    int ret = _DkStreamAttributesQueryByHandle(handle, attr);

    current_context_set_libos();
    return ret;
}

int DkStreamAttributesSetByHandle(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    assert(current_context_is_libos());
    current_context_set_pal();

    if (!handle || !attr) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    const struct handle_ops* ops = HANDLE_OPS(handle);
    if (!ops) {
        current_context_set_libos();
        return -PAL_ERROR_BADHANDLE;
    }

    if (!ops->attrsetbyhdl) {
        current_context_set_libos();
        return -PAL_ERROR_NOTSUPPORT;
    }

    int ret = ops->attrsetbyhdl(handle, attr);

    current_context_set_libos();
    return ret;
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
    assert(current_context_is_libos());
    current_context_set_pal();

    if (!handle || !buffer || !size) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    int ret = _DkStreamGetName(handle, (void*)buffer, size);

    current_context_set_libos();
    return ret;
}

/* _DkStreamMap for internal use. Map specific handle to certain memory,
   with given protection, offset and size */
int _DkStreamMap(PAL_HANDLE handle, void** paddr, int prot, uint64_t offset, uint64_t size) {
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
    assert(current_context_is_libos());
    current_context_set_pal();

    assert(addr);
    void* map_addr = *addr;

    if (!handle) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    if (map_addr && !IS_ALLOC_ALIGNED_PTR(map_addr)) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }
    if (!size || !IS_ALLOC_ALIGNED(size) || !IS_ALLOC_ALIGNED(offset)) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    if (map_addr && _DkCheckMemoryMappable(map_addr, size)) {
        current_context_set_libos();
        return -PAL_ERROR_DENIED;
    }

    int ret = _DkStreamMap(handle, addr, prot, offset, size);

    current_context_set_libos();
    return ret;
}

int DkStreamUnmap(PAL_PTR addr, PAL_NUM size) {
    assert(current_context_is_libos());
    current_context_set_pal();

    if (!addr || !IS_ALLOC_ALIGNED_PTR(addr) || !size || !IS_ALLOC_ALIGNED(size)) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    if (_DkCheckMemoryMappable((void*)addr, size)) {
        current_context_set_libos();
        return -PAL_ERROR_DENIED;
    }

    int ret = _DkStreamUnmap((void*)addr, size);

    current_context_set_libos();
    return ret;
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
    assert(current_context_is_libos());
    current_context_set_pal();

    if (!handle) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    int64_t ret = _DkStreamSetLength(handle, length);

    if (ret < 0) {
        current_context_set_libos();
        return ret;
    }

    assert((uint64_t)ret == length);
    current_context_set_libos();
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
    assert(current_context_is_libos());
    current_context_set_pal();

    if (!handle) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    int ret = _DkStreamFlush(handle);

    current_context_set_libos();
    return ret;
}

int DkSendHandle(PAL_HANDLE handle, PAL_HANDLE cargo) {
    assert(current_context_is_libos());
    current_context_set_pal();

    // Return error if any of the handle is NULL
    if (!handle || !cargo) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    int ret = _DkSendHandle(handle, cargo);

    current_context_set_libos();
    return ret;
}

int DkReceiveHandle(PAL_HANDLE handle, PAL_HANDLE* cargo) {
    assert(current_context_is_libos());
    current_context_set_pal();

    // return error if any of the handle is NULL
    if (!handle) {
        current_context_set_libos();
        return -PAL_ERROR_INVAL;
    }

    *cargo = NULL;
    int ret = _DkReceiveHandle(handle, cargo);

    current_context_set_libos();
    return ret;
}

int DkStreamChangeName(PAL_HANDLE hdl, PAL_STR uri) {
    assert(current_context_is_libos());
    current_context_set_pal();

    struct handle_ops* ops = NULL;
    char* type             = NULL;
    int ret;

    if (uri) {
        ret = parse_stream_uri(&uri, &type, &ops);

        if (ret < 0) {
            current_context_set_libos();
            return ret;
        }
    }

    const struct handle_ops* hops = HANDLE_OPS(hdl);

    if (!hops || !hops->rename || (ops && hops != ops)) {
        free(type);
        current_context_set_libos();
        return -PAL_ERROR_NOTSUPPORT;
    }

    ret = hops->rename(hdl, type, uri);
    free(type);

    current_context_set_libos();
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
    assert(current_context_is_libos());
    current_context_set_pal();

    int ret = _DkDebugLog(buffer, size);

    current_context_set_libos();
    return ret;
}
