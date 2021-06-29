/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2019 Intel Corporation */

/*
 * Implementation of system calls "eventfd" and "eventfd2". Since eventfd emulation currently relies
 * on the host, these system calls are disallowed by default due to security concerns. To use them,
 * they must be explicitly allowed through the "sys.insecure__allow_eventfd" manifest key.
 */

#include <asm/fcntl.h>
#include <sys/eventfd.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_table.h"
#include "shim_utils.h"
#include "toml.h"

static int create_eventfd(PAL_HANDLE* efd, unsigned count, int flags) {
    int ret;

    assert(g_manifest_root);
    bool allow_eventfd;
    ret = toml_bool_in(g_manifest_root, "sys.insecure__allow_eventfd", /*defaultval=*/false,
                       &allow_eventfd);
    if (ret < 0) {
        log_error("Cannot parse \'sys.insecure__allow_eventfd\' (the value must be `true` or "
                  "`false`)");
        return -ENOSYS;
    }

    if (!allow_eventfd) {
        /* eventfd is not explicitly allowed in manifest */
        return -ENOSYS;
    }

    PAL_HANDLE hdl = NULL;
    int pal_flags  = 0;

    pal_flags |= flags & EFD_NONBLOCK ? PAL_OPTION_NONBLOCK : 0;
    pal_flags |= flags & EFD_CLOEXEC ? PAL_OPTION_CLOEXEC : 0;
    pal_flags |= flags & EFD_SEMAPHORE ? PAL_OPTION_EFD_SEMAPHORE : 0;

    /* eventfd() requires count (aka initval) but PAL's DkStreamOpen() doesn't have such an
     * argument. Using create arg as a work-around (note: initval is uint32 but create is int32). */
    ret = DkStreamOpen(URI_PREFIX_EVENTFD, 0, 0, count, pal_flags, &hdl);
    if (ret < 0) {
        log_error("eventfd open failure");
        return pal_to_unix_errno(ret);
    }

    *efd = hdl;
    return 0;
}

long shim_do_eventfd2(unsigned int count, int flags) {
    int ret = 0;
    struct shim_handle* hdl = get_new_handle();

    if (!hdl) {
        ret = -ENOMEM;
        goto out;
    }

    hdl->type = TYPE_EVENTFD;
    hdl->fs = &eventfd_builtin_fs;
    hdl->flags = O_RDWR;
    hdl->acc_mode = MAY_READ | MAY_WRITE;

    if ((ret = create_eventfd(&hdl->pal_handle, count, flags)) < 0)
        goto out;

    flags = flags & EFD_CLOEXEC ? FD_CLOEXEC : 0;

    /* get_new_handle() above increments hdl's refcount. Followed by another increment inside
     * set_new_fd_handle. So we need to put_handle() afterwards. */
    int vfd = set_new_fd_handle(hdl, flags, NULL);

    ret = vfd;

out:
    if (hdl)
        put_handle(hdl);

    return ret;
}

long shim_do_eventfd(unsigned int count) {
    return shim_do_eventfd2(count, 0);
}
