/* Copyright (C) 2019 Intel Corporation
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
 * shim_eventfd.c
 *
 * Implementation of system calls "eventfd" and "eventfd2". Since eventfd emulation currently relies
 * on the host, these system calls are disallowed by default due to security concerns. To use them,
 * they must be explicitly allowed through the "sys.allow_insecure_eventfd" manifest key.
 */

#include <asm/fcntl.h>
#include <sys/eventfd.h>

#include <pal.h>
#include <pal_error.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_table.h>
#include <shim_utils.h>

static int create_eventfd(PAL_HANDLE* efd, unsigned count, int flags) {
    if (!root_config) {
        /* eventfd must be explicitly allowed in manifest; error out if no manifest found */
        return -ENOSYS;
    }

    char eventfd_cfg[2];
    ssize_t len =
        get_config(root_config, "sys.allow_insecure_eventfd", eventfd_cfg, sizeof(eventfd_cfg));
    if (len != 1 || eventfd_cfg[0] != '1') {
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
    if (!(hdl = DkStreamOpen(URI_PREFIX_EVENTFD, 0, 0, count, pal_flags))) {
        debug("eventfd open failure\n");
        return -PAL_ERRNO;
    }

    *efd = hdl;
    return 0;
}

int shim_do_eventfd2(unsigned int count, int flags) {
    int ret = 0;
    struct shim_handle* hdl = get_new_handle();

    if (!hdl) {
        ret = -ENOMEM;
        goto out;
    }

    hdl->type = TYPE_EVENTFD;
    set_handle_fs(hdl, &eventfd_builtin_fs);
    hdl->flags    = O_RDWR;
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

int shim_do_eventfd(unsigned int count) {
    return shim_do_eventfd2(count, 0);
}
