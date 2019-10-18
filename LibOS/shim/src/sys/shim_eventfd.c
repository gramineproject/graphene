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
 * Implementation of system calls "eventfd" and "eventfd2".
 */

#include <asm/fcntl.h>
#include <sys/eventfd.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_table.h>
#include <shim_handle.h>
#include <shim_fs.h>

int create_eventfd(PAL_HANDLE* efd, unsigned count, int flags) {
    PAL_HANDLE hdl = NULL;
    int pal_flags = 0;

    pal_flags |= flags & EFD_NONBLOCK ? PAL_OPTION_NONBLOCK : 0;
    pal_flags |= flags & EFD_CLOEXEC ? PAL_OPTION_CLOEXEC : 0;
    pal_flags |= flags & EFD_SEMAPHORE ? PAL_OPTION_EFD_SEMAPHORE : 0;

    /* eventfd() requires initval but PAL's DkStreamOpen() doesn't have such an argument.
     * Using `create` argument as a work-around;
     * one issue is initval's type is unsigned int, but create is int32 in_DkStreamOpen */
    if (!(hdl = DkStreamOpen("eventfd:", 0, 0, count, pal_flags))) {
        debug("eventfd open failure\n");
        return -PAL_ERRNO;
    }

    *efd = hdl;
    return 0;

}

int shim_do_eventfd2(unsigned int count, int flags) {
    if (test_user_memory((void *) &count, sizeof(unsigned int), false))
        return -EFAULT;

    int ret = 0;
    struct shim_handle* hdl = get_new_handle();

    if (!hdl) {
        ret = -ENOMEM;
        goto out;
    }

    hdl->type = TYPE_EVENTFD;
    set_handle_fs(hdl, &eventfd_builtin_fs);
    hdl->flags = O_RDWR;
    hdl->acc_mode = MAY_READ | MAY_WRITE;

    if ((ret = create_eventfd(&hdl->pal_handle, count, flags)) < 0)
        goto out;

    flags = flags & EFD_CLOEXEC ? FD_CLOEXEC : 0;

    /* get_new_handle() above increments hdl's refcount.
     * Followed by another increment inside set_new_fd_handle.
     * So we need to put_handle() afterwards */
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
