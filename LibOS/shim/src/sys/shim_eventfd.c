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
 * Implementation of system call "eventfd" and "eventfd2".
 */

#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_table.h>
#include <shim_handle.h>
#include <shim_fs.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>

#include <asm/fcntl.h>
#include <sys/eventfd.h>

int create_eventfd(PAL_HANDLE * efd, unsigned initval, int flags) {
    PAL_HANDLE hdl = NULL;
    int ret = 0;
    int pal_flags = 0;

    //Note: saving other flag options->EFD_CLOEXEC, and EFD_SEMAPHORE
    pal_flags = flags & EFD_NONBLOCK ? PAL_OPTION_NONBLOCK : 0;
    pal_flags = flags & EFD_CLOEXEC ? (PAL_OPTION_CLOEXEC | pal_flags) : pal_flags;
    pal_flags = flags & EFD_SEMAPHORE ? (PAL_OPTION_EFD_SEMAPHORE | pal_flags) : pal_flags;

    //Note: Passing initval as param for create, for lack of better option.
    if (!(hdl = DkStreamOpen(EVENTFD_URI_PREFIX, 0, 0, initval, pal_flags))) {
        ret = -PAL_ERRNO;
        debug("eventfd open failure\n");
        goto err;
    }

    *efd = hdl;
    return 0;

err:
    return ret;
}

int shim_do_eventfd2(int init, int flags) {

    if (test_user_memory((void *) &init, sizeof(unsigned int), true))
        return -EFAULT;

    int ret = 0;

    //Note: allocates from MEM_MGR buffer, and INC(hdl->ref_cnt)
    struct shim_handle * hdl = get_new_handle();

    if (!hdl) {
        ret = -ENOMEM;
        goto out;
    }

    hdl->type = TYPE_EVENTFD;
    set_handle_fs(hdl, &eventfd_builtin_fs);
    hdl->flags = O_RDWR;
    hdl->acc_mode = MAY_READ | MAY_WRITE;

    if ((ret = create_eventfd(&hdl->pal_handle, init, flags)) < 0)
        goto out;

    flags = flags & EFD_CLOEXEC ? FD_CLOEXEC : 0;
    //Note: maps hdl<=>vfd in hdl's map array, and also INC(hdl->ref_cnt)
    //in __set_new_fd_handle using get_handle(hdl).
    int vfd = set_new_fd_handle(hdl, flags, NULL);

    if (vfd < 0) {
        goto out;
    }

    ret = vfd;

out:
    if (hdl)
        put_handle(hdl);

    return ret;

}

int shim_do_eventfd(unsigned int init) {
    return shim_do_eventfd2(init, 0);
}
