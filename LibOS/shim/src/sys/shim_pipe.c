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
 * shim_pipe.c
 *
 * Implementation of system call "pipe", "pipe2" and "socketpair".
 */

#include <asm/fcntl.h>
#include <errno.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_table.h>
#include <shim_utils.h>

int create_pipes(IDTYPE* pipeid, PAL_HANDLE* srv, PAL_HANDLE* cli, struct shim_qstr* qstr,
                 int flags) {
    PAL_HANDLE hdl0 = NULL, hdl1 = NULL, hdl2 = NULL;
    int ret = 0;
    char uri[PIPE_URI_SIZE];

    if ((ret = create_pipe(pipeid, uri, PIPE_URI_SIZE, &hdl0, qstr,
                           /*use_vmid_for_name=*/false)) < 0) {
        debug("pipe creation failure\n");
        return ret;
    }

    if (!(hdl2 = DkStreamOpen(uri, 0, 0, 0, flags & O_NONBLOCK))) {
        ret = -PAL_ERRNO;
        debug("pipe connection failure\n");
        goto err;
    }

    if (!(hdl1 = DkStreamWaitForClient(hdl0))) {
        ret = -PAL_ERRNO;
        debug("pipe acception failure\n");
        goto err;
    }

    DkStreamDelete(hdl0, 0);
    DkObjectClose(hdl0);
    *srv = hdl1;
    *cli = hdl2;
    return 0;
err:
    if (hdl1)
        DkObjectClose(hdl1);
    if (hdl2)
        DkObjectClose(hdl2);
    DkStreamDelete(hdl0, 0);
    DkObjectClose(hdl0);
    return ret;
}

int shim_do_pipe2(int* filedes, int flags) {
    if (!filedes || test_user_memory(filedes, 2 * sizeof(int), true))
        return -EFAULT;

    int ret = 0;

    struct shim_handle* hdl1 = get_new_handle();
    struct shim_handle* hdl2 = get_new_handle();

    if (!hdl1 || !hdl2) {
        ret = -ENOMEM;
        goto out;
    }

    hdl1->type = TYPE_PIPE;
    set_handle_fs(hdl1, &pipe_builtin_fs);
    hdl1->flags    = O_RDONLY;
    hdl1->acc_mode = MAY_READ;

    hdl2->type = TYPE_PIPE;
    set_handle_fs(hdl2, &pipe_builtin_fs);
    hdl2->flags    = O_WRONLY;
    hdl2->acc_mode = MAY_WRITE;

    if ((ret = create_pipes(&hdl1->info.pipe.pipeid, &hdl1->pal_handle, &hdl2->pal_handle,
                            &hdl1->uri, flags)) < 0)
        goto out;

    qstrcopy(&hdl2->uri, &hdl2->uri);

    flags    = flags & O_CLOEXEC ? FD_CLOEXEC : 0;
    int vfd1 = set_new_fd_handle(hdl1, flags, NULL);
    int vfd2 = set_new_fd_handle(hdl2, flags, NULL);

    if (vfd1 < 0 || vfd2 < 0) {
        if (vfd1 >= 0) {
            struct shim_handle* tmp = detach_fd_handle(vfd1, NULL, NULL);
            if (tmp)
                put_handle(tmp);
        }
        if (vfd2 >= 0) {
            struct shim_handle* tmp = detach_fd_handle(vfd2, NULL, NULL);
            if (tmp)
                put_handle(tmp);
        }
        ret = (vfd1 < 0) ? vfd1 : vfd2;
        goto out;
    }

    filedes[0] = vfd1;
    filedes[1] = vfd2;
out:
    if (hdl1)
        put_handle(hdl1);
    if (hdl2)
        put_handle(hdl2);
    return ret;
}

int shim_do_pipe(int* filedes) {
    return shim_do_pipe2(filedes, 0);
}

int shim_do_socketpair(int domain, int type, int protocol, int* sv) {
    if (domain != AF_UNIX)
        return -EAFNOSUPPORT;

    if (type != SOCK_STREAM)
        return -EPROTONOSUPPORT;

    if (!sv || test_user_memory(sv, 2 * sizeof(int), true))
        return -EFAULT;

    int ret                  = 0;
    struct shim_handle* hdl1 = get_new_handle();
    struct shim_handle* hdl2 = get_new_handle();

    if (!hdl1 || !hdl2) {
        ret = -ENOMEM;
        goto out;
    }

    struct shim_sock_handle* sock1 = &hdl1->info.sock;
    struct shim_sock_handle* sock2 = &hdl2->info.sock;

    hdl1->type = TYPE_SOCK;
    set_handle_fs(hdl1, &socket_builtin_fs);
    hdl1->flags       = O_RDONLY;
    hdl1->acc_mode    = MAY_READ | MAY_WRITE;
    sock1->domain     = domain;
    sock1->sock_type  = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    sock1->protocol   = protocol;
    sock1->sock_state = SOCK_ACCEPTED;

    hdl2->type = TYPE_SOCK;
    set_handle_fs(hdl2, &socket_builtin_fs);
    hdl1->flags       = O_WRONLY;
    hdl2->acc_mode    = MAY_READ | MAY_WRITE;
    sock2->domain     = domain;
    sock2->sock_type  = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    sock2->protocol   = protocol;
    sock2->sock_state = SOCK_CONNECTED;

    if ((ret = create_pipes(&sock1->addr.un.pipeid, &hdl1->pal_handle, &hdl2->pal_handle,
                            &hdl1->uri, type & SOCK_NONBLOCK ? O_NONBLOCK : 0)) < 0)
        goto out;

    sock2->addr.un.pipeid = sock1->addr.un.pipeid;
    qstrcopy(&hdl2->uri, &hdl1->uri);

    int flags = type & SOCK_CLOEXEC ? FD_CLOEXEC : 0;
    int vfd1  = set_new_fd_handle(hdl1, flags, NULL);
    int vfd2  = set_new_fd_handle(hdl2, flags, NULL);

    if (vfd1 < 0 || vfd2 < 0) {
        if (vfd1 >= 0) {
            struct shim_handle* tmp = detach_fd_handle(vfd1, NULL, NULL);
            if (tmp)
                put_handle(tmp);
        }
        if (vfd2 >= 0) {
            struct shim_handle* tmp = detach_fd_handle(vfd2, NULL, NULL);
            if (tmp)
                put_handle(tmp);
        }
        ret = (vfd1 < 0) ? vfd1 : vfd2;
        goto out;
    }

    sv[0] = vfd1;
    sv[1] = vfd2;
out:
    if (hdl1)
        put_handle(hdl1);
    if (hdl2)
        put_handle(hdl2);
    return ret;
}
