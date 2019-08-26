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
 * shim_clone.c
 *
 * Implementation of system call "dup", "dup2" and "dup3".
 */

#include <errno.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_utils.h>

int shim_do_dup(int fd) {
    struct shim_handle_map* handle_map = get_cur_handle_map(NULL);
    int flags                          = 0;

    struct shim_handle* hdl = get_fd_handle(fd, &flags, handle_map);
    if (!hdl)
        return -EBADF;

    int vfd = set_new_fd_handle(hdl, flags, handle_map);
    put_handle(hdl);
    return vfd < 0 ? -EMFILE : vfd;
}

int shim_do_dup2(int oldfd, int newfd) {
    struct shim_handle_map* handle_map = get_cur_handle_map(NULL);

    struct shim_handle* hdl = get_fd_handle(oldfd, NULL, handle_map);
    if (!hdl)
        return -EBADF;

    struct shim_handle* new_hdl = detach_fd_handle(newfd, NULL, handle_map);

    if (new_hdl)
        put_handle(new_hdl);

    int vfd = set_new_fd_handle_by_fd(newfd, hdl, 0, handle_map);
    put_handle(hdl);
    return vfd < 0 ? -EMFILE : vfd;
}

int shim_do_dup3(int oldfd, int newfd, int flags) {
    struct shim_handle_map* handle_map = get_cur_handle_map(NULL);
    struct shim_handle* hdl            = get_fd_handle(oldfd, NULL, handle_map);
    if (!hdl)
        return -EBADF;

    struct shim_handle* new_hdl = detach_fd_handle(newfd, NULL, handle_map);

    if (new_hdl)
        put_handle(new_hdl);

    int vfd = set_new_fd_handle_by_fd(newfd, hdl, flags, handle_map);
    put_handle(hdl);
    return vfd < 0 ? -EMFILE : vfd;
}
