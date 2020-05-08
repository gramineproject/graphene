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

#include <shim_thread.h>

int shim_do_dup(unsigned int fd) {
    struct shim_handle_map* handle_map = get_cur_handle_map(NULL);

    struct shim_handle* hdl = get_fd_handle(fd, NULL, handle_map);
    if (!hdl)
        return -EBADF;

    // dup() always zeroes fd flags
    int vfd = set_new_fd_handle(hdl, /*fd_flags=*/0, handle_map);
    put_handle(hdl);
    return vfd == -ENOMEM ? -EMFILE : vfd;
}

int shim_do_dup2(unsigned int oldfd, unsigned int newfd) {
    if (oldfd == newfd)
        return -EINVAL;

    struct shim_handle_map* handle_map = get_cur_handle_map(NULL);
    struct shim_handle* hdl = get_fd_handle(oldfd, NULL, handle_map);
    if (!hdl)
        return -EBADF;

    struct shim_handle* new_hdl = detach_fd_handle(newfd, NULL, handle_map);

    if (new_hdl)
        put_handle(new_hdl);

    // dup2() always zeroes fd flags
    int vfd = set_new_fd_handle_by_fd(newfd, hdl, /*fd_flags=*/0, handle_map);
    put_handle(hdl);
    return vfd == -ENOMEM ? -EMFILE : vfd;
}

int shim_do_dup3(unsigned int oldfd, unsigned int newfd, int flags) {
    if ((flags & ~O_CLOEXEC) || oldfd == newfd)
        return -EINVAL;

    struct shim_handle_map* handle_map = get_cur_handle_map(NULL);
    struct shim_handle* hdl = get_fd_handle(oldfd, NULL, handle_map);
    if (!hdl)
        return -EBADF;

    struct shim_handle* new_hdl = detach_fd_handle(newfd, NULL, handle_map);

    if (new_hdl)
        put_handle(new_hdl);

    int fd_flags = (flags & O_CLOEXEC) ? FD_CLOEXEC : 0;
    int vfd = set_new_fd_handle_by_fd(newfd, hdl, fd_flags, handle_map);
    put_handle(hdl);
    return vfd == -ENOMEM ? -EMFILE : vfd;
}
