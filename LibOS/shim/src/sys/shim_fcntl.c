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
 * shim_fcntl.c
 *
 * Implementation of system call "fcntl".
 */

#include <errno.h>
#include <linux/fcntl.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_utils.h>

int shim_do_fcntl(int fd, int cmd, unsigned long arg) {
    struct shim_handle_map* handle_map = get_cur_handle_map(NULL);
    int flags;
    int ret = -ENOSYS;

    struct shim_handle* hdl = get_fd_handle(fd, &flags, handle_map);
    if (!hdl)
        return -EBADF;

    switch (cmd) {
        /* F_DUPFD (long)
         *   Find the lowest numbered available file descriptor greater than or
         *   equal to arg and make it be a copy of fd.  This is different from
         *   dup2(2), which uses exactly the descriptor specified.
         *   On success, the new descriptor is returned.
         */
        case F_DUPFD: {
            int vfd = arg;

            while (1) {
                if (set_new_fd_handle_by_fd(vfd, hdl, flags, handle_map) == vfd)
                    break;
                vfd++;
            };

            ret = vfd;
            break;
        }

        /* F_DUPFD_CLOEXEC (long; since Linux 2.6.24)
         *   As for F_DUPFD, but additionally set the close-on-exec flag for
         *   the duplicate descriptor.  Specifying this  flag  permits a
         *   program to avoid an additional fcntl() F_SETFD operation to set
         *   the FD_CLOEXEC flag.  For an explanation of why this flag is
         *   useful, see the description of O_CLOEXEC in open(2).
         */
        case F_DUPFD_CLOEXEC: {
            int vfd = arg;
            flags |= FD_CLOEXEC;

            while (1) {
                if (set_new_fd_handle_by_fd(vfd, hdl, flags, handle_map) == vfd)
                    break;
                vfd++;
            };

            ret = vfd;
            break;
        }

        /* File descriptor flags
         *   The following commands manipulate the flags associated with a file
         *   descriptor.  Currently, only one such flag is defined: FD_CLOEXEC,
         *   the close-on-exec flag.  If the FD_CLOEXEC bit is 0, the file
         *   descriptor will
         *   remain open across an execve(2), otherwise it will be closed.
         *
         * F_GETFD (void)
         *   Read the file descriptor flags; arg is ignored.
         */
        case F_GETFD:
            ret = flags & FD_CLOEXEC;
            break;

        /* F_SETFD (long)
         *   Set the file descriptor flags to the value specified by arg.
         */
        case F_SETFD:
            lock(&handle_map->lock);
            if (HANDLE_ALLOCATED(handle_map->map[fd]))
                handle_map->map[fd]->flags = arg & FD_CLOEXEC;
            unlock(&handle_map->lock);
            ret = 0;
            break;

        /* File status flags
         *   Each open file description has certain associated status flags,
         *   initialized by open(2) and possibly modified by fcntl().
         *   Duplicated file descriptors (made with dup(2), fcntl(F_DUPFD),
         *   fork(2), etc.) refer to the same open file description, and thus
         *   share the same file status flags.
         *   The file status flags and their semantics are described in open(2).
         *
         * F_GETFL (void)
         *   Read the file status flags; arg is ignored.
         */
        case F_GETFL:
            lock(&hdl->lock);
            flags = hdl->flags;
            unlock(&hdl->lock);
            ret = flags;
            break;

        /* F_SETFL (long)
         *   Set the file status flags to the value specified by arg.  File
         *   access mode (O_RDONLY, O_WRONLY, O_RDWR) and file creation flags
         *   (i.e., O_CREAT, O_EXCL, O_NOCTTY, O_TRUNC) in arg are ignored. On
         *   Linux this command can only change the O_APPEND, O_DIRECT,
         *   O_NOATIME, and O_NONBLOCK flags.
         */
#define FCNTL_SETFL_MASK (O_APPEND | O_NONBLOCK)
        case F_SETFL:
            lock(&hdl->lock);
            if (hdl->fs && hdl->fs->fs_ops && hdl->fs->fs_ops->setflags)
                hdl->fs->fs_ops->setflags(hdl, arg & FCNTL_SETFL_MASK);
            hdl->flags = (hdl->flags & ~FCNTL_SETFL_MASK) | (arg & FCNTL_SETFL_MASK);
            unlock(&hdl->lock);
            ret = 0;
            break;

        /* Advisory locking
         *   F_GETLK, F_SETLK and F_SETLKW are used to acquire, release, and
         *   test for the existence of record locks (also known as file-segment
         *   or file-region locks).  The third argument, lock, is a pointer to
         *   a structure that has at least the following fields (in unspecified
         *   order).
         *
         * F_SETLK (struct flock *)
         *   Acquire  a lock (when l_type is F_RDLCK or F_WRLCK) or release a
         *   lock (when l_type is F_UNLCK) on the bytes specified by the
         *   l_whence, l_start, and l_len fields of lock.  If a conflicting lock
         *   is held by another process, this call returns -1 and sets errno to
         *   EACCES or EAGAIN.
         */
        case F_SETLK:
            ret = -ENOSYS;
            break;

        /* F_SETLKW (struct flock *)
         *   As for F_SETLK, but if a conflicting lock is held on the file,
         *   then wait for that lock to be released. If a signal is caught while
         *   waiting, then the call is interrupted and (after the signal handler
         *   has returned) returns immediately (with return value -1 and errno
         *   set to EINTR; see signal(7)).
         */
        case F_SETLKW:
            ret = -ENOSYS;
            break;

        /* F_GETLK (struct flock *)
         *   On input to this call, lock describes a lock we would like to place
         *   on the file.  If the lock could be placed, fcntl() does not
         *   actually place it, but returns F_UNLCK in the l_type field of lock
         *   and leaves the other fields of the structure unchanged.  If one or
         *   more incompatible locks would prevent this lock being placed, then
         *   fcntl() returns details about one of these locks in the l_type,
         *   l_whence, l_start, and l_len fields of lock and sets l_pid to be
         *   the PID of the process holding that lock.
         */
        case F_GETLK:
            ret = -ENOSYS;
            break;

        /* F_SETOWN (int)
         *   Set  the process ID or process group ID that will receive SIGIO
         *   and SIGURG signals for events on file descriptor fd to the ID given
         *   in arg.  A process ID is specified as a positive value; a process
         *   group ID is specified as a negative value.  Most commonly, the
         *   calling process specifies itself as the owner (that is, arg is
         *   specified as getpid(2)).
         */
        case F_SETOWN:
            ret = 0;
            /* XXX: DUMMY for now */
            break;
    }

    put_handle(hdl);
    return ret;
}
