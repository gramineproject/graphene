/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Implementation of system call "fcntl":
 *
 * - F_DUPFD, F_DUPFD_CLOEXEC (duplicate a file descriptor)
 * - F_GETFD, F_SETFD (file descriptor flags)
 * - F_GETFL, F_SETFL (file status flags)
 * - F_SETLK, F_SETLKW, F_GETLK (POSIX advisory locks)
 * - F_SETOWN (file descriptor owner): dummy implementation
 */

#include <errno.h>
#include <linux/fcntl.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_fs.h"
#include "shim_fs_lock.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_table.h"
#include "shim_thread.h"
#include "shim_utils.h"

#define FCNTL_SETFL_MASK (O_APPEND | O_NONBLOCK)

static int _set_handle_flags(struct shim_handle* hdl, unsigned long arg) {
    if (hdl->fs && hdl->fs->fs_ops && hdl->fs->fs_ops->setflags) {
        int ret = hdl->fs->fs_ops->setflags(hdl, arg & FCNTL_SETFL_MASK);
        if (ret < 0) {
            return ret;
        }
    }
    hdl->flags = (hdl->flags & ~FCNTL_SETFL_MASK) | (arg & FCNTL_SETFL_MASK);
    return 0;
}

int set_handle_nonblocking(struct shim_handle* hdl, bool on) {
    lock(&hdl->lock);
    int ret = _set_handle_flags(hdl, on ? hdl->flags | O_NONBLOCK : hdl->flags & ~O_NONBLOCK);
    unlock(&hdl->lock);
    return ret;
}

/*
 * Convert user-mode `struct flock` into our `struct posix_lock`. This mostly means converting the
 * position parameters (l_whence, l_start, l_len) to an absolute inclusive range [start .. end]. See
 * `man fcntl` for details.
 *
 * We need to return -EINVAL for underflow (positions before start of file), and -EOVERFLOW for
 * positive overflow.
 */
static int flock_to_posix_lock(struct flock* fl, struct shim_handle* hdl, struct posix_lock* pl) {
    if (!(fl->l_type == F_RDLCK || fl->l_type == F_WRLCK || fl->l_type == F_UNLCK))
        return -EINVAL;

    int ret;

    struct shim_fs* fs = hdl->fs;
    assert(fs && fs->fs_ops);

    uint64_t origin;
    switch (fl->l_whence) {
        case SEEK_SET:
            origin = 0;
            break;
        case SEEK_CUR: {
            if (!fs->fs_ops->seek)
                return -EINVAL;

            off_t pos = fs->fs_ops->seek(hdl, 0, SEEK_CUR);
            if (pos < 0)
                return pos;
            origin = pos;
            break;
        }
        case SEEK_END: {
            if (!fs->fs_ops->hstat)
                return -EINVAL;

            struct stat stat;
            ret = fs->fs_ops->hstat(hdl, &stat);
            if (ret < 0)
                return ret;
            assert(stat.st_size >= 0);
            origin = stat.st_size;
            break;
        }
        default:
            return -EINVAL;
    }

    if (__builtin_add_overflow(origin, fl->l_start, &origin)) {
        return fl->l_start > 0 ? -EOVERFLOW : -EINVAL;
    }

    uint64_t start, end;
    if (fl->l_len > 0) {
        /* len > 0: the range is [origin .. origin + len - 1] */
        start = origin;
        if (__builtin_add_overflow(origin, fl->l_len - 1, &end))
            return -EOVERFLOW;
    } else if (fl->l_len < 0) {
        /* len < 0: the range is [origin + len .. origin - 1] */
        if (__builtin_add_overflow(origin, fl->l_len, &start))
            return -EINVAL;
        if (__builtin_add_overflow(origin, -1, &end))
            return -EINVAL;
    } else {
        /* len == 0: the range is [origin .. EOF] */
        start = origin;
        end = FS_LOCK_EOF;
    }

    pl->type = fl->l_type;
    pl->start = start;
    pl->end = end;
    pl->pid = g_process.pid;
    return 0;
}

long shim_do_fcntl(int fd, int cmd, unsigned long arg) {
    struct shim_handle_map* handle_map = get_thread_handle_map(NULL);
    int flags;
    int ret;

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
            ret = set_new_fd_handle_above_fd(arg, hdl, flags, handle_map);
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
            flags |= FD_CLOEXEC;
            ret = set_new_fd_handle_above_fd(arg, hdl, flags, handle_map);
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
        case F_SETFL:
            lock(&hdl->lock);
            ret = _set_handle_flags(hdl, arg);
            unlock(&hdl->lock);
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
         *
         * F_SETLKW (struct flock *)
         *   As for F_SETLK, but if a conflicting lock is held on the file,
         *   then wait for that lock to be released. If a signal is caught while
         *   waiting, then the call is interrupted and (after the signal handler
         *   has returned) returns immediately (with return value -1 and errno
         *   set to EINTR; see signal(7)).
         */
        case F_SETLK:
        case F_SETLKW: {
            struct flock *fl = (struct flock*)arg;
            if (!is_user_memory_readable(fl, sizeof(*fl))) {
                ret = -EFAULT;
                break;
            }

            if (!hdl->dentry) {
                /* TODO: Linux allows locks on pipes etc. Our locks work only for "normal" files
                 * that have a dentry. */
                ret = -EINVAL;
                break;
            }

            if (fl->l_type == F_RDLCK && !(hdl->acc_mode & MAY_READ)) {
                ret = -EINVAL;
                break;
            }

            if (fl->l_type == F_WRLCK && !(hdl->acc_mode & MAY_WRITE)) {
                ret = -EINVAL;
                break;
            }

            struct posix_lock pl;
            ret = flock_to_posix_lock(fl, hdl, &pl);
            if (ret < 0)
                break;

            ret = posix_lock_set(hdl->dentry, &pl, /*wait=*/cmd == F_SETLKW);
            break;
        }

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
        case F_GETLK: {
            struct flock *fl = (struct flock*)arg;
            if (!is_user_memory_readable(fl, sizeof(*fl))
                    || !is_user_memory_writable(fl, sizeof(*fl))) {
                ret = -EFAULT;
                break;
            }

            if (!hdl->dentry) {
                ret = -EINVAL;
                break;
            }

            struct posix_lock pl;
            ret = flock_to_posix_lock(fl, hdl, &pl);
            if (ret < 0)
                break;

            if (pl.type == F_UNLCK) {
                ret = -EINVAL;
                break;
            }

            struct posix_lock pl2;
            ret = posix_lock_get(hdl->dentry, &pl, &pl2);
            if (ret < 0)
                break;

            fl->l_type = pl2.type;
            if (pl2.type != F_UNLCK) {
                fl->l_whence = SEEK_SET;
                fl->l_start = pl2.start;
                fl->l_len = pl2.end - pl2.start + 1;
                fl->l_pid = pl2.pid;
            }
            ret = 0;
            break;
        }

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

        default:
            ret = -EINVAL;
            break;
    }

    put_handle(hdl);
    return ret;
}
