/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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
 * db_files.c
 *
 * This file contains operands to handle streams with URIs that start with
 * "file:" or "dir:".
 */
#undef __GLIBC__

#include "pal_defs.h"
#include "pal_freebsd_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_freebsd.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "api.h"

#include <sys/stat.h>
#include <sys/fcntl.h>
#include <errno.h>

#include <sys/types.h>
typedef __kernel_pid_t pid_t;

/* 'open' operation for file streams */
static int file_open (PAL_HANDLE * handle, const char * type, const char * uri,
                      int access, int share, int create, int options)
{
    int flags = HOST_FILE_OPEN(access, create, options);
    int mode = HOST_PERM(share);

    /* try to do the real open */
    int ret = INLINE_SYSCALL(open, 3, uri, flags|O_CLOEXEC, mode);

    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    /* if try_create_path succeeded, prepare for the file handle */
    int len = strlen(uri);
    PAL_HANDLE hdl = malloc(HANDLE_SIZE(file) + len + 1);
    SET_HANDLE_TYPE(hdl, file);
    hdl->hdr.flags |= RFD(0)|WFD(0)|WRITEABLE(0);
    hdl->file.fd = ret;
    hdl->file.offset = 0;
    hdl->file.append = 0;
    hdl->file.pass = 0;
    char * path = (void *) hdl + HANDLE_SIZE(file);
    memcpy(path, uri, len + 1);
    hdl->file.realpath = path;
    *handle = hdl;
    return 0;
}

#ifndef SEEK_SET
# define SEEK_SET 0
#endif

/* 'read' operation for file streams. */
static int file_read (PAL_HANDLE handle, int offset, int count,
                      void * buffer)
{
    int fd = handle->file.fd;
    int ret;
    if (handle->file.offset != offset) {
        ret = INLINE_SYSCALL(lseek, 3, fd, offset, SEEK_SET);

        if (IS_ERR(ret))
            return -PAL_ERROR_DENIED;

        handle->file.offset = offset;
    }

    ret = INLINE_SYSCALL(read, 3, fd, buffer, count);

    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    handle->file.offset = offset + ret;
    return ret;
}

/* 'write' operation for file streams. */
static int file_write (PAL_HANDLE handle, int offset, int count,
                       const void * buffer)
{
    int fd = handle->file.fd;
    int ret;

    if (handle->file.offset != offset) {
        ret = INLINE_SYSCALL(lseek, 3, fd, offset, SEEK_SET);
        if (IS_ERR(ret))
            return -PAL_ERROR_DENIED;

        handle->file.offset = offset;
    }

    ret = INLINE_SYSCALL(write, 3, fd, buffer, count);

    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    handle->file.offset = offset + ret;
    return ret;
}

/* 'close' operation for file streams. In this case, it will only
   close the file withou deleting it. */
static int file_close (PAL_HANDLE handle)
{
    int fd = handle->file.fd;

    int ret = INLINE_SYSCALL(close, 1, fd);

    if (handle->file.realpath &&
        handle->file.realpath != (void *) handle + HANDLE_SIZE(file))
        free((void *) handle->file.realpath);

    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : 0;
}

/* 'delete' operation for file streams. It will actually delete
   the file if we can successfully close it. */
static int file_delete (PAL_HANDLE handle, int access)
{
    if (access)
        return -PAL_ERROR_INVAL;

    INLINE_SYSCALL(unlink, 1, handle->file.realpath);
    return 0;
}

/* 'map' operation for file stream. */
static int file_map (PAL_HANDLE handle, void ** addr, int prot,
                     int offset, int size)
{
    int fd = handle->file.fd;
    void * mem = *addr;
    int flags = MAP_FILE|HOST_FLAGS(0, prot)|(mem ? MAP_FIXED : 0);
    prot = HOST_PROT(prot);

    /* The memory will always allocated with flag MAP_PRIVATE
       and MAP_FILE */

    mem = (void *) ARCH_MMAP(mem, size, prot, flags, fd, offset);

    if (IS_ERR_P(mem))
        return -PAL_ERROR_DENIED;

    *addr = mem;
    return 0;
}

/* 'setlength' operation for file stream. */
static int file_setlength (PAL_HANDLE handle, int length)
{
    int ret = INLINE_SYSCALL(ftruncate, 2, handle->file.fd, length);

    if (IS_ERR(ret))
        return (ERRNO(ret) == EINVAL || ERRNO(ret) == EBADF) ?
               -PAL_ERROR_BADHANDLE : -PAL_ERROR_DENIED;

    return length;
}

/* 'flush' operation for file stream. */
static int file_flush (PAL_HANDLE handle)
{
    int ret = INLINE_SYSCALL(fsync, 1, handle->file.fd);

    if (IS_ERR(ret))
        return (ERRNO(ret) == EINVAL || ERRNO(ret) == EBADF) ?
               -PAL_ERROR_BADHANDLE : -PAL_ERROR_DENIED;

    return 0;
}

static inline int file_stat_type (struct stat * stat)
{
    if (S_ISREG(stat->st_mode))
        return pal_type_file;
    if (S_ISDIR(stat->st_mode))
        return pal_type_dir;
    if (S_ISCHR(stat->st_mode))
        return pal_type_dev;
    if (S_ISFIFO(stat->st_mode))
        return pal_type_pipe;
    if (S_ISSOCK(stat->st_mode))
        return pal_type_dev;

    return 0;
}

/* copy attr content from POSIX stat struct to PAL_STREAM_ATTR */
static inline void
file_attrcopy (PAL_STREAM_ATTR * attr, struct stat * stat)
{
    attr->handle_type  = file_stat_type(stat);
    attr->disconnected = PAL_FALSE;
    attr->nonblocking  = PAL_FALSE;
    attr->readable     = stataccess(stat, ACCESS_R);
    attr->writeable    = stataccess(stat, ACCESS_W);
    attr->runnable     = stataccess(stat, ACCESS_X);
    attr->share_flags  = stat->st_mode;
    attr->pending_size = stat->st_size;
}

/* 'attrquery' operation for file streams */
static int file_attrquery (const char * type, const char * uri,
                           PAL_STREAM_ATTR * attr)
{
    struct stat stat_buf;
    /* try to do the real open */
    int ret = INLINE_SYSCALL(stat, 2, uri, &stat_buf);

    /* if it failed, return the right error code */
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    file_attrcopy(attr, &stat_buf);
    return 0;
}

/* 'attrquerybyhdl' operation for file streams */
static int file_attrquerybyhdl (PAL_HANDLE handle,
                                PAL_STREAM_ATTR * attr)
{
    int fd = handle->hdr.fds[0];
    struct stat stat_buf;

    int ret = INLINE_SYSCALL(fstat, 2, fd, &stat_buf);

    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    file_attrcopy(attr, &stat_buf);
    return 0;
}

static int file_attrsetbyhdl (PAL_HANDLE handle,
                              PAL_STREAM_ATTR * attr)
{
    int fd = handle->hdr.fds[0], ret;

    ret = INLINE_SYSCALL(fchmod, 2, fd, attr->share_flags);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    return 0;
}

static int file_rename (PAL_HANDLE handle, const char * type,
                        const char * uri)
{
    int ret = INLINE_SYSCALL(rename, 2, handle->file.realpath, uri);

    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    handle->file.realpath = malloc_copy(uri, strlen(uri));
    return 0;
}

static int file_getname (PAL_HANDLE handle, char * buffer, int count)
{
    if (!handle->file.realpath)
        return 0;

    int len = strlen(handle->file.realpath);
    char * tmp = strcpy_static(buffer, "file:", count);

    if (!tmp || buffer + count < tmp + len + 1)
        return -PAL_ERROR_TOOLONG;

    memcpy(tmp, handle->file.realpath, len + 1);
    return tmp + len - buffer;
}

const char * file_getrealpath (PAL_HANDLE handle)
{
    return handle->file.realpath;
}

struct handle_ops file_ops = {
        .getname            = &file_getname,
        .getrealpath        = &file_getrealpath,
        .open               = &file_open,
        .read               = &file_read,
        .write              = &file_write,
        .close              = &file_close,
        .delete             = &file_delete,
        .map                = &file_map,
        .setlength          = &file_setlength,
        .flush              = &file_flush,
        .attrquery          = &file_attrquery,
        .attrquerybyhdl     = &file_attrquerybyhdl,
        .attrsetbyhdl       = &file_attrsetbyhdl,
        .rename             = &file_rename,
    };

/* 'open' operation for directory stream. Directory stream does not have a
   specific type prefix, its URI looks the same file streams, plus it
   ended with slashes. dir_open will be called by file_open. */
static int dir_open (PAL_HANDLE * handle, const char * type, const char * uri,
                     int access, int share, int create, int options)
{
    int ret;
    int mode = HOST_PERM(share);

    if (create & PAL_CREAT_TRY) {
        ret = INLINE_SYSCALL(mkdir, 2, uri, mode);

        if (IS_ERR(ret) && ERRNO(ret) == EEXIST &&
            create & PAL_CREAT_ALWAYS)
            return -PAL_ERROR_STREAMEXIST;
    }

    ret = INLINE_SYSCALL(open, 3, uri, O_DIRECTORY|options|O_CLOEXEC, 0);

    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    int len = strlen(uri);
    PAL_HANDLE hdl = malloc(HANDLE_SIZE(dir) + len + 1);
    SET_HANDLE_TYPE(hdl, dir);
    hdl->hdr.flags |= RFD(0);
    hdl->dir.fd = ret;
    char * path = (void *) hdl + HANDLE_SIZE(dir);
    memcpy(path, uri, len + 1);
    hdl->dir.realpath = path;
    hdl->dir.buf = NULL;
    hdl->dir.ptr = NULL;
    hdl->dir.end = NULL;
    hdl->dir.endofstream = false;
    *handle = hdl;
    return 0;
}

struct dirent {
        __uint32_t d_fileno;            /* file number of entry */
        __uint16_t d_reclen;            /* length of this record */
        __uint8_t  d_type;              /* file type, see below */
        __uint8_t  d_namlen;            /* length of string in d_name */
        char    d_name[255 + 1];        /* name must be no longer than this */
};

#define DT_UNKNOWN      0
#define DT_FIFO         1
#define DT_CHR          2
#define DT_DIR          4
#define DT_BLK          6
#define DT_REG          8
#define DT_LNK          10
#define DT_SOCK         12
#define DT_WHT          14

#define DIRBUF_SIZE     1024

/* 'read' operation for directory stream. Directory stream will not
   need a 'write' operat4on. */
int dir_read (PAL_HANDLE handle, int offset, int count, void * buf)
{
    void * dent_buf = handle->dir.buf ? : __alloca(DIRBUF_SIZE);
    void * ptr = handle->dir.ptr;
    void * end = handle->dir.end;
    int bytes = 0;

    if (ptr && ptr < end)
        goto output;

    do {
        if (handle->dir.endofstream)
            break;

        int size = INLINE_SYSCALL(getdents, 3, handle->dir.fd, dent_buf,
                                  DIRBUF_SIZE); 

        if (IS_ERR(size))
            return -PAL_ERROR_DENIED;

        if (size == 0) {
            handle->dir.endofstream = PAL_TRUE;
            break;
        }

        ptr = dent_buf;
        end = dent_buf + size;

output:
        while (ptr < end) {
            struct dirent * d = (struct dirent *) ptr;

            if (d->d_name[0] == '.' &&
                (!d->d_name[1] || d->d_name[1] == '.'))
                goto next;

            bool isdir = (d->d_type == DT_DIR);
            int len = d->d_namlen;
            if (len + (isdir ? 2 : 1) > count)
                break;

            memcpy(buf, d->d_name, len);
            if (isdir)
                ((char *) buf)[len++] = '/';
            ((char *) buf)[len++] = '\0';

            bytes += len;
            buf += len;
            count -= len;
next:
            ptr += d->d_reclen;
        }
    } while (ptr == end);

    if (ptr < end) {
        if (!handle->dir.buf)
            handle->dir.buf = malloc(DIRBUF_SIZE);

        if (handle->dir.buf != ptr) {
            memmove(handle->dir.buf, ptr, end - ptr);
            end = handle->dir.buf + (end - ptr);
            ptr = handle->dir.buf;
        }

        if (!bytes)
            return -PAL_ERROR_OVERFLOW;
    }

    return bytes ? : -PAL_ERROR_ENDOFSTREAM;
}

/* 'close' operation of directory streams */
static int dir_close (PAL_HANDLE handle)
{
    int fd = handle->dir.fd;

    int ret = INLINE_SYSCALL(close, 1, fd);

    if (handle->dir.buf) {
        free(handle->dir.buf);
        handle->dir.buf = handle->dir.ptr = handle->dir.end = NULL;
    }

    if (handle->dir.realpath &&
        handle->dir.realpath != (void *) handle + HANDLE_SIZE(dir))
        free((void *) handle->dir.realpath);

    if (IS_ERR(ret))
        return -PAL_ERROR_BADHANDLE;

    return 0;
}

/* 'delete' operation of directoy streams */
static int dir_delete (PAL_HANDLE handle, int access)
{
    if (access)
        return -PAL_ERROR_INVAL;

    int ret = dir_close(handle);

    if (ret < 0)
        return ret;

    ret = INLINE_SYSCALL(rmdir, 1, handle->dir.realpath);

    return (IS_ERR(ret) && ERRNO(ret) != ENOENT) ?
           -PAL_ERROR_DENIED : 0;
}

static int dir_rename (PAL_HANDLE handle, const char * type,
                       const char * uri)
{
    int ret = INLINE_SYSCALL(rename, 2, handle->dir.realpath, uri);

    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    handle->dir.realpath = malloc_copy(uri, strlen(uri));
    return 0;
}

static int dir_getname (PAL_HANDLE handle, char * buffer, int count)
{
    if (!handle->dir.realpath)
        return 0;

    int len = strlen(handle->dir.realpath);
    char * tmp = strcpy_static(buffer, "file:", count);

    if (!tmp || buffer + count < tmp + len + 1)
        return -PAL_ERROR_TOOLONG;

    memcpy(tmp, handle->dir.realpath, len + 1);
    return tmp + len - buffer;
}

static const char * dir_getrealpath (PAL_HANDLE handle)
{
    return handle->dir.realpath;
}

struct handle_ops dir_ops = {
        .getname            = &dir_getname,
        .getrealpath        = &dir_getrealpath,
        .open               = &dir_open,
        .read               = &dir_read,
        .close              = &dir_close,
        .delete             = &dir_delete,
        .attrquery          = &file_attrquery,
        .attrquerybyhdl     = &file_attrquerybyhdl,
        .attrsetbyhdl       = &file_attrsetbyhdl,
        .rename             = &dir_rename,
    };
