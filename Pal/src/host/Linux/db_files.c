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

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "api.h"

#include <linux/types.h>
typedef __kernel_pid_t pid_t;
#undef __GLIBC__
#include <linux/stat.h>
#include <asm/errno.h>

/* 'open' operation for file streams */
static int file_open (PAL_HANDLE * handle, const char * type, const char * uri,
                      int access, int share, int create, int options)
{
    if (strcmp_static(type, URI_TYPE_FILE))
        return -PAL_ERROR_INVAL;

    /* try to do the real open */
    int ret = INLINE_SYSCALL(open, 3, uri,
                             HOST_ACCESS(access)|create|options|O_CLOEXEC,
                             share);

    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    /* if try_create_path succeeded, prepare for the file handle */
    size_t len = strlen(uri);
    PAL_HANDLE hdl = malloc(HANDLE_SIZE(file) + len + 1);
    SET_HANDLE_TYPE(hdl, file);
    HANDLE_HDR(hdl)->flags |= RFD(0)|WFD(0);
    hdl->file.fd = ret;
    hdl->file.map_start = NULL;
    char * path = (void *) hdl + HANDLE_SIZE(file);
    memcpy(path, uri, len + 1);
    hdl->file.realpath = (PAL_STR) path;
    *handle = hdl;
    return 0;
}

/* 'read' operation for file streams. */
static int64_t file_read (PAL_HANDLE handle, uint64_t offset, uint64_t count,
                          void * buffer)
{
    int fd = handle->file.fd;
    int64_t ret;

    ret = INLINE_SYSCALL(pread64, 4, fd, buffer, count, offset);

    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    return ret;
}

/* 'write' operation for file streams. */
static int64_t file_write (PAL_HANDLE handle, uint64_t offset, uint64_t count,
                           const void * buffer)
{
    int fd = handle->file.fd;
    int64_t ret;

    ret = INLINE_SYSCALL(pwrite64, 4, fd, buffer, count, offset);

    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    return ret;
}

/* 'close' operation for file streams. In this case, it will only
   close the file withou deleting it. */
static int file_close (PAL_HANDLE handle)
{
    int fd = handle->file.fd;

    int ret = INLINE_SYSCALL(close, 1, fd);

    /* initial realpath is part of handle object and will be freed with it */
    if (handle->file.realpath &&
        handle->file.realpath != (void *) handle + HANDLE_SIZE(file)) {
        free((void *) handle->file.realpath);
    }

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
                     uint64_t offset, uint64_t size)
{
    int fd = handle->file.fd;
    void * mem = *addr;
    /*
     * work around for fork emulation
     * the first exec image to be loaded has to be at same address
     * as parent.
     */
    if (mem == NULL && handle->file.map_start != NULL) {
        mem = (PAL_PTR)handle->file.map_start;
        /* this address is used. don't over-map it later */
        handle->file.map_start = NULL;
    }
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
static int64_t file_setlength (PAL_HANDLE handle, uint64_t length)
{
    int ret = INLINE_SYSCALL(ftruncate, 2, handle->file.fd, length);

    if (IS_ERR(ret))
        return (ERRNO(ret) == EINVAL || ERRNO(ret) == EBADF) ?
               -PAL_ERROR_BADHANDLE : -PAL_ERROR_DENIED;

    return (int64_t) length;
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
    attr->writable     = stataccess(stat, ACCESS_W);
    attr->runnable     = stataccess(stat, ACCESS_X);
    attr->share_flags  = stat->st_mode;
    attr->pending_size = stat->st_size;
}

/* 'attrquery' operation for file streams */
static int file_attrquery (const char * type, const char * uri,
                           PAL_STREAM_ATTR * attr)
{
    if (strcmp_static(type, URI_TYPE_FILE) && strcmp_static(type, URI_TYPE_DIR))
        return -PAL_ERROR_INVAL;

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
    int fd = handle->generic.fds[0];
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
    int fd = handle->generic.fds[0], ret;

    ret = INLINE_SYSCALL(fchmod, 2, fd, attr->share_flags | 0600);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    return 0;
}

static int file_rename (PAL_HANDLE handle, const char * type,
                        const char * uri)
{
    if (strcmp_static(type, URI_TYPE_FILE))
        return -PAL_ERROR_INVAL;

    char* tmp = strdup(uri);
    if (!tmp)
        return -PAL_ERROR_NOMEM;

    int ret = INLINE_SYSCALL(rename, 2, handle->file.realpath, uri);
    if (IS_ERR(ret)) {
        free(tmp);
        return unix_to_pal_error(ERRNO(ret));
    }

    /* initial realpath is part of handle object and will be freed with it */
    if (handle->file.realpath &&
            handle->file.realpath != (void *) handle + HANDLE_SIZE(file)) {
        free((void *) handle->file.realpath);
    }

    handle->file.realpath = tmp;
    return 0;
}

static int file_getname (PAL_HANDLE handle, char * buffer, size_t count)
{
    if (!handle->file.realpath)
        return 0;

    size_t len = strlen(handle->file.realpath);
    char * tmp = strcpy_static(buffer, URI_PREFIX_FILE, count);

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
    if (strcmp_static(type, URI_TYPE_DIR))
        return -PAL_ERROR_INVAL;
    if (!WITHIN_MASK(access, PAL_ACCESS_MASK))
        return -PAL_ERROR_INVAL;

    int ret = 0;

    if (create & PAL_CREATE_TRY) {
        ret = INLINE_SYSCALL(mkdir, 2, uri, share);

        if (IS_ERR(ret) && ERRNO(ret) == EEXIST &&
            create & PAL_CREATE_ALWAYS)
            return -PAL_ERROR_STREAMEXIST;
    }

    ret = INLINE_SYSCALL(open, 3, uri, O_DIRECTORY|options|O_CLOEXEC, 0);

    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    size_t len = strlen(uri);
    PAL_HANDLE hdl = malloc(HANDLE_SIZE(dir) + len + 1);
    SET_HANDLE_TYPE(hdl, dir);
    HANDLE_HDR(hdl)->flags |= RFD(0);
    hdl->dir.fd = ret;
    char * path = (void *) hdl + HANDLE_SIZE(dir);
    memcpy(path, uri, len + 1);
    hdl->dir.realpath = (PAL_STR) path;
    hdl->dir.buf = (PAL_PTR) NULL;
    hdl->dir.ptr = (PAL_PTR) NULL;
    hdl->dir.end = (PAL_PTR) NULL;
    hdl->dir.endofstream = PAL_FALSE;
    *handle = hdl;
    return 0;
}

struct linux_dirent64 {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
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

static inline bool is_dot_or_dotdot(const char* name) {
    return (name[0] == '.' && !name[1]) || (name[0] == '.' && name[1] == '.' && !name[2]);
}

/* 'read' operation for directory stream. Directory stream will not
   need a 'write' operation. */
static int64_t dir_read(PAL_HANDLE handle, uint64_t offset, size_t count, void* _buf) {
    size_t bytes_written = 0;
    char* buf = (char*)_buf;

    if (offset) {
        return -PAL_ERROR_INVAL;
    }

    if (handle->dir.endofstream == PAL_TRUE) {
        return -PAL_ERROR_ENDOFSTREAM;
    }

    while (1) {
        while ((char*)handle->dir.ptr < (char*)handle->dir.end) {
            struct linux_dirent64* dirent = (struct linux_dirent64*)handle->dir.ptr;

            if (is_dot_or_dotdot(dirent->d_name)) {
                goto skip;
            }

            bool is_dir = dirent->d_type == DT_DIR;
            size_t len = strlen(dirent->d_name);

            if (len + 1 + (is_dir ? 1 : 0) > count) {
                goto out;
            }

            memcpy(buf, dirent->d_name, len);
            if (is_dir) {
                buf[len++] = '/';
            }
            buf[len++] = '\0';

            buf += len;
            bytes_written += len;
            count -= len;
skip:
            handle->dir.ptr = (char*)handle->dir.ptr + dirent->d_reclen;
        }

        if (!count) {
            /* No space left, returning */
            goto out;
        }

        if (!handle->dir.buf) {
            handle->dir.buf = (PAL_PTR)malloc(DIRBUF_SIZE);
            if (!handle->dir.buf) {
                return -PAL_ERROR_NOMEM;
            }
        }

        int size = INLINE_SYSCALL(getdents64, 3, handle->dir.fd, handle->dir.buf, DIRBUF_SIZE);
        if (IS_ERR(size)) {
            /* If something was written just return that and pretend
             * no error was seen - it will be caught next time. */
            if (bytes_written) {
                return bytes_written;
            }
            return unix_to_pal_error(ERRNO(size));
        }

        if (!size) {
            handle->dir.endofstream = PAL_TRUE;
            goto out;
        }

        handle->dir.ptr = handle->dir.buf;
        handle->dir.end = (char*)handle->dir.buf + size;
    }

out:
    return (int64_t)bytes_written ? : -PAL_ERROR_ENDOFSTREAM;
}

/* 'close' operation of directory streams */
static int dir_close (PAL_HANDLE handle)
{
    int fd = handle->dir.fd;

    int ret = INLINE_SYSCALL(close, 1, fd);

    if (handle->dir.buf) {
        free((void *) handle->dir.buf);
        handle->dir.buf = handle->dir.ptr = handle->dir.end = (PAL_PTR) NULL;
    }

    /* initial realpath is part of handle object and will be freed with it */
    if (handle->dir.realpath &&
        handle->dir.realpath != (void *) handle + HANDLE_SIZE(dir)) {
        free((void *) handle->dir.realpath);
    }

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
    if (strcmp_static(type, URI_TYPE_DIR))
        return -PAL_ERROR_INVAL;

    char* tmp = strdup(uri);
    if (!tmp)
        return -PAL_ERROR_NOMEM;

    int ret = INLINE_SYSCALL(rename, 2, handle->dir.realpath, uri);
    if (IS_ERR(ret)) {
        free(tmp);
        return unix_to_pal_error(ERRNO(ret));
    }

    /* initial realpath is part of handle object and will be freed with it */
    if (handle->dir.realpath &&
            handle->dir.realpath != (void *) handle + HANDLE_SIZE(dir)) {
        free((void *) handle->dir.realpath);
    }

    handle->dir.realpath = tmp;
    return 0;
}

static int dir_getname (PAL_HANDLE handle, char * buffer, size_t count)
{
    if (!handle->dir.realpath)
        return 0;

    size_t len = strlen(handle->dir.realpath);
    char * tmp = strcpy_static(buffer, URI_PREFIX_DIR, count);

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
