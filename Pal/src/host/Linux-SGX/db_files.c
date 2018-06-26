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

#include "pal_defs.h"
#include "pal_linux_defs.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_debug.h"
#include "pal_error.h"
#include "api.h"

#include <linux/types.h>
typedef __kernel_pid_t pid_t;
#undef __GLIBC__
#include <linux/stat.h>
#include <linux/fs.h>
#include <asm/stat.h>
#include <asm/fcntl.h>

#include "enclave_pages.h"

/* 'open' operation for file streams */
static int file_open (PAL_HANDLE * handle, const char * type, const char * uri,
                      int access, int share, int create, int options)
{
    /* try to do the real open */
    int fd = ocall_open(uri, access|create|options, share);

    if (fd < 0)
        return fd;

    /* if try_create_path succeeded, prepare for the file handle */
    int len = strlen(uri);
    PAL_HANDLE hdl = malloc(HANDLE_SIZE(file) + len + 1);
    SET_HANDLE_TYPE(hdl, file);
    HANDLE_HDR(hdl)->flags |= RFD(0)|WFD(0)|WRITEABLE(0);
    hdl->file.fd = fd;
    hdl->file.append = 0;
    hdl->file.pass = 0;
    char * path = (void *) hdl + HANDLE_SIZE(file);
    get_norm_path(uri, path, 0, len + 1);
    hdl->file.realpath = (PAL_STR) path;

    sgx_stub_t * stubs;
    uint64_t total;
    int ret = load_trusted_file(hdl, &stubs, &total, create);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Accessing file:%s is denied. (%s) "
                "This file is not trusted or allowed.\n", hdl->file.realpath,
                PAL_STRERROR(-ret));
        free(hdl);
        return -PAL_ERROR_DENIED;
    }

    hdl->file.stubs = (PAL_PTR) stubs;
    hdl->file.total = total;
    *handle = hdl;
    return 0;
}

/* 'read' operation for file streams. */
static int64_t file_read (PAL_HANDLE handle, uint64_t offset, uint64_t count,
                      void * buffer)
{
    sgx_stub_t * stubs = (sgx_stub_t *) handle->file.stubs;
    unsigned int total = handle->file.total;
    int ret;

    if (offset >= total)
        return 0;

    uint64_t end = (offset + count > total) ? total : offset + count;
    uint64_t map_start, map_end;

    if (stubs) {
        map_start = offset & ~(TRUSTED_STUB_SIZE - 1);
        map_end = (end + TRUSTED_STUB_SIZE - 1) & ~(TRUSTED_STUB_SIZE - 1);
        /* Don't go past the end of file with the stub map either */
        if (map_end > total)
            map_end = ALLOC_ALIGNUP(total);
    } else {
        map_start = ALLOC_ALIGNDOWN(offset);
        map_end = ALLOC_ALIGNUP(end);
    }

    void * umem;
    ret = ocall_map_untrusted(handle->file.fd, map_start,
                              map_end - map_start, PROT_READ, &umem);
    if (ret < 0)
        return -PAL_ERROR_DENIED;

    if (stubs) {
        ret = copy_and_verify_trusted_file(handle->file.realpath, umem,
                                           map_start, map_end,
                                           buffer, offset, end - offset,
                                           stubs, total);
        if (ret < 0) {
            ocall_unmap_untrusted(umem, map_end - map_start);
            return ret;
        }
    } else {
        memcpy(buffer, umem + (offset - map_start), end - offset);
    }

    ocall_unmap_untrusted(umem, map_end - map_start);
    return end - offset;
}

/* 'write' operation for file streams. */
static int64_t file_write(PAL_HANDLE handle, uint64_t offset, uint64_t count,
                          const void * buffer)
{
    uint64_t map_start = ALLOC_ALIGNDOWN(offset);
    uint64_t map_end = ALLOC_ALIGNUP(offset + count);
    void * umem;
    int ret;

    ret = ocall_map_untrusted(handle->file.fd, map_start,
                              map_end - map_start, PROT_WRITE, &umem);
    if (ret < 0) {
        return -PAL_ERROR_DENIED;
    }

    if (offset + count > handle->file.total) {
        ocall_ftruncate(handle->file.fd, offset + count);
        handle->file.total = offset + count;
    }

    memcpy(umem + offset - map_start, buffer, count);

    ocall_unmap_untrusted(umem, map_end - map_start);
    return count;
}

/* 'close' operation for file streams. In this case, it will only
   close the file withou deleting it. */
static int file_close (PAL_HANDLE handle)
{
    int fd = handle->file.fd;
    ocall_close(fd);

    if (handle->file.realpath &&
        handle->file.realpath != (void *) handle + HANDLE_SIZE(file))
        free((void *) handle->file.realpath);

    return 0;
}

/* 'delete' operation for file streams. It will actually delete
   the file if we can successfully close it. */
static int file_delete (PAL_HANDLE handle, int access)
{
    if (access)
        return -PAL_ERROR_INVAL;

    return ocall_delete(handle->file.realpath);
}

/* 'map' operation for file stream. */
static int file_map (PAL_HANDLE handle, void ** addr, int prot,
                     uint64_t offset, uint64_t size)
{
    sgx_stub_t * stubs = (sgx_stub_t *) handle->file.stubs;
    uint64_t total = handle->file.total;
    void * mem = *addr;
    void * umem;
    int ret;

    /*
     * If the file is listed in the manifest as an "allowed" file,
     * we allow mapping the file outside the enclave, if the library OS
     * does not request a specific address.
     */
    if (!mem && !stubs && !(prot & PAL_PROT_WRITECOPY)) {
        ret = ocall_map_untrusted(handle->file.fd, offset, size,
                                  HOST_PROT(prot), &mem);
        if (!ret)
            *addr = mem;
        return ret;
    }

    if (!(prot & PAL_PROT_WRITECOPY) && (prot & PAL_PROT_WRITE)) {
        SGX_DBG(DBG_E, "file_map does not currently support writeable pass-through mappings on SGX.  You may add the PAL_PROT_WRITECOPY (MAP_PRIVATE) flag to your file mapping to keep the writes inside the enclave but they won't be reflected outside of the enclave.\n");
        return -PAL_ERROR_DENIED;
    }

    mem = get_reserved_pages(mem, size);
    if (!mem)
        return -PAL_ERROR_NOMEM;

    uint64_t end = (offset + size > total) ? total : offset + size;
    uint64_t map_start, map_end;

    if (stubs) {
        map_start = offset & ~(TRUSTED_STUB_SIZE - 1);
        map_end = (end + TRUSTED_STUB_SIZE - 1) & ~(TRUSTED_STUB_SIZE - 1);
    } else {
        map_start = ALLOC_ALIGNDOWN(offset);
        map_end = ALLOC_ALIGNUP(end);
    }

    ret = ocall_map_untrusted(handle->file.fd, map_start,
                              map_end - map_start, PROT_READ, &umem);
    if (ret < 0) {
        SGX_DBG(DBG_E, "file_map - ocall returned %d\n", ret);
        return ret;
    }

    if (stubs) {
        ret = copy_and_verify_trusted_file(handle->file.realpath, umem,
                                           map_start, map_end,
                                           mem, offset, end - offset,
                                           stubs, total);

        if (ret < 0) {
            SGX_DBG(DBG_E, "file_map - verify trusted returned %d\n", ret);
            ocall_unmap_untrusted(umem, map_end - map_start);
            return ret;
        }
    } else {
        memcpy(mem, umem + (offset - map_start), end - offset);
    }

    ocall_unmap_untrusted(umem, map_end - map_start);
    *addr = mem;
    return 0;
}

/* 'setlength' operation for file stream. */
static int64_t file_setlength (PAL_HANDLE handle, uint64_t length)
{
    int ret = ocall_ftruncate(handle->file.fd, length);
    if (ret < 0)
        return ret;
    handle->file.total = length;
    return (int64_t) length;
}

/* 'flush' operation for file stream. */
static int file_flush (PAL_HANDLE handle)
{
    ocall_fsync(handle->file.fd);
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
    attr->handle_type = file_stat_type(stat);
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
    /* try to do the real open */
    int fd = ocall_open(uri, 0, 0);
    if (fd < 0)
        return fd;

    struct stat stat_buf;
    int ret = ocall_fstat(fd, &stat_buf);
    ocall_close(fd);

    /* if it failed, return the right error code */
    if (ret < 0)
        return ret;

    file_attrcopy(attr, &stat_buf);
    return 0;
}

/* 'attrquerybyhdl' operation for file streams */
static int file_attrquerybyhdl (PAL_HANDLE handle,
                                PAL_STREAM_ATTR * attr)
{
    int fd = handle->file.fd;
    struct stat stat_buf;

    int ret = ocall_fstat(fd, &stat_buf);
    if (ret < 0)
        return ret;

    file_attrcopy(attr, &stat_buf);
    return 0;
}

static int file_attrsetbyhdl (PAL_HANDLE handle,
                              PAL_STREAM_ATTR * attr)
{
    int fd = handle->file.fd;
    int ret = ocall_fchmod(fd, attr->share_flags | 0600);
    if (ret < 0)
        return ret;

    return 0;
}

static int file_rename (PAL_HANDLE handle, const char * type,
                        const char * uri)
{
    int ret = ocall_rename(handle->file.realpath, uri);
    if (ret < 0)
        return ret;

    /* TODO: old realpath memory is potentially leaked here, and need
     * to check for strdup memory allocation failure. */
    handle->file.realpath = strdup(uri);
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

    if (create & PAL_CREAT_TRY) {
        ret = ocall_mkdir(uri, share);
        if (ret == -PAL_ERROR_STREAMEXIST && (create & PAL_CREAT_ALWAYS))
            return ret;
    }

    ret = ocall_open(uri, O_DIRECTORY|options, 0);
    if (ret < 0)
        return ret;

    int len = strlen(uri);
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

#define DIRBUF_SIZE     1024

/* 'read' operation for directory stream. Directory stream will not
   need a 'write' operat4on. */
static int64_t dir_read (PAL_HANDLE handle, uint64_t offset, uint64_t count,
                         void * buf)
{
    void * dent_buf = (void *) handle->dir.buf ? : __alloca(DIRBUF_SIZE);
    void * ptr = (void *) handle->dir.ptr;
    void * end = (void *) handle->dir.end;
    int bytes = 0;

    if (ptr && ptr < end)
        goto output;

    do {
        if (handle->dir.endofstream)
            break;

        int size = ocall_getdents(handle->dir.fd, dent_buf, DIRBUF_SIZE);

        if (size < 0)
            return size;

        if (size == 0) {
            handle->dir.endofstream = PAL_TRUE;
            break;
        }

        ptr = dent_buf;
        end = dent_buf + size;

output:
        while (ptr < end) {
            struct linux_dirent64 * d = (struct linux_dirent64 *) ptr;

            if (d->d_name[0] == '.' &&
                (!d->d_name[1] || d->d_name[1] == '.'))
                goto next;

            bool isdir = (d->d_type == DT_DIR);
            int len = strlen(d->d_name);
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
            handle->dir.buf = (PAL_PTR) malloc(DIRBUF_SIZE);

        if ((void *) handle->dir.buf != ptr) {
            memmove((void *) handle->dir.buf, ptr, end - ptr);
            end = (void *) handle->dir.buf + (end - ptr);
            ptr = (void *) handle->dir.buf;
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

    ocall_close(fd);

    if (handle->dir.buf) {
        free((void *) handle->dir.buf);
        handle->dir.buf = handle->dir.ptr = handle->dir.end = (PAL_PTR) NULL;
    }

    if (handle->dir.realpath &&
        handle->dir.realpath != (void *) handle + HANDLE_SIZE(dir))
        free((void *) handle->dir.realpath);

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

    return ocall_delete(handle->dir.realpath);
}

static int dir_rename (PAL_HANDLE handle, const char * type,
                       const char * uri)
{
    int ret = ocall_rename(handle->dir.realpath, uri);
    if (ret < 0)
        return ret;

    /* TODO: old realpath memory is potentially leaked here, and need
     * to check for strdup memory allocation failure. */
    handle->dir.realpath = strdup(uri);
    return 0;
}

static int dir_getname (PAL_HANDLE handle, char * buffer, int count)
{
    if (!handle->dir.realpath)
        return 0;

    int len = strlen(handle->dir.realpath);
    char * tmp = strcpy_static(buffer, "dir:", count);

    if (!tmp || buffer + count < tmp + len + 1)
        return -PAL_ERROR_TOOLONG;

    memcpy(tmp, handle->dir.realpath, len + 1);
    return tmp + len - buffer;

    if (len + 6 >= count)
        return -PAL_ERROR_TOOLONG;
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
