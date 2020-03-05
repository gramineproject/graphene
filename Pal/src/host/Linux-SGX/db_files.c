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

#include <linux/types.h>

#include "api.h"
#include "assert.h"
#include "pal.h"
#include "pal_debug.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_linux_error.h"
typedef __kernel_pid_t pid_t;
#undef __GLIBC__
#include <asm/fcntl.h>
#include <asm/stat.h>
#include <linux/fs.h>
#include <linux/stat.h>

#include "enclave_pages.h"

/* 'open' operation for file streams */
static int file_open(PAL_HANDLE* handle, const char* type, const char* uri, int access, int share,
                     int create, int options) {
    if (strcmp_static(type, URI_TYPE_FILE))
        return -PAL_ERROR_INVAL;
    /* try to do the real open */
    int fd = ocall_open(uri, access | create | options, share);

    if (IS_ERR(fd))
        return unix_to_pal_error(ERRNO(fd));

    /* if try_create_path succeeded, prepare for the file handle */
    size_t len     = strlen(uri) + 1;
    PAL_HANDLE hdl = malloc(HANDLE_SIZE(file) + len);
    SET_HANDLE_TYPE(hdl, file);
    HANDLE_HDR(hdl)->flags |= RFD(0) | WFD(0);
    hdl->file.fd     = fd;
    char* path       = (void*)hdl + HANDLE_SIZE(file);
    int ret;
    if ((ret = get_norm_path(uri, path, &len)) < 0) {
        SGX_DBG(DBG_E, "Could not normalize path (%s): %s\n", uri, pal_strerror(ret));
        free(hdl);
        return ret;
    }
    hdl->file.realpath = (PAL_STR)path;

    sgx_stub_t* stubs;
    uint64_t total;
    void* umem;
    ret = load_trusted_file(hdl, &stubs, &total, create, &umem);
    if (ret < 0) {
        SGX_DBG(DBG_E,
                "Accessing file:%s is denied. (%s) "
                "This file is not trusted or allowed.\n",
                hdl->file.realpath, pal_strerror(ret));
        free(hdl);
        return ret;
    }
    if (stubs && total) {
        assert(umem);
    }

    hdl->file.stubs  = (PAL_PTR)stubs;
    hdl->file.total  = total;
    hdl->file.umem = umem;

    *handle = hdl;
    return 0;
}

/* 'read' operation for file streams. */
static int64_t file_read(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buffer) {
    int64_t ret;
    sgx_stub_t* stubs = (sgx_stub_t*)handle->file.stubs;

    if (!stubs) {
        ret = ocall_pread(handle->file.fd, buffer, count, offset);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));
        return ret;
    }

    /* case of trusted file: already mmaped in umem, copy from there and verify hash */
    uint64_t total = handle->file.total;
    if (offset >= total)
        return 0;

    uint64_t end       = (offset + count > total) ? total : offset + count;
    uint64_t map_start = ALIGN_DOWN(offset, TRUSTED_STUB_SIZE);
    uint64_t map_end   = ALIGN_UP(end, TRUSTED_STUB_SIZE);

    if (map_end > total)
        map_end = ALLOC_ALIGN_UP(total);

    ret = copy_and_verify_trusted_file(handle->file.realpath, handle->file.umem + map_start,
            map_start, map_end, buffer, offset, end - offset, stubs, total);
    if (ret < 0)
        return ret;

    return end - offset;
}

/* 'write' operation for file streams. */
static int64_t file_write(PAL_HANDLE handle, uint64_t offset, uint64_t count, const void* buffer) {
    int64_t ret;
    sgx_stub_t* stubs = (sgx_stub_t*)handle->file.stubs;

    if (!stubs) {
        ret = ocall_pwrite(handle->file.fd, buffer, count, offset);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));
        return ret;
    }

    /* case of trusted file: disallow writing completely */
    SGX_DBG(DBG_E, "Writing to a trusted file (%s) is disallowed!\n", handle->file.realpath);
    return -PAL_ERROR_DENIED;
}

/* 'close' operation for file streams. In this case, it will only
   close the file without deleting it. */
static int file_close(PAL_HANDLE handle) {
    int fd = handle->file.fd;

    if (handle->file.stubs && handle->file.total) {
        /* case of trusted file: the whole file was mmapped in untrusted memory */
        ocall_munmap_untrusted(handle->file.umem, handle->file.total);
    }

    ocall_close(fd);

    /* initial realpath is part of handle object and will be freed with it */
    if (handle->file.realpath && handle->file.realpath != (void*)handle + HANDLE_SIZE(file))
        free((void*)handle->file.realpath);

    return 0;
}

/* 'delete' operation for file streams. It will actually delete
   the file if we can successfully close it. */
static int file_delete(PAL_HANDLE handle, int access) {
    if (access)
        return -PAL_ERROR_INVAL;

    int ret = ocall_delete(handle->file.realpath);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

/* 'map' operation for file stream. */
static int file_map(PAL_HANDLE handle, void** addr, int prot, uint64_t offset, uint64_t size) {
    sgx_stub_t* stubs = (sgx_stub_t*)handle->file.stubs;
    uint64_t total    = handle->file.total;
    void* mem         = *addr;
    void* umem;
    int ret;

    /*
     * If the file is listed in the manifest as an "allowed" file,
     * we allow mapping the file outside the enclave, if the library OS
     * does not request a specific address.
     */
    if (!mem && !stubs && !(prot & PAL_PROT_WRITECOPY)) {
        ret = ocall_mmap_untrusted(handle->file.fd, offset, size, HOST_PROT(prot), &mem);
        if (!IS_ERR(ret))
            *addr = mem;
        return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
    }

    if (!(prot & PAL_PROT_WRITECOPY) && (prot & PAL_PROT_WRITE)) {
        SGX_DBG(DBG_E,
                "file_map does not currently support writable pass-through mappings on SGX.  You "
                "may add the PAL_PROT_WRITECOPY (MAP_PRIVATE) flag to your file mapping to keep "
                "the writes inside the enclave but they won't be reflected outside of the "
                "enclave.\n");
        return -PAL_ERROR_DENIED;
    }

    mem = get_enclave_pages(mem, size, /*is_pal_internal=*/false);
    if (!mem)
        return -PAL_ERROR_NOMEM;

    uint64_t end = (offset + size > total) ? total : offset + size;
    uint64_t map_start, map_end;

    if (stubs) {
        map_start = ALIGN_DOWN(offset, TRUSTED_STUB_SIZE);
        map_end   = ALIGN_UP(end, TRUSTED_STUB_SIZE);
    } else {
        map_start = ALLOC_ALIGN_DOWN(offset);
        map_end   = ALLOC_ALIGN_UP(end);
    }

    ret = ocall_mmap_untrusted(handle->file.fd, map_start, map_end - map_start, PROT_READ, &umem);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "file_map - ocall returned %d\n", ret);
        return unix_to_pal_error(ERRNO(ret));
    }

    if (stubs) {
        ret = copy_and_verify_trusted_file(handle->file.realpath, umem, map_start, map_end, mem,
                                           offset, end - offset, stubs, total);

        if (ret < 0) {
            SGX_DBG(DBG_E, "file_map - verify trusted returned %d\n", ret);
            ocall_munmap_untrusted(umem, map_end - map_start);
            return ret;
        }
    } else {
        memcpy(mem, umem + (offset - map_start), end - offset);
    }

    ocall_munmap_untrusted(umem, map_end - map_start);
    *addr = mem;
    return 0;
}

/* 'setlength' operation for file stream. */
static int64_t file_setlength(PAL_HANDLE handle, uint64_t length) {
    int ret = ocall_ftruncate(handle->file.fd, length);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    handle->file.total = length;
    return (int64_t)length;
}

/* 'flush' operation for file stream. */
static int file_flush(PAL_HANDLE handle) {
    ocall_fsync(handle->file.fd);
    return 0;
}

static inline int file_stat_type(struct stat* stat) {
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
static inline void file_attrcopy(PAL_STREAM_ATTR* attr, struct stat* stat) {
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
static int file_attrquery(const char* type, const char* uri, PAL_STREAM_ATTR* attr) {
    if (strcmp_static(type, URI_TYPE_FILE) && strcmp_static(type, URI_TYPE_DIR))
        return -PAL_ERROR_INVAL;
    /* try to do the real open */
    int fd = ocall_open(uri, 0, 0);
    if (IS_ERR(fd))
        return unix_to_pal_error(ERRNO(fd));

    struct stat stat_buf;
    int ret = ocall_fstat(fd, &stat_buf);
    ocall_close(fd);

    /* if it failed, return the right error code */
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    file_attrcopy(attr, &stat_buf);
    return 0;
}

/* 'attrquerybyhdl' operation for file streams */
static int file_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    int fd = handle->file.fd;
    struct stat stat_buf;

    int ret = ocall_fstat(fd, &stat_buf);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    file_attrcopy(attr, &stat_buf);
    return 0;
}

static int file_attrsetbyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    int fd  = handle->file.fd;
    int ret = ocall_fchmod(fd, attr->share_flags | 0600);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    return 0;
}

static int file_rename(PAL_HANDLE handle, const char* type, const char* uri) {
    if (strcmp_static(type, URI_TYPE_FILE))
        return -PAL_ERROR_INVAL;

    char* tmp = strdup(uri);
    if (!tmp)
        return -PAL_ERROR_NOMEM;

    int ret = ocall_rename(handle->file.realpath, uri);
    if (IS_ERR(ret)) {
        free(tmp);
        return unix_to_pal_error(ERRNO(ret));
    }

    /* initial realpath is part of handle object and will be freed with it */
    if (handle->file.realpath && handle->file.realpath != (void*)handle + HANDLE_SIZE(file)) {
        free((void*)handle->file.realpath);
    }

    handle->file.realpath = tmp;
    return 0;
}

static int file_getname(PAL_HANDLE handle, char* buffer, size_t count) {
    if (!handle->file.realpath)
        return 0;

    int len   = strlen(handle->file.realpath);
    char* tmp = strcpy_static(buffer, URI_PREFIX_FILE, count);

    if (!tmp || buffer + count < tmp + len + 1)
        return -PAL_ERROR_TOOLONG;

    memcpy(tmp, handle->file.realpath, len + 1);
    return tmp + len - buffer;
}

const char* file_getrealpath(PAL_HANDLE handle) {
    return handle->file.realpath;
}

struct handle_ops file_ops = {
    .getname        = &file_getname,
    .getrealpath    = &file_getrealpath,
    .open           = &file_open,
    .read           = &file_read,
    .write          = &file_write,
    .close          = &file_close,
    .delete         = &file_delete,
    .map            = &file_map,
    .setlength      = &file_setlength,
    .flush          = &file_flush,
    .attrquery      = &file_attrquery,
    .attrquerybyhdl = &file_attrquerybyhdl,
    .attrsetbyhdl   = &file_attrsetbyhdl,
    .rename         = &file_rename,
};

/* 'open' operation for directory stream. Directory stream does not have a
   specific type prefix, its URI looks the same file streams, plus it
   ended with slashes. dir_open will be called by file_open. */
static int dir_open(PAL_HANDLE* handle, const char* type, const char* uri, int access, int share,
                    int create, int options) {
    if (strcmp_static(type, URI_TYPE_DIR))
        return -PAL_ERROR_INVAL;
    if (!WITHIN_MASK(access, PAL_ACCESS_MASK))
        return -PAL_ERROR_INVAL;

    int ret;

    if (create & PAL_CREATE_TRY) {
        ret = ocall_mkdir(uri, share);
        if (IS_ERR(ret) && ERRNO(ret) == EEXIST && create & PAL_CREATE_ALWAYS)
            return -PAL_ERROR_STREAMEXIST;
    }

    ret = ocall_open(uri, O_DIRECTORY | options, 0);
    if (IS_ERR(ret))
        return unix_to_pal_error(ERRNO(ret));

    int len        = strlen(uri);
    PAL_HANDLE hdl = malloc(HANDLE_SIZE(dir) + len + 1);
    SET_HANDLE_TYPE(hdl, dir);
    HANDLE_HDR(hdl)->flags |= RFD(0);
    hdl->dir.fd = ret;
    char* path  = (void*)hdl + HANDLE_SIZE(dir);
    memcpy(path, uri, len + 1);
    hdl->dir.realpath    = (PAL_STR)path;
    hdl->dir.buf         = (PAL_PTR)NULL;
    hdl->dir.ptr         = (PAL_PTR)NULL;
    hdl->dir.end         = (PAL_PTR)NULL;
    hdl->dir.endofstream = PAL_FALSE;
    *handle              = hdl;
    return 0;
}

#define DIRBUF_SIZE 1024
static inline bool is_dot_or_dotdot(const char* name) {
    return (name[0] == '.' && !name[1]) || (name[0] == '.' && name[1] == '.' && !name[2]);
}

/* 'read' operation for directory stream. Directory stream will not
   need a 'write' operation. */
static int64_t dir_read(PAL_HANDLE handle, uint64_t offset, size_t count, void* _buf) {
    size_t bytes_written = 0;
    char* buf            = (char*)_buf;

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
            size_t len  = strlen(dirent->d_name);

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

        int size = ocall_getdents(handle->dir.fd, handle->dir.buf, DIRBUF_SIZE);
        if (IS_ERR(size)) {
            /*
             * If something was written just return that and pretend no error
             * was seen - it will be caught next time.
             */
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
    return (int64_t)bytes_written ?: -PAL_ERROR_ENDOFSTREAM;
}

/* 'close' operation of directory streams */
static int dir_close(PAL_HANDLE handle) {
    int fd = handle->dir.fd;

    ocall_close(fd);

    if (handle->dir.buf) {
        free((void*)handle->dir.buf);
        handle->dir.buf = handle->dir.ptr = handle->dir.end = (PAL_PTR)NULL;
    }

    /* initial realpath is part of handle object and will be freed with it */
    if (handle->dir.realpath && handle->dir.realpath != (void*)handle + HANDLE_SIZE(dir))
        free((void*)handle->dir.realpath);

    return 0;
}

/* 'delete' operation of directoy streams */
static int dir_delete(PAL_HANDLE handle, int access) {
    if (access)
        return -PAL_ERROR_INVAL;

    int ret = dir_close(handle);
    if (ret < 0)
        return ret;

    ret = ocall_delete(handle->dir.realpath);
    return IS_ERR(ret) ? unix_to_pal_error(ERRNO(ret)) : ret;
}

static int dir_rename(PAL_HANDLE handle, const char* type, const char* uri) {
    if (strcmp_static(type, URI_TYPE_DIR))
        return -PAL_ERROR_INVAL;

    char* tmp = strdup(uri);
    if (!tmp)
        return -PAL_ERROR_NOMEM;

    int ret = ocall_rename(handle->dir.realpath, uri);
    if (IS_ERR(ret)) {
        free(tmp);
        return unix_to_pal_error(ERRNO(ret));
    }

    /* initial realpath is part of handle object and will be freed with it */
    if (handle->dir.realpath && handle->dir.realpath != (void*)handle + HANDLE_SIZE(dir)) {
        free((void*)handle->dir.realpath);
    }

    handle->dir.realpath = tmp;
    return 0;
}

static int dir_getname(PAL_HANDLE handle, char* buffer, size_t count) {
    if (!handle->dir.realpath)
        return 0;

    size_t len = strlen(handle->dir.realpath);
    char* tmp  = strcpy_static(buffer, URI_PREFIX_DIR, count);

    if (!tmp || buffer + count < tmp + len + 1)
        return -PAL_ERROR_TOOLONG;

    memcpy(tmp, handle->dir.realpath, len + 1);
    return tmp + len - buffer;

    if (len + 6 >= count)
        return -PAL_ERROR_TOOLONG;
}

static const char* dir_getrealpath(PAL_HANDLE handle) {
    return handle->dir.realpath;
}

struct handle_ops dir_ops = {
    .getname        = &dir_getname,
    .getrealpath    = &dir_getrealpath,
    .open           = &dir_open,
    .read           = &dir_read,
    .close          = &dir_close,
    .delete         = &dir_delete,
    .attrquery      = &file_attrquery,
    .attrquerybyhdl = &file_attrquerybyhdl,
    .attrsetbyhdl   = &file_attrsetbyhdl,
    .rename         = &dir_rename,
};
