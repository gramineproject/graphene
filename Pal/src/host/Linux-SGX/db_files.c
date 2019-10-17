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

#include "api.h"
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
#include <linux/types.h>

#include "enclave_pages.h"

/* 'open' operation for file streams */
static int file_open(PAL_HANDLE* handle, const char* type, const char* uri, int access, int share,
                     int create, int options) {
    if (strcmp_static(type, URI_TYPE_FILE))
        return -PAL_ERROR_INVAL;

    SGX_DBG(DBG_D, "file_open: uri %s, access 0x%x, share 0x%x, create 0x%x, options 0x%x\n",
        uri, access, share, create, options);

    /* prepare the file handle */
    size_t len     = strlen(uri) + 1;
    PAL_HANDLE hdl = malloc(HANDLE_SIZE(file) + len);
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    SET_HANDLE_TYPE(hdl, file);
    HANDLE_HDR(hdl)->flags |= RFD(0) | WFD(0);
    char* path       = (void*)hdl + HANDLE_SIZE(file);
    int ret;
    if ((ret = get_norm_path(uri, path, &len)) < 0) {
        SGX_DBG(DBG_E, "Could not normalize path (%s): %s\n", uri, pal_strerror(ret));
        free(hdl);
        return ret;
    }
    hdl->file.realpath = (PAL_STR)path;

    int fd;
    struct protected_file* pf = get_protected_file(path);
    bool pf_create = create & O_CREAT; /* whether to re-initialize the PF */

    if (pf && (create == PAL_CREATE_TRY)) { /* open the file whether it exists or not */
        /* We need to know whether the file will be created or not
           to know if we should re-initialize (truncate) the PF.
           PAL_CREATE_TRY|PAL_CREATE_ALWAYS is equivalent to O_CREAT|O_EXCL */
        fd = ocall_open(uri, access | (create | PAL_CREATE_ALWAYS) | options, share);
        if (fd == -EEXIST) {
            /* do not recreate the file */
            pf_create = false;
            fd = ocall_open(uri, access | create | options, share);
        } else if (!IS_ERR(fd)) {
            pf_create = true;
        }
    } else {
        /* try to do the real open */
        fd = ocall_open(uri, access | create | options, share);
    }

    if (IS_ERR(fd)) {
        ret = unix_to_pal_error(ERRNO(fd));
        goto out;
    }

    hdl->file.fd = fd;

    if (pf) {
        pf_file_mode_t pf_mode = 0;
        if ((access & O_RDWR) == O_RDWR) /* 2 */
            pf_mode = PF_FILE_MODE_READ | PF_FILE_MODE_WRITE;
        else if ((access & O_WRONLY) == O_WRONLY) /* 1 */
            pf_mode = PF_FILE_MODE_WRITE;
        else /* O_RDONLY == 0 */
            pf_mode = PF_FILE_MODE_READ;

        /* get real file size */
        struct stat st;
        ret = ocall_fstat(fd, &st);
        if (IS_ERR(ret)) {
            SGX_DBG(DBG_E, "file_open(%s): fstat failed: %d\n", path, ret);
            ret = unix_to_pal_error(ERRNO(ret));
            goto out;
        }

        ret = -PAL_ERROR_DENIED;
        pf = load_protected_file(path, (int*)&hdl->file.fd, st.st_size, pf_mode, pf_create, pf);
        if (pf) {
            bool allowed = false;
            pf_status_t pfs = pf_check_path(pf->context, path, &allowed);
            if (!allowed || PF_FAILURE(pfs)) {
                SGX_DBG(DBG_E, "file_open(%s): path doesn't match PF's allowed paths\n", path);
                goto out;
            }

            if (pf->refcount == INT64_MAX) {
                SGX_DBG(DBG_E, "file_open(%s): maximum refcount exceeded\n", path);
                goto out;
            }

            pf->refcount++;
        } else {
            SGX_DBG(DBG_E, "load_protected_file(%s, %d) failed\n", path, hdl->file.fd);
            goto out;
        }

        hdl->file.offset = 0;
    } else {
        sgx_stub_t* stubs;
        uint64_t total;
        ret = load_trusted_file(hdl, &stubs, &total, create);
        if (ret < 0) {
            SGX_DBG(DBG_E, "Accessing file:%s is denied. (%s) "
                    "This file is not trusted or allowed.\n",
                    hdl->file.realpath, pal_strerror(ret));
            free(hdl);
            return ret;
        }

        hdl->file.stubs  = (PAL_PTR)stubs;
        hdl->file.total  = total;
        hdl->file.offset = 0;

        if (hdl->file.stubs && hdl->file.total) {
            /* case of trusted file: mmap the whole file in untrusted memory for future reads/writes */
            ret = ocall_mmap_untrusted(hdl->file.fd, 0, hdl->file.total, PROT_READ, &hdl->file.umem);
            if (IS_ERR(ret)) {
                /* note that we don't free stubs because they are re-used in same trusted file */
                free(hdl);
                return unix_to_pal_error(ERRNO(ret));
            }
        }
    }

    *handle = hdl;
    ret = 0;

out:
    if (ret != 0) {
        if (pf && pf->context)
            unload_protected_file(pf);

        free(hdl);
        if (fd >= 0)
            ocall_close(fd);
    }
    return ret;
}


static int64_t pf_file_read(struct protected_file* pf, PAL_HANDLE handle, uint64_t offset,
                            uint64_t count, void* buffer) {
    int fd = handle->file.fd;

    if (!pf->context) {
        SGX_DBG(DBG_E, "pf_file_read: PF fd %d not initialized\n", fd);
        return -PAL_ERROR_BADHANDLE;
    }

    pf_status_t pfs = pf_read(pf->context, offset, count, buffer);

    if (PF_FAILURE(pfs)) {
        SGX_DBG(DBG_E, "pf_file_read(PF fd %d): pf_read failed: %d\n", fd, pfs);
        return -PAL_ERROR_DENIED;
    }

    return count;
}

/* 'read' operation for file streams. */
static int64_t file_read(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buffer) {
    struct protected_file* pf = find_protected_file_handle(handle);

    if (pf)
        return pf_file_read(pf, handle, offset, count, buffer);

    int64_t ret;
    sgx_stub_t* stubs = (sgx_stub_t*)handle->file.stubs;

    if (!stubs) {
        /* case of allowed file: emulate via lseek + read */
        if (handle->file.offset != offset) {
            ret = ocall_lseek(handle->file.fd, offset, SEEK_SET);
            if (IS_ERR(ret))
                return -PAL_ERROR_DENIED;
            handle->file.offset = offset;
        }

        ret = ocall_read(handle->file.fd, buffer, count);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        handle->file.offset = offset + ret;
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


static int64_t pf_file_write(struct protected_file* pf, PAL_HANDLE handle, uint64_t offset,
                             uint64_t count, const void* buffer) {
    int fd = handle->file.fd;

    if (!pf->context) {
        SGX_DBG(DBG_E, "pf_file_write: PF fd %d not initialized\n", fd);
        return -PAL_ERROR_BADHANDLE;
    }

    pf_status_t pf_ret = pf_write(pf->context, offset, count, buffer);

    if (PF_FAILURE(pf_ret)) {
        SGX_DBG(DBG_E, "file_write(PF fd %d): pf_write failed: %d\n", fd, pf_ret);
        return -PAL_ERROR_DENIED;
    }

    return count;
}

/* 'write' operation for file streams. */
static int64_t file_write(PAL_HANDLE handle, uint64_t offset, uint64_t count, const void* buffer) {
    struct protected_file *pf = find_protected_file_handle(handle);

    if (pf)
        return pf_file_write(pf, handle, offset, count, buffer);

    int64_t ret;
    sgx_stub_t* stubs = (sgx_stub_t*)handle->file.stubs;

    if (!stubs) {
        /* case of allowed file: emulate via lseek + write */
        if (handle->file.offset != offset) {
            ret = ocall_lseek(handle->file.fd, offset, SEEK_SET);
            if (IS_ERR(ret))
                return -PAL_ERROR_DENIED;
            handle->file.offset = offset;
        }

        ret = ocall_write(handle->file.fd, buffer, count);
        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        handle->file.offset = offset + ret;
        return ret;
    }

    /* case of trusted file: disallow writing completely */
    SGX_DBG(DBG_E, "Writing to a trusted file (%s) is disallowed!\n", handle->file.realpath);
    return -PAL_ERROR_DENIED;
}

static int pf_file_close(struct protected_file* pf, PAL_HANDLE handle) {
    int fd = handle->file.fd;

    if (pf->refcount == 0) {
        SGX_DBG(DBG_E, "pf_file_close(PF fd %d) refcount == 0\n", fd);
        return -PAL_ERROR_INVAL;
    }

    pf->refcount--;
    if (pf->refcount == 0)
        return unload_protected_file(pf);

    return 0;
}

/* 'close' operation for file streams. In this case, it will only
   close the file without deleting it. */
static int file_close(PAL_HANDLE handle) {
    int fd = handle->file.fd;
    struct protected_file* pf = find_protected_file_handle(handle);

    if (pf) {
        int ret = pf_file_close(pf, handle);
        if (ret < 0)
            return ret;
    }

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

static int pf_file_map(struct protected_file* pf, PAL_HANDLE handle, void** addr, int prot,
                       uint64_t offset, uint64_t size) {
    int fd = handle->file.fd;

    if (size == 0)
        return -PAL_ERROR_INVAL;

    if ((prot & PAL_PROT_READ) && (prot & PAL_PROT_WRITE)) {
        SGX_DBG(DBG_E, "file_map(PF fd %d): trying to map with R+W access\n", fd);
        return -PAL_ERROR_NOTSUPPORT;
    }

    if (!pf->context) {
        SGX_DBG(DBG_E, "file_map(PF fd %d): PF not initialized\n", fd);
        return -PAL_ERROR_BADHANDLE;
    }

    uint64_t pf_size;
    __attribute__((unused)) pf_status_t pfs = pf_get_size(pf->context, &pf_size);
    assert(PF_SUCCESS(pfs));

    SGX_DBG(DBG_D, "pf_file_map: pf %p, fd %d, addr %p, prot %d, offset %lu, size %lu\n",
        pf, fd, *addr, prot, offset, size);

    /* LibOS always provides preallocated buffer for file maps */
    assert(*addr);


    if (prot & PAL_PROT_WRITE) {
        struct pf_map* map = malloc(sizeof(*map));
        memset(map, 0, sizeof(*map));

        map->pf     = pf;
        map->size   = size;
        map->offset = offset;
        map->buffer = *addr;

        LISTP_ADD_TAIL(map, &g_pf_map_list, list);
    }

    if (prot & PAL_PROT_READ) {
        /* we don't check this on writes since file size may be extended then */
        if (offset >= pf_size) {
            SGX_DBG(DBG_E, "file_map(PF fd %d): offset (%lu) >= file size (%lu)\n",
                fd, offset, pf_size);
            return -PAL_ERROR_INVAL;
        }

        memset(*addr, 0, size);
        uint64_t copy_size = size;
        if (size > pf_size - offset)
            copy_size = pf_size - offset;

        pf_status_t pf_ret = pf_read(pf->context, offset, copy_size, *addr);
        if (PF_FAILURE(pf_ret)) {
            SGX_DBG(DBG_E, "file_map(PF fd %d): pf_read failed: %d\n", fd, pf_ret);
            return -PAL_ERROR_DENIED;
        }
    }

    /* Writes will be flushed to the PF on close. */
    return 0;
}

/* 'map' operation for file stream. */
static int file_map(PAL_HANDLE handle, void** addr, int prot, uint64_t offset, uint64_t size) {
    struct protected_file* pf = find_protected_file_handle(handle);

    if (pf)
        return pf_file_map(pf, handle, addr, prot, offset, size);

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

    mem = get_reserved_pages(mem, size);
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

static int64_t pf_file_setlength(struct protected_file *pf, PAL_HANDLE handle, uint64_t length) {
    int fd = handle->file.fd;

    pf_status_t pfs = pf_set_size(pf->context, length);
    if (PF_FAILURE(pfs)) {
        SGX_DBG(DBG_E, "file_setlength(PF fd %d, %lu): pf_set_size returned %d\n",
                fd, length, pfs);
        uint64_t size;
        pfs = pf_get_size(pf->context, &size);
        assert(PF_SUCCESS(pfs));
        return size;
    }
    return length;
}

/* 'setlength' operation for file stream. */
static int64_t file_setlength(PAL_HANDLE handle, uint64_t length) {
    struct protected_file *pf = find_protected_file_handle(handle);
    if (pf)
        return pf_file_setlength(pf, handle, length);

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

static int pf_file_attrquery(struct protected_file* pf, int fd, const char* path, size_t real_size,
                             PAL_STREAM_ATTR* attr) {
    pf = load_protected_file(path, (pf_handle_t)&fd, real_size, PAL_PROT_READ, false, pf);
    if (!pf) {
        SGX_DBG(DBG_E, "pf_file_attrquery: load_protected_file(%s, %d) failed\n", path, fd);
        /* The call above will fail for PFs that were tampered with or have a wrong path.
         * glibc kills the process if this fails during directory enumeration, but that
         * should be fine given the scenario.
         */
        ocall_close(fd);
        return -PAL_ERROR_DENIED;
    }

    uint64_t size;
    __attribute__((unused)) pf_status_t pfs = pf_get_size(pf->context, &size);
    assert(PF_SUCCESS(pfs));
    attr->pending_size = size;

    if (fd == *(int*)pf->context->handle) { /* this is a PF opened just for us, close it */
        pfs = pf_close(pf->context);
        pf->context = NULL;
        assert(PF_SUCCESS(pfs));
    }

    ocall_close(fd);
    return 0;
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

    /* if it failed, return the right error code */
    if (IS_ERR(ret)) {
        ocall_close(fd);
        return unix_to_pal_error(ERRNO(ret));
    }

    file_attrcopy(attr, &stat_buf);

    char path[URI_MAX];
    size_t len = URI_MAX;
    ret = get_norm_path(uri, path, &len);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Could not normalize path (%s): %s\n", uri, pal_strerror(ret));
        ocall_close(fd);
        return ret;
    }

    /* For protected files return the data size, not real FS size */
    struct protected_file* pf = get_protected_file(path);
    if (pf && attr->handle_type != pal_type_dir)
        return pf_file_attrquery(pf, fd, path, stat_buf.st_size, attr);

    ocall_close(fd);
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

    if (attr->handle_type != pal_type_dir) {
        /* For protected files return the data size, not real FS size */
        struct protected_file* pf = find_protected_file_handle(handle);
        if (pf) {
            uint64_t size;
            __attribute__((unused)) pf_status_t pfs = pf_get_size(pf->context, &size);
            assert(PF_SUCCESS(pfs));
            attr->pending_size = size;
        }
    }
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
