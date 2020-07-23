/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

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
#include "pal_flags_conv.h"
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

    /* prepare the file handle */
    size_t len     = strlen(uri) + 1;
    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(file) + len);
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    SET_HANDLE_TYPE(hdl, file);
    HANDLE_HDR(hdl)->flags |= RFD(0) | WFD(0);
    char* path = (void*)hdl + HANDLE_SIZE(file);
    int ret;
    if ((ret = get_norm_path(uri, path, &len)) < 0) {
        SGX_DBG(DBG_E, "Could not normalize path (%s): %s\n", uri, pal_strerror(ret));
        free(hdl);
        return ret;
    }
    hdl->file.realpath = (PAL_STR)path;

    struct protected_file* pf = get_protected_file(path);
    struct stat st;
    /* whether to re-initialize the PF */
    bool pf_create = (create & PAL_CREATE_ALWAYS) || (create & PAL_CREATE_TRY);

    /* try to do the real open */
    int fd = ocall_open(uri, PAL_ACCESS_TO_LINUX_OPEN(access)  |
                             PAL_CREATE_TO_LINUX_OPEN(create)  |
                             PAL_OPTION_TO_LINUX_OPEN(options),
                        share);
    if (IS_ERR(fd)) {
        ret = unix_to_pal_error(ERRNO(fd));
        goto out;
    }

    hdl->file.fd = fd;

    /* check if the file is seekable and get real file size */
    ret = ocall_fstat(fd, &st);
    if (IS_ERR(ret)) {
        SGX_DBG(DBG_E, "file_open(%s): fstat failed: %d\n", path, ret);
        ret = unix_to_pal_error(ERRNO(ret));
        goto out;
    }

    hdl->file.seekable = !S_ISFIFO(st.st_mode);

    if (pf) {
        pf_file_mode_t pf_mode = 0;
        if ((access & PAL_ACCESS_RDWR) == PAL_ACCESS_RDWR)
            pf_mode = PF_FILE_MODE_READ | PF_FILE_MODE_WRITE;
        else if ((access & PAL_ACCESS_WRONLY) == PAL_ACCESS_WRONLY)
            pf_mode = PF_FILE_MODE_WRITE;
        else
            pf_mode = PF_FILE_MODE_READ;

        /* disallow opening more than one writable handle to a PF */
        if (pf_mode & PF_FILE_MODE_WRITE) {
            if (pf->writable_fd >= 0) {
                SGX_DBG(DBG_D, "file_open(%s): disallowing concurrent writable handle\n", path);
                ret = -PAL_ERROR_DENIED;
                goto out;
            }
        }

        ret = -PAL_ERROR_DENIED;

        /* the protected files should be regular files (seekable) */
        if (!hdl->file.seekable) {
            SGX_DBG(DBG_E, "file_open(%s): disallowing non-seekable file handle\n", path);
            goto out;
        }

        pf = load_protected_file(path, (int*)&hdl->file.fd, st.st_size, pf_mode, pf_create, pf);
        if (pf) {
            pf->refcount++;
            if (pf_mode & PF_FILE_MODE_WRITE) {
                pf->writable_fd = fd;
            }
        } else {
            SGX_DBG(DBG_E, "load_protected_file(%s, %d) failed\n", path, hdl->file.fd);
            goto out;
        }
    } else {
        sgx_stub_t* stubs;
        uint64_t total;
        void* umem;
        ret = load_trusted_file(hdl, &stubs, &total, create, &umem);
        if (ret < 0) {
            SGX_DBG(DBG_E, "Accessing file:%s is denied (%s). This file is not trusted or allowed."
                    " Trusted files should be regular files (seekable).\n", hdl->file.realpath,
                    pal_strerror(ret));
            goto out;
        }

        if (stubs && total) {
            assert(umem);
        }

        hdl->file.stubs = (PAL_PTR)stubs;
        hdl->file.total = total;
        hdl->file.umem  = umem;
    }

    *handle = hdl;
    ret = 0;

out:
    if (ret != 0) {
        if (pf && pf->context && pf->refcount == 0)
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
        SGX_DBG(DBG_E, "pf_file_read(PF fd %d): PF not initialized\n", fd);
        return -PAL_ERROR_BADHANDLE;
    }

    size_t bytes_read = 0;
    pf_status_t pfs = pf_read(pf->context, offset, count, buffer, &bytes_read);

    if (PF_FAILURE(pfs)) {
        SGX_DBG(DBG_E, "pf_file_read(PF fd %d): pf_read failed: %d\n", fd, pfs);
        return -PAL_ERROR_DENIED;
    }

    return bytes_read;
}

/* 'read' operation for file streams. */
static int64_t file_read(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buffer) {
    struct protected_file* pf = find_protected_file_handle(handle);

    if (pf)
        return pf_file_read(pf, handle, offset, count, buffer);

    int64_t ret;
    sgx_stub_t* stubs = (sgx_stub_t*)handle->file.stubs;

    if (!stubs) {
        if (handle->file.seekable) {
            ret = ocall_pread(handle->file.fd, buffer, count, offset);
        } else {
            ret = ocall_read(handle->file.fd, buffer, count);
        }

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


static int64_t pf_file_write(struct protected_file* pf, PAL_HANDLE handle, uint64_t offset,
                             uint64_t count, const void* buffer) {
    int fd = handle->file.fd;

    if (!pf->context) {
        SGX_DBG(DBG_E, "pf_file_write(PF fd %d): PF not initialized\n", fd);
        return -PAL_ERROR_BADHANDLE;
    }

    pf_status_t pf_ret = pf_write(pf->context, offset, count, buffer);

    if (PF_FAILURE(pf_ret)) {
        SGX_DBG(DBG_E, "pf_file_write(PF fd %d): pf_write failed: %d\n", fd, pf_ret);
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
        if (handle->file.seekable) {
            ret = ocall_pwrite(handle->file.fd, buffer, count, offset);
        } else {
            ret = ocall_write(handle->file.fd, buffer, count);
        }

        if (IS_ERR(ret))
            return unix_to_pal_error(ERRNO(ret));

        return ret;
    }

    /* case of trusted file: disallow writing completely */
    SGX_DBG(DBG_E, "Writing to a trusted file (%s) is disallowed!\n", handle->file.realpath);
    return -PAL_ERROR_DENIED;
}

static int pf_file_close(struct protected_file* pf, PAL_HANDLE handle) {
    int fd = handle->file.fd;

    if (pf->refcount == 0) {
        SGX_DBG(DBG_E, "pf_file_close(PF fd %d): refcount == 0\n", fd);
        return -PAL_ERROR_INVAL;
    }

    pf->refcount--;

    if (pf->writable_fd == fd)
        pf->writable_fd = -1;

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

    assert(WITHIN_MASK(prot, PAL_PROT_MASK));
    if ((prot & PAL_PROT_READ) && (prot & PAL_PROT_WRITE)) {
        SGX_DBG(DBG_E, "pf_file_map(PF fd %d): trying to map with R+W access\n", fd);
        return -PAL_ERROR_NOTSUPPORT;
    }

    if (!pf->context) {
        SGX_DBG(DBG_E, "pf_file_map(PF fd %d): PF not initialized\n", fd);
        return -PAL_ERROR_BADHANDLE;
    }

    uint64_t pf_size;
    pf_status_t pfs = pf_get_size(pf->context, &pf_size);
    __UNUSED(pfs);
    assert(PF_SUCCESS(pfs));

    SGX_DBG(DBG_D, "pf_file_map(PF fd %d): pf %p, addr %p, prot %d, offset %lu, size %lu\n",
            fd, pf, *addr, prot, offset, size);

    /* LibOS always provides preallocated buffer for file maps */
    assert(*addr);

    if (prot & PAL_PROT_WRITE) {
        struct pf_map* map = calloc(1, sizeof(*map));

        map->pf     = pf;
        map->size   = size;
        map->offset = offset;
        map->buffer = *addr;

        pf_lock();
        LISTP_ADD_TAIL(map, &g_pf_map_list, list);
        pf_unlock();
    }

    if (prot & PAL_PROT_READ) {
        /* we don't check this on writes since file size may be extended then */
        if (offset >= pf_size) {
            SGX_DBG(DBG_E, "pf_file_map(PF fd %d): offset (%lu) >= file size (%lu)\n",
                    fd, offset, pf_size);
            return -PAL_ERROR_INVAL;
        }

        uint64_t copy_size = MIN(size, pf_size - offset);

        size_t bytes_read = 0;
        pf_status_t pf_ret = pf_read(pf->context, offset, copy_size, *addr, &bytes_read);
        if (bytes_read != copy_size) {
            /* mapped region must be read completely from file, otherwise it's an error */
            pf_ret = PF_STATUS_CORRUPTED;
        }
        if (PF_FAILURE(pf_ret)) {
            SGX_DBG(DBG_E, "pf_file_map(PF fd %d): pf_read failed: %d\n", fd, pf_ret);
            return -PAL_ERROR_DENIED;
        }
        memset(*addr + copy_size, 0, size - copy_size);
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
        ret = ocall_mmap_untrusted(handle->file.fd, offset, size, PAL_PROT_TO_LINUX(prot), &mem);
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

static int64_t pf_file_setlength(struct protected_file *pf, PAL_HANDLE handle, uint64_t length) {
    int fd = handle->file.fd;

    pf_status_t pfs = pf_set_size(pf->context, length);
    if (PF_FAILURE(pfs)) {
        SGX_DBG(DBG_E, "pf_file_setlength(PF fd %d, %lu): pf_set_size returned %d\n",
                fd, length, pfs);
        return -PAL_ERROR_DENIED;
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
    int fd = handle->file.fd;
    struct protected_file *pf = find_protected_file_handle(handle);
    if (pf) {
        int ret = flush_pf_maps(pf, /*buffer=*/NULL, /*remove=*/false);
        if (ret < 0) {
            SGX_DBG(DBG_E, "file_flush(PF fd %d): flush_pf_maps returned %d\n", fd, ret);
            return ret;
        }
        pf_status_t pfs = pf_flush(pf->context);
        if (PF_FAILURE(pfs)) {
            SGX_DBG(DBG_E, "file_flush(PF fd %d): pf_flush returned %d\n", fd, pfs);
            return -PAL_ERROR_DENIED;
        }
    } else {
        ocall_fsync(fd);
    }
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

static int pf_file_attrquery(struct protected_file* pf, int fd_from_attrquery, const char* path,
                             uint64_t real_size, PAL_STREAM_ATTR* attr) {
    pf = load_protected_file(path, &fd_from_attrquery, real_size, PAL_PROT_READ, /*create=*/false,
                             pf);
    if (!pf) {
        SGX_DBG(DBG_E, "pf_file_attrquery: load_protected_file(%s, %d) failed\n", path,
                fd_from_attrquery);
        /* The call above will fail for PFs that were tampered with or have a wrong path.
         * glibc kills the process if this fails during directory enumeration, but that
         * should be fine given the scenario.
         */
        return -PAL_ERROR_DENIED;
    }

    uint64_t size;
    pf_status_t pfs = pf_get_size(pf->context, &size);
    __UNUSED(pfs);
    assert(PF_SUCCESS(pfs));
    attr->pending_size = size;

    pf_handle_t pf_handle;
    pfs = pf_get_handle(pf->context, &pf_handle);
    assert(PF_SUCCESS(pfs));

    if (fd_from_attrquery == *(int*)pf_handle) { /* this is a PF opened just for us, close it */
        pfs = pf_close(pf->context);
        pf->context = NULL;
        assert(PF_SUCCESS(pfs));
    }

    return 0;
}

/* 'attrquery' operation for file streams */
static int file_attrquery(const char* type, const char* uri, PAL_STREAM_ATTR* attr) {
    if (strcmp_static(type, URI_TYPE_FILE) && strcmp_static(type, URI_TYPE_DIR))
        return -PAL_ERROR_INVAL;

    /* open the file with O_NONBLOCK to avoid blocking the current thread if it is actually a FIFO pipe;
     * O_NONBLOCK will be reset below if it is a regular file */
    int fd = ocall_open(uri, O_NONBLOCK, 0);
    if (IS_ERR(fd))
        return unix_to_pal_error(ERRNO(fd));

    struct stat stat_buf;
    int ret = ocall_fstat(fd, &stat_buf);

    /* if it failed, return the right error code */
    if (IS_ERR(ret)) {
        ret = unix_to_pal_error(ERRNO(ret));
        goto out;
    }

    file_attrcopy(attr, &stat_buf);

    char path[URI_MAX];
    size_t len = URI_MAX;
    ret = get_norm_path(uri, path, &len);
    if (ret < 0) {
        SGX_DBG(DBG_E, "Could not normalize path (%s): %s\n", uri, pal_strerror(ret));
        goto out;
    }

    /* For protected files return the data size, not real FS size */
    struct protected_file* pf = get_protected_file(path);
    if (pf && attr->handle_type != pal_type_dir) {
        /* protected files should be regular files */
        if (S_ISFIFO(stat_buf.st_mode)) {
            ret = -PAL_ERROR_DENIED;
            goto out;
        }

        /* reset O_NONBLOCK because pf_file_attrquery() may issue reads which don't expect non-blocking mode */
        ret = ocall_fsetnonblock(fd, 0);
        if (IS_ERR(ret)) {
            ret = unix_to_pal_error(ERRNO(ret));
            goto out;
        }

        ret = pf_file_attrquery(pf, fd, path, stat_buf.st_size, attr);
    }
    else
        ret = 0;

out:
    ocall_close(fd);
    return ret;
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
            /* protected files should be regular files (seekable) */
            if (!handle->file.seekable)
                return -PAL_ERROR_DENIED;

            uint64_t size;
            pf_status_t pfs = pf_get_size(pf->context, &size);
            __UNUSED(pfs);
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

static const char* file_getrealpath(PAL_HANDLE handle) {
    return handle->file.realpath;
}

struct handle_ops g_file_ops = {
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

    if (create & PAL_CREATE_TRY || create & PAL_CREATE_ALWAYS) {
        ret = ocall_mkdir(uri, share);

        if (IS_ERR(ret)) {
            if (ERRNO(ret) == EEXIST && create & PAL_CREATE_ALWAYS)
                return -PAL_ERROR_STREAMEXIST;
            if (ERRNO(ret) != EEXIST)
                return unix_to_pal_error(ERRNO(ret));
            assert(ERRNO(ret) == EEXIST && create & PAL_CREATE_TRY);
        }
    }

    ret = ocall_open(uri, O_DIRECTORY | PAL_OPTION_TO_LINUX_OPEN(options), 0);
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

struct handle_ops g_dir_ops = {
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
