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

/*
 * A common helper function for map/read that both copies the file contents
 * into an in-enclave buffer, and hashes/checks the contents.  If needed,
 * regions at both ends are copied into a scratch buffer to avoid a TOCTTOU
 * race.
 *
 * * Note that it must be done this way to avoid the following TOCTTOU race
 * * condition with the untrusted runtime system (URTS):
 *       *  URTS: put good contents in buffer
 *       *  Enclave: buffer check passes
 *       *  URTS: put bad contents in buffer
 *       *  Enclave: copies in bad buffer contents
 *
 * * For optimization, we verify the memory in place, as the application code
 *   should not use the memory before return.  There can be subtle interactions
 *   at the edges of a region with ELF loading.  Namely, the ELF loader will
 *   want to map several file chunks that are not aligned to TRUSTED_STUB_SIZE
 *   next to each other, sometimes overlapping.  There is probably room to
 *   improve load time with more smarts around ELF loading, but for now, just
 *   make things work.
 *
 * handle is the PAL handle for the file
 * umem is the untrusted file mapping (should already be set up by the caller)
 * umap_start and umap_end are the offset _within the file_ of umap.  Both
 *    should be aligned to the file checking chunk size (TRUSTED_STUB_SIZE)
 * offset is the offset within the file requested by the caller (read/mmap)
 *   umap_start should be the same value, but aligned down.
 * buffer is the destination of the copy; should be in trusted enclave memory
 * end is the last byte within the buffer, as an offset of the file
 */

static int
__file_copy_and_check(PAL_HANDLE handle, void *umem, uint64_t umap_start,
                      uint64_t umap_end, uint64_t offset, void *buffer,
                      uint64_t end)
{

    uint64_t verify_size = umap_end - umap_start;
    uint64_t verify_offset = umap_start;
    uint64_t umap_offset = offset - umap_start;
    void *buf_ptr = buffer;
    int check_start = 0, check_end = 0; // Do we need to do a special case
                                        // for verifying the first or last chunk?
    void * scratch_buffer = NULL; // Enclave memory
    int ret = 0;
    sgx_stub_t * stubs = (sgx_stub_t *) handle->file.stubs;
    uint64_t total = handle->file.total;
    int end_of_file = 0;

    /* This function should only be called if stubs exist */
    assert(stubs);

    if (umap_end == ALLOC_ALIGNUP(total)) end_of_file = 1;

    /* Here, we need to copy the data into a trusted buffer to hash it
     * first, lest we have a similar TOCTTOU issue to file_map.  As an
     * optimization, try to use the buffer for STUB-sized chunks.
     */

    // Figure out in one spot if we will need the scratch buffer
    if (umap_start != offset) check_start = 1;
    // Don't bother checking the end separately if there is only one chunk.
    if (umap_end != end &&
        umap_end > umap_start + TRUSTED_STUB_SIZE)
        check_end = 1;
    if (check_start || check_end) {
        scratch_buffer = get_reserved_pages(NULL, TRUSTED_STUB_SIZE);
        if (!scratch_buffer) {
            ret = -PAL_ERROR_NOMEM;
            goto out; 
        }
    }

    // Case 1: See if we need to verify the first chunk separately
    if (check_start) {
        // The first bytes should come from umem (offset-map_start).  This
        // should be less than TRUSTED_STUB_SIZE.  We need to make sure that
        // the bytes that are actually returned are _identical_ to the ones verified.
        uint64_t first_bytes = offset - umap_start;
        uint64_t remainder = TRUSTED_STUB_SIZE - first_bytes;
        // Handle the case where the entire trusted map is smaller than the
        // whole chunk - i.e., we need to copy some data from the end too
        uint64_t end_bytes = 0, mid_bytes = 0;
        if (end < total && end < umap_start + TRUSTED_STUB_SIZE) {
            remainder = end - umap_start - first_bytes;
            mid_bytes = remainder + first_bytes;
            end_bytes = TRUSTED_STUB_SIZE - mid_bytes;
            if (end_of_file) end_bytes = umap_end - mid_bytes;
        }
        SGX_DBG(DBG_M, "__file_copy_and_check: case 1: offset is %llx, end is %llx, umap_start is %llx, umap_end is %llx, first_bytes is %llx, total is %llx (%llx), end_bytes are %llx, mid_bytes %llx, remainder is %llx\n", offset, end, umap_start, umap_end, first_bytes, total, total-umap_start, end_bytes, mid_bytes, remainder);
        assert(first_bytes < TRUSTED_STUB_SIZE);
        memcpy(scratch_buffer, umem, first_bytes);
        memcpy(scratch_buffer + first_bytes, buffer, remainder);
        if (end_bytes)
            memcpy(scratch_buffer + mid_bytes, umem + mid_bytes, end_bytes);
        ret = verify_trusted_file(handle->file.realpath, scratch_buffer,
                                  umap_start, TRUSTED_STUB_SIZE,
                                  stubs, total);
        if (ret) {
            SGX_DBG(DBG_E, "__file_copy_and_check - verify trusted (case 1) returned %d\n", ret);
            goto out_unmap_scratch;
        }
        verify_size -= TRUSTED_STUB_SIZE;
        verify_offset += TRUSTED_STUB_SIZE;
        // Account for the offset into mem
        buf_ptr += (TRUSTED_STUB_SIZE - umap_offset);
    }

    // Case 2: Check last chunk, if needed
    if (check_end) {
        // Copy the contents into the scratch buffer
        uint64_t delta = umap_end & (TRUSTED_STUB_SIZE - 1) ? : TRUSTED_STUB_SIZE;
        uint64_t end_offset = umap_end - delta;
        uint64_t end_copy_size = TRUSTED_STUB_SIZE; // Still copy a whole chunk
        // Add the offset to the umem ptr, adjusting for the overall
        // offset of the mapping
        void *end_ptr = umem + (end_offset - umap_start);

        // end_offset should be aligned now, just leaaving the last
        // sub-chunk
        assert(end_offset == 0 || (end_offset & ~(TRUSTED_STUB_SIZE-1)));

        if (end_of_file) {
            // If EOF, just copy the end
            end_copy_size = delta;
        }

        SGX_DBG(DBG_M, "__file_copy_and_check - scratch memcpy (end) - %p %p (..%p), end_copy_size is %llu, end_offset %x, eof? %d\n", scratch_buffer, end_ptr, end_ptr + end_copy_size, end_copy_size, end_offset, end_of_file);
        SGX_DBG(DBG_M, "__file_copy_and_check - scratch memcpy (end) - end is %llx, delta is %llx, umem is %p umap_start is %llx\n", end, delta, umem, umap_start);
        // Get the first n bytes from the main buffer, and the rest from umem,
        // so that we are cretain we hash and check precisely the same
        // contents
        uint64_t buffer_end = end - offset;
        uint64_t buffer_offset = (end & ~(TRUSTED_STUB_SIZE - 1)) - offset;
        uint64_t first_bytes = buffer_end - buffer_offset;
        uint64_t remainder = end_copy_size - first_bytes;
        SGX_DBG(DBG_M, "__file_copy_and_check - first bytes are %llu, remainder %llu, buffer end is %llx, buffer offset is %llx, offset is %llx\n", first_bytes, remainder, buffer_end, buffer_offset, offset);
        SGX_DBG(DBG_M, "__file_copy_and_check - first bytes are (buf 1)  %llx, (buf 2) %llx\n", *((uint64_t *) end_ptr), *((uint64_t *) (((char *) buffer) + buffer_offset)));
        assert(buffer_end != 0 || buffer_offset != 0);
        assert(first_bytes < TRUSTED_STUB_SIZE);
        //memcpy(scratch_buffer, end_ptr, end_copy_size);
        memcpy(scratch_buffer, buffer+buffer_offset, first_bytes);
        memcpy(scratch_buffer + first_bytes, end_ptr + first_bytes, remainder);

        ret = verify_trusted_file(handle->file.realpath, scratch_buffer,
                                  end_offset, end_copy_size,
                                  stubs, total);
        if (ret) {
            SGX_DBG(DBG_E, "__file_copy_and_check - verify trusted (case 2) returned %d\n", ret);
            goto out_unmap_scratch;
        }
        verify_size -= end_copy_size;
    }

    if (verify_size) {
        ret = verify_trusted_file(handle->file.realpath, umem,
                                  umap_start, umap_end - umap_start,
                                  stubs, total);

        if (ret) {
            SGX_DBG(DBG_E, "__file_copy_and_check - verify trusted returned %d (case 3)\n", ret);
            goto out_unmap_scratch;
        }
    }

out_unmap_scratch:
    if (scratch_buffer) {
        SGX_DBG(DBG_M, "*** __file_copy_and_check: freeing scratch buffer %p ***\n", scratch_buffer);
        free_pages(scratch_buffer, TRUSTED_STUB_SIZE);
    }
out:
    return ret;
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

    /* Go ahead and do the copy */
    memcpy(buffer, umem + offset - map_start, end - offset);

    if (stubs) {
        /* XXX: It would be good to assert that the buffer is actually in
         * enclave memory, or else we either have an error or a pointless
         * check */
        ret = __file_copy_and_check(handle, umem, map_start,
                                    map_end, offset, buffer, end);
        if (ret) goto out;
    } 

    // Success
    ret = end - offset;
out:
    ocall_unmap_untrusted(umem, map_end - map_start);
    return ret;
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

/* 'map' operation for file stream. 
 * 
 * For SGX, we need to do a little more work.  Part of the complexity comes in
 * for doing both memory management and verification.
 * 
 * At a high level, the code works like this:
 * 
 * First, we do a mapping of the file contents in untrusted memory. In some
 * cases, where we allow the file but don't care about its integrity or
 * confidentiality, this is good enough and we return.  
 * 
 * Second, allocate the desired range (if specified by *addr)
 * in trusted memory.  
 * 
 * Third, we have to copy the file contents into trusted memory in chunks of
 * size TRUSTED_STUB_SIZE, as this is the granularity of the measurement.  We then
 * hash and check the contents. We use a helper function __file_copy_and_check
 * to do the copying and deal with unaligned starts and ends.
 * 
 * Finally, if verification passes, unmap the untrusted copy of the file.
 * 
 */
static int file_map (PAL_HANDLE handle, void ** addr, int prot,
                     uint64_t offset, uint64_t size)
{
    sgx_stub_t * stubs = (sgx_stub_t *) handle->file.stubs;
    uint64_t total = handle->file.total;
    void * mem = *addr; // Enclave map addr
    void * umem; // urts map addr
    int ret = 0;
    int uprot; // Permission requested on untrusted mapping
    uint64_t umap_start, umap_end, umap_size; // Boundaries for untrusted
                                              // mapping
    uint64_t umap_offset = 0; //offset into umap padding
    int umap_suffices = 0;

    if (!(prot & PAL_PROT_WRITECOPY) && (prot & PAL_PROT_WRITE)) {
        SGX_DBG(DBG_E, "file_map does not currently support writeable pass-through mappings on SGX.  You may add the PAL_PROT_WRITECOPY (MAP_PRIVATE) flag to your file mapping to keep the writes inside the enclave but they won't be reflected outside of the enclave.\n");
        return -PAL_ERROR_DENIED;
    }

    uint64_t end = (offset + size > total) ? total : offset + size;
    uint64_t map_start, map_end;

    SGX_DBG(DBG_M, "*** file_map: requested offset %llx, size %llu, end is %llx, total %llx ***\n", offset, size, end, total);

    /* Set up the untrusted mapping */
    if (!stubs && !(prot & PAL_PROT_WRITECOPY)) {
        /* This is the case where an untrusted map suffices.  
         * 
         * XXX: Review this policy and/or document flag choice more.
         */
        umap_suffices = 1;
        umem = *addr;
        uprot = HOST_PROT(prot);
        umap_start = offset;
        umap_size = size;
    } else {
        umem = NULL;
        uprot = PROT_READ;
        /* If we have a merkle tree cached, use it.  This means mapping in
         * merkle-node-sized chunks.
         * 
         * DEP XXX: Document cases where a trusted file wouldn't have stubs, and
         * why it is ok not to verify them.  For a trusted file I can't see
         * how this is secure if stub caching is disabled; I think you would
         * have to rebuild on every map operation, which this code is not
         * doing.
         */
        if (stubs) {
            /* DEP 11/24/17: If stubs are set, we verify in larger chunks.
             * Here the umap_start and umap_offset can be different, as we
             * round to a larger size.
             */
            umap_start = offset & ~(TRUSTED_STUB_SIZE - 1);
            umap_offset = offset - umap_start;
            umap_end = (end + TRUSTED_STUB_SIZE - 1) & ~(TRUSTED_STUB_SIZE - 1);
            /* Don't go past the end of file with the stub map either */
            if (umap_end > total) {
                umap_end = ALLOC_ALIGNUP(total);
            }
            SGX_DBG(DBG_M, "file_map: umap_end %p, end %p, umap_start %p, TRUSTED_STUB_SIZE %d\n", umap_end, end, umap_start,
                    TRUSTED_STUB_SIZE);
        } else {
            umap_start = ALLOC_ALIGNDOWN(offset);
            umap_end = ALLOC_ALIGNUP(end);
        }
        umap_size = umap_end - umap_start;
    }

    ret = ocall_map_untrusted(handle->file.fd, umap_start, umap_size,
                              uprot, &umem);
    if (ret)
        return ret;

    SGX_DBG(DBG_M, "*** file_map: umem is at %p, starts %p, ends %p (%p), umap_size 0x%llx ***\n", umem, umap_start,
            umap_end, umem + umap_size, umap_size);

    /* Stop early if an untrusted map suffices and the mapping was successful*/
    if (umap_suffices) {
        SGX_DBG(DBG_M, "*** file_map: umem suffices ***\n");
        *addr = umem;
        return 0;
    }

    /* Try to allocate the desired address range from enclave memory 
     * 
     * The memory will always allocated with flag MAP_PRIVATE
     * and MAP_FILE 
     */
    SGX_DBG(DBG_M, "file_map: *addr is %p\n", *addr);    
  

    SGX_DBG(DBG_M, "*** file_map: requesting %p, %d ***\n", mem, size);
    mem = get_reserved_pages(mem, size);
    if (!mem) {
        ret = -PAL_ERROR_NOMEM;
        goto out; 
    }
    
    /* Step three: copy the contents into the enclave buffer.  Initially,
     * let's just copy into the buffer we want to return; we will popuulate
     * the scratch buffer later, if needed.
     * 
     * Use the smaller of the two buffer sizes as the copy size.
     */
    uint64_t copy_size = size;
    if (copy_size > umap_size)
        copy_size = umap_size;
    SGX_DBG(DBG_M, "file_map - memcpy - from (%p + offset %lld = %p), copy size is %llu\n", umem, umap_offset,
            umem + umap_offset, copy_size);
    memcpy(mem, umem + umap_offset, copy_size);

    /* Step four: verify the contents.*/
    if (stubs) {

        ret = __file_copy_and_check(handle, umem, umap_start, umap_end, offset, mem, end);
        if (ret) goto out_unmap;
    }
    
    /* Allocation and verification was successful.  Set *addr */
    *addr = mem;
    SGX_DBG(DBG_M, "*** file_map: done ok - setting addr to %p ***\n", mem);

out_unmap:
    if (ret) 
        free_pages(mem, size);
out:
    /* Unmap untrusted memory */
    ocall_unmap_untrusted(umem, umap_size);
    SGX_DBG(DBG_M, "file_map - finally returning %d\n", ret);
    return ret;
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
