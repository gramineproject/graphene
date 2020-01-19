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
 * shim_mmap.c
 *
 * Implementation of system call "mmap", "munmap" and "mprotect".
 */

#include <errno.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_profile.h>
#include <shim_table.h>
#include <shim_vma.h>
#include <stdatomic.h>
#include <sys/mman.h>

DEFINE_PROFILE_OCCURENCE(mmap, memory);

void* shim_do_mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
    struct shim_handle* hdl = NULL;
    long ret                = 0;

    /*
     * According to the manpage, both addr and offset have to be page-aligned,
     * but not the length. mmap() will automatically round up the length.
     */
    if (addr && !IS_ALLOC_ALIGNED_PTR(addr))
        return (void*)-EINVAL;

    if (fd >= 0 && !IS_ALLOC_ALIGNED(offset))
        return (void*)-EINVAL;

    if (!IS_ALLOC_ALIGNED(length))
        length = ALLOC_ALIGN_UP(length);

    if (!length || !access_ok(addr, length))
        return (void*)-EINVAL;

    /* ignore MAP_32BIT when MAP_FIXED is set */
    if ((flags & (MAP_32BIT | MAP_FIXED)) == (MAP_32BIT | MAP_FIXED))
        flags &= ~MAP_32BIT;

    assert(!(flags & (VMA_UNMAPPED | VMA_TAINTED)));

    int pal_alloc_type = 0;

    if ((flags & MAP_FIXED) || addr) {
        struct shim_vma_val tmp;

        if (addr < PAL_CB(user_address.start) || PAL_CB(user_address.end) <= addr ||
            (uintptr_t)PAL_CB(user_address.end) - (uintptr_t)addr < length) {
            debug(
                "mmap: user specified address %p with length %lu "
                "not in allowed user space, ignoring this hint\n",
                addr, length);
            if (flags & MAP_FIXED)
                return (void*)-EINVAL;
            addr = NULL;
        } else if (!lookup_overlap_vma(addr, length, &tmp)) {
            if (flags & MAP_FIXED)
                debug(
                    "mmap: allowing overlapping MAP_FIXED allocation at %p with "
                    "length %lu\n",
                    addr, length);
            else
                addr = NULL;
        }
    }

    if ((flags & (MAP_ANONYMOUS | MAP_FILE)) == MAP_FILE) {
        if (fd < 0)
            return (void*)-EINVAL;

        hdl = get_fd_handle(fd, NULL, NULL);
        if (!hdl)
            return (void*)-EBADF;

        if (!hdl->fs || !hdl->fs->fs_ops || !hdl->fs->fs_ops->mmap) {
            put_handle(hdl);
            return (void*)-ENODEV;
        }
    }

    if (addr) {
        bkeep_mmap(addr, length, prot, flags, hdl, offset, NULL);
    } else {
        addr = bkeep_unmapped_heap(length, prot, flags, hdl, offset, NULL);
        /*
         * Let the library OS manages the address space. If we can't find
         * proper space to allocate the memory, simply return failure.
         */
        if (!addr)
            return (void*)-ENOMEM;
    }

    // Approximate check only, to help root out bugs.
    void* cur_stack = current_stack();
    __UNUSED(cur_stack);
    assert(cur_stack < addr || cur_stack > addr + length);

    /* addr needs to be kept for bkeep_munmap() below */
    void* ret_addr = addr;
    if (!hdl) {
        ret_addr = (void*)DkVirtualMemoryAlloc(ret_addr, length, pal_alloc_type, PAL_PROT(prot, 0));

        if (!ret_addr) {
            if (PAL_NATIVE_ERRNO == PAL_ERROR_DENIED)
                ret = -EPERM;
            else
                ret = -PAL_ERRNO;
        }
    } else {
        ret = hdl->fs->fs_ops->mmap(hdl, &ret_addr, length, PAL_PROT(prot, flags), flags, offset);
    }

    if (hdl)
        put_handle(hdl);

    if (ret < 0) {
        bkeep_munmap(addr, length, flags);
        return (void*)ret;
    }

    ADD_PROFILE_OCCURENCE(mmap, length);
    return ret_addr;
}

int shim_do_mprotect(void* addr, size_t length, int prot) {
    /*
     * According to the manpage, addr has to be page-aligned, but not the
     * length. mprotect() will automatically round up the length.
     */
    if (!addr || !IS_ALLOC_ALIGNED_PTR(addr))
        return -EINVAL;

    if (!IS_ALLOC_ALIGNED(length))
        length = ALLOC_ALIGN_UP(length);

    if (bkeep_mprotect(addr, length, prot, 0) < 0)
        return -EPERM;

    if (!DkVirtualMemoryProtect(addr, length, prot))
        return -PAL_ERRNO;

    return 0;
}

int shim_do_munmap(void* addr, size_t length) {
    /*
     * According to the manpage, addr has to be page-aligned, but not the
     * length. munmap() will automatically round up the length.
     */
    if (!addr || !IS_ALLOC_ALIGNED_PTR(addr))
        return -EINVAL;

    if (!length || !access_ok(addr, length))
        return -EINVAL;

    if (!IS_ALLOC_ALIGNED(length))
        length = ALLOC_ALIGN_UP(length);

    struct shim_vma_val vma;

    if (lookup_overlap_vma(addr, length, &vma) < 0) {
        debug("can't find addr %p - %p in map, quit unmapping\n", addr, addr + length);

        /* Really not an error */
        return -EFAULT;
    }

    /* lookup_overlap_vma() calls __dump_vma() which adds a reference to file */
    if (vma.file)
        put_handle(vma.file);

    /* Protect first to make sure no overlapping with internal
     * mappings */
    if (bkeep_mprotect(addr, length, PROT_NONE, 0) < 0)
        return -EPERM;

    DkVirtualMemoryFree(addr, length);

    if (bkeep_munmap(addr, length, 0) < 0)
        BUG();

    return 0;
}

/* This emulation of mincore() always tells that pages are _NOT_ in RAM
 * pessimistically due to lack of a good way to know it.
 * Possibly it may cause performance(or other) issue due to this lying.
 */
int shim_do_mincore(void* addr, size_t len, unsigned char* vec) {
    if (!IS_ALLOC_ALIGNED_PTR(addr))
        return -EINVAL;

    if (test_user_memory(addr, len, false))
        return -ENOMEM;

    unsigned long pages = ALLOC_ALIGN_UP(len) / g_pal_alloc_align;
    if (test_user_memory(vec, pages, true))
        return -EFAULT;

    for (unsigned long i = 0; i < pages; i++) {
        struct shim_vma_val vma;
        if (lookup_overlap_vma(addr + i * g_pal_alloc_align, 1, &vma) < 0)
            return -ENOMEM;
        /*
         * lookup_overlap_vma() calls __dump_vma() which adds a reference to
         * file, remove the reference to file immediately since we don't use
         * it anyway
         */
        if (vma.file)
            put_handle(vma.file);
        if (vma.flags & VMA_UNMAPPED)
            return -ENOMEM;
    }

    static atomic_bool warned = false;
    if (!warned) {
        warned = true;
        warn("mincore emulation always tells pages are _NOT_ in RAM. This may cause issues.\n");
    }

    /* There is no good way to know if the page is in RAM.
     * Conservatively tell that it's not in RAM. */
    for (unsigned long i = 0; i < pages; i++) {
        vec[i] = 0;
    }

    return 0;
}


int shim_do_mbind(void* start, unsigned long len, int mode, unsigned long* nmask,
                  unsigned long maxnode, int flags) {
    /* dummy implementation, always return success */
    __UNUSED(start);
    __UNUSED(len);
    __UNUSED(mode);
    __UNUSED(nmask);
    __UNUSED(maxnode);
    __UNUSED(flags);
    return 0;
}
