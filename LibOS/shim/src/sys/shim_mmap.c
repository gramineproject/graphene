/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_mmap.c
 *
 * Implementation of system call "mmap", "munmap" and "mprotect".
 */

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_handle.h>
#include <shim_vma.h>
#include <shim_fs.h>
#include <shim_profile.h>

#include <pal.h>
#include <pal_error.h>

#include <sys/mman.h>
#include <errno.h>

DEFINE_PROFILE_OCCURENCE(mmap, memory);

void * shim_do_mmap (void * addr, size_t length, int prot, int flags, int fd,
                     off_t offset)
{
    struct shim_handle * hdl = NULL;
    long ret = -ENOMEM;
    bool reserved = false;

    assert(!(flags & (VMA_UNMAPPED|VMA_TAINTED)));

    if (flags & MAP_32BIT)
        return -ENOSYS;

    int pal_alloc_type = 0;

    if (!addr) {
        addr = get_unmapped_vma(ALIGN_UP(length), flags);
        if (addr)
            reserved = true;
    }

    if (addr) {
        void * cur_stack = current_stack();
        assert(cur_stack < addr || cur_stack > addr + length);
    }

    void * mapped = ALIGN_DOWN((void *) addr);
    void * mapped_end = ALIGN_UP((void *) addr + length);

    addr = mapped;
    length = mapped_end - mapped;

    if (flags & MAP_ANONYMOUS) {
        addr = (void *) DkVirtualMemoryAlloc(addr, length, pal_alloc_type,
                                             PAL_PROT(prot, 0));

        if (!addr) {
            ret = (PAL_NATIVE_ERRNO == PAL_ERROR_DENIED) ? -EPERM : -PAL_ERRNO;
            goto free_reserved;
        }

        ADD_PROFILE_OCCURENCE(mmap, length);
    } else {
        if (fd < 0) {
            ret = -EINVAL;
            goto free_reserved;
        }

        hdl = get_fd_handle(fd, NULL, NULL);
        if (!hdl) {
            ret = -EBADF;
            goto free_reserved;
        }

        if (!hdl->fs || !hdl->fs->fs_ops || !hdl->fs->fs_ops->mmap) {
            put_handle(hdl);
            ret = -ENODEV;
            goto free_reserved;
        }

        if ((ret = hdl->fs->fs_ops->mmap(hdl, &addr, length, prot,
                                         flags, offset)) < 0) {
            put_handle(hdl);
            goto free_reserved;
        }
    }

    if (addr != mapped) {
        mapped = ALIGN_DOWN((void *) addr);
        mapped_end = ALIGN_UP((void *) addr + length);
    }

    ret = bkeep_mmap((void *) mapped, mapped_end - mapped, prot,
                     flags, hdl, offset, NULL);
    assert(!ret);
    if (hdl)
        put_handle(hdl);
    return addr;

free_reserved:
    if (reserved)
        bkeep_munmap((void *) mapped, mapped_end - mapped, &flags);
    return (void *) ret;
}

int shim_do_mprotect (void * addr, size_t len, int prot)
{
    uintptr_t mapped = ALIGN_DOWN((uintptr_t) addr);
    uintptr_t mapped_end = ALIGN_UP((uintptr_t) addr + len);
    int flags = 0;

    if (bkeep_mprotect((void *) mapped, mapped_end - mapped, prot, &flags) < 0)
        return -EACCES;

    if (!DkVirtualMemoryProtect((void *) mapped, mapped_end - mapped, prot))
        return -PAL_ERRNO;

    return 0;
}

int shim_do_munmap (void * addr, size_t len)
{
    struct shim_vma * tmp = NULL;

    if (lookup_overlap_vma(addr, len, &tmp) < 0) {
        debug("can't find addr %p - %p in map, quit unmapping\n",
              addr, addr + len);

        /* Really not an error */
        return -EFAULT;
    }

    uintptr_t mapped = ALIGN_DOWN((uintptr_t) addr);
    uintptr_t mapped_end = ALIGN_UP((uintptr_t) addr + len);
    int flags = 0;

    if (bkeep_munmap((void *) mapped, mapped_end - mapped, &flags) < 0)
        return -EACCES;

    DkVirtualMemoryFree((void *) mapped, mapped_end - mapped);
    return 0;
}
