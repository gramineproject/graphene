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

    assert(!(flags & (VMA_UNMAPPED|VMA_TAINTED)));

    int pal_alloc_type = ((flags & MAP_32BIT) ? PAL_ALLOC_32BIT : 0);
    int pal_prot = prot;

    addr = addr ? : get_unmapped_vma(ALIGN_UP(length), flags);

    void * mapped = ALIGN_DOWN((void *) addr);
    void * mapped_end = ALIGN_UP((void *) addr + length);

    addr = mapped;
    length = mapped_end - mapped;

    if (flags & MAP_ANONYMOUS) {
        addr = DkVirtualMemoryAlloc(addr, length, pal_alloc_type,
                                    pal_prot);

        if (!addr)
            return (void *) -PAL_ERRNO;

        ADD_PROFILE_OCCURENCE(mmap, length);
    } else {
        if (fd < 0)
            return (void *) -EINVAL;

        hdl = get_fd_handle(fd, NULL, NULL);
        if (!hdl)
            return (void *) -EBADF;

        if (!hdl->fs || !hdl->fs->fs_ops || !hdl->fs->fs_ops->mmap) {
            put_handle(hdl);
            return (void *) -ENODEV;
        }

        if (flags & MAP_PRIVATE)
            prot |= PAL_PROT_WRITECOPY;

        if ((ret = hdl->fs->fs_ops->mmap(hdl, &addr, length, prot,
                                         flags, offset)) < 0) {
            put_handle(hdl);
            return (void *) ret;
        }
    }

    if (addr != mapped) {
        mapped = ALIGN_DOWN((void *) addr);
        mapped_end = ALIGN_UP((void *) addr + length);
    }

    ret = bkeep_mmap((void *) mapped, mapped_end - mapped, prot,
                     flags, hdl, offset, "user");
    assert(!ret);
    if (hdl)
        put_handle(hdl);
    return addr;
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
