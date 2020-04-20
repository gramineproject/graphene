/* Copyright (C) 2014 Stony Brook University
   Copyright (C) 2020 Invisible Things Lab
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
#include <shim_table.h>
#include <shim_vma.h>
#include <stdatomic.h>
#include <sys/mman.h>

#define LEGACY_MAP_MASK (MAP_SHARED \
                | MAP_PRIVATE \
                | MAP_FIXED \
                | MAP_ANONYMOUS \
                | MAP_DENYWRITE \
                | MAP_EXECUTABLE \
                | MAP_UNINITIALIZED \
                | MAP_GROWSDOWN \
                | MAP_LOCKED \
                | MAP_NORESERVE \
                | MAP_POPULATE \
                | MAP_NONBLOCK \
                | MAP_STACK \
                | MAP_HUGETLB \
                | MAP_32BIT \
                | MAP_HUGE_2MB \
                | MAP_HUGE_1GB)

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

    /* This check is Graphene specific. */
    if (flags & (VMA_UNMAPPED | VMA_TAINTED | VMA_INTERNAL)) {
        return (void*)-EINVAL;
    }

    if (flags & MAP_ANONYMOUS) {
        switch (flags & MAP_TYPE) {
            case MAP_SHARED:
                break;
            case MAP_PRIVATE:
                break;
            default:
                return (void*)-EINVAL;
        }
    } else {
        /* MAP_FILE is the opposite of MAP_ANONYMOUS and is implicit */
        switch (flags & MAP_TYPE) {
            case MAP_SHARED:
                flags &= LEGACY_MAP_MASK;
                /* fall through */
            case MAP_SHARED_VALIDATE:
                /* Currently we do not support additional flags like MAP_SYNC */
                if (flags & ~LEGACY_MAP_MASK) {
                    return (void*)-EOPNOTSUPP;
                }
                /* fall through */
            case MAP_PRIVATE:
                if (fd < 0) {
                    return (void*)-EINVAL;
                }

                hdl = get_fd_handle(fd, NULL, NULL);
                if (!hdl) {
                    return (void*)-EBADF;
                }

                if (!hdl->fs || !hdl->fs->fs_ops || !hdl->fs->fs_ops->mmap) {
                    ret = -ENODEV;
                    goto out_handle;
                }

                if (hdl->flags & O_WRONLY) {
                    ret = -EACCES;
                    goto out_handle;
                }

                if ((flags & MAP_SHARED) && (prot & PROT_WRITE) && !(hdl->flags & O_RDWR)) {
                    ret = -EACCES;
                    goto out_handle;
                }

                break;
            default:
                return (void*)-EINVAL;
        }
    }

    /* ignore MAP_32BIT when MAP_FIXED is set */
    if ((flags & (MAP_32BIT | MAP_FIXED)) == (MAP_32BIT | MAP_FIXED))
        flags &= ~MAP_32BIT;

    if (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) {
        ret = bkeep_mmap_fixed(addr, length, prot, flags, hdl, offset, NULL);
        if (ret < 0) {
            goto out_handle;
        }
    } else {
        /* We know that `addr + length` does not overflow (`access_ok` above). */
        if (addr && ((uintptr_t)addr + length <= (uintptr_t)PAL_CB(user_address.end))) {
            ret = bkeep_mmap_any_in_range(PAL_CB(user_address.start), (char*)addr + length, length,
                                          prot, flags, hdl, offset, NULL, &addr);
        } else {
            /* Hacky way to mark we had no hit and need to search below. */
            ret = -1;
        }
        if (ret < 0) {
            /* We either had no hinted address or could not allocate memory at it. */
            ret = bkeep_mmap_any_aslr(length, prot, flags, hdl, offset, NULL, &addr);
        }
        if (ret < 0) {
            ret = -ENOMEM;
            goto out_handle;
        }
    }

    if (!hdl) {
        if (DkVirtualMemoryAlloc(addr, length, 0, PAL_PROT(prot, flags)) != addr) {
            if (PAL_NATIVE_ERRNO == PAL_ERROR_DENIED) {
                ret = -EPERM;
            } else {
                ret = -PAL_ERRNO;
            }
        }
    } else {
        void* ret_addr = addr;
        ret = hdl->fs->fs_ops->mmap(hdl, &ret_addr, length, prot, flags, offset);
        if (ret_addr != addr) {
            debug("Requested address (%p) differs from allocated (%p)!\n", addr, ret_addr);
            BUG();
        }
    }

    if (ret < 0) {
        void* tmp_vma = NULL;
        if (bkeep_munmap(addr, length, /*is_internal=*/false, &tmp_vma) < 0) {
            debug("[mmap] Failed to remove bookkeeped memory that was not allocated at %p-%p!\n",
                  addr, (char*)addr + length);
            BUG();
        }
        bkeep_remove_tmp_vma(tmp_vma);
    }

out_handle:
    if (hdl) {
        put_handle(hdl);
    }

    if (ret < 0) {
        return (void*)ret;
    }
    return addr;
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

    int ret = bkeep_mprotect(addr, length, prot, /*is_internal=*/false);
    if (ret < 0) {
        return ret;
    }

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

    void* tmp_vma = NULL;
    int ret = bkeep_munmap(addr, length, /*is_internal=*/false, &tmp_vma);
    if (ret < 0) {
        return ret;
    }

    DkVirtualMemoryFree(addr, length);

    bkeep_remove_tmp_vma(tmp_vma);

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

    if (!is_in_adjacent_user_vmas(addr, len)) {
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
