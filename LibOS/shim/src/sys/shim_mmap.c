/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Invisible Things Lab
 * Copyright (C) 2020 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

/*
 * Implementation of system calls "mmap", "munmap" and "mprotect".
 */

#include <errno.h>
#include <stdatomic.h>
#include <sys/mman.h>

#include "pal.h"
#include "pal_error.h"
#include "shim_flags_conv.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_table.h"
#include "shim_vma.h"

#ifdef MAP_32BIT /* x86_64-specific */
#define MAP_32BIT_IF_SUPPORTED MAP_32BIT
#else
#define MAP_32BIT_IF_SUPPORTED 0
#endif

#define LEGACY_MAP_MASK (MAP_SHARED             \
                       | MAP_PRIVATE            \
                       | MAP_FIXED              \
                       | MAP_ANONYMOUS          \
                       | MAP_DENYWRITE          \
                       | MAP_EXECUTABLE         \
                       | MAP_UNINITIALIZED      \
                       | MAP_GROWSDOWN          \
                       | MAP_LOCKED             \
                       | MAP_NORESERVE          \
                       | MAP_POPULATE           \
                       | MAP_NONBLOCK           \
                       | MAP_STACK              \
                       | MAP_HUGETLB            \
                       | MAP_32BIT_IF_SUPPORTED \
                       | MAP_HUGE_2MB           \
                       | MAP_HUGE_1GB)

void* shim_do_mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
    struct shim_handle* hdl = NULL;
    long ret = 0;

    if (!(flags & MAP_FIXED) && addr)
        addr = ALLOC_ALIGN_DOWN_PTR(addr);

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

#ifdef MAP_32BIT
    /* ignore MAP_32BIT when MAP_FIXED is set */
    if ((flags & (MAP_32BIT | MAP_FIXED)) == (MAP_32BIT | MAP_FIXED))
        flags &= ~MAP_32BIT;
#endif

    /* mmap on devices is special: pass-through and not reflected in LibOS's VMA metadata */
    if (hdl && hdl->type == TYPE_FILE && hdl->info.file.type == FILE_DEV) {
        void* ret_addr = addr;
        ret = hdl->fs->fs_ops->mmap(hdl, &ret_addr, length, prot, flags, offset);
        if (!ret)
            addr = ret_addr;
        goto out_handle;
    }

    if (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) {
        /* We know that `addr + length` does not overflow (`access_ok` above). */
        if (addr < PAL_CB(user_address.start)
                || (uintptr_t)PAL_CB(user_address.end) < (uintptr_t)addr + length) {
            ret = -EINVAL;
            goto out_handle;
        }
        ret = bkeep_mmap_fixed(addr, length, prot, flags, hdl, offset, NULL);
        if (ret < 0) {
            goto out_handle;
        }
    } else {
        /* We know that `addr + length` does not overflow (`access_ok` above). */
        if (addr && (uintptr_t)PAL_CB(user_address.start) <= (uintptr_t)addr
                && (uintptr_t)addr + length <= (uintptr_t)PAL_CB(user_address.end)) {
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

    /* From now on `addr` contains the actual address we want to map (and already bookkeeped). */

    if (!hdl) {
        if (DkVirtualMemoryAlloc(addr, length, 0, LINUX_PROT_TO_PAL(prot, flags)) != addr) {
            if (PAL_NATIVE_ERRNO() == PAL_ERROR_DENIED) {
                ret = -EPERM;
            } else {
                ret = -PAL_ERRNO();
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
    if (prot & ~(PROT_NONE | PROT_READ | PROT_WRITE | PROT_EXEC | PROT_GROWSDOWN | PROT_GROWSUP |
                 PROT_SEM)) {
        return -EINVAL;
    }

    if ((prot & (PROT_GROWSDOWN | PROT_GROWSUP)) == (PROT_GROWSDOWN | PROT_GROWSUP)) {
        return -EINVAL;
    }

    /* We do not support these flags (at least yet). */
    if (prot & (PROT_GROWSUP | PROT_SEM)) {
        return -EOPNOTSUPP;
    }

    /*
     * According to the manpage, addr has to be page-aligned, but not the
     * length. mprotect() will automatically round up the length.
     */
    if (!addr || !IS_ALLOC_ALIGNED_PTR(addr))
        return -EINVAL;

    if (length == 0) {
        return 0;
    }

    if (!IS_ALLOC_ALIGNED(length))
        length = ALLOC_ALIGN_UP(length);

    if (!access_ok(addr, length)) {
        return -EINVAL;
    }

    /* `bkeep_mprotect` and then `DkVirtualMemoryProtect` is racy, but it's hard to do it properly.
     * On the other hand if this race happens, it means user app is buggy, so not a huge problem. */

    int ret = bkeep_mprotect(addr, length, prot, /*is_internal=*/false);
    if (ret < 0) {
        return ret;
    }

    if (prot & PROT_GROWSDOWN) {
        struct shim_vma_info vma_info = {0};
        if (lookup_vma(addr, &vma_info) >= 0) {
            addr = vma_info.addr;
            if (vma_info.file) {
                put_handle(vma_info.file);
            }
        } else {
            warn("Memory that was about to be mprotected was unmapped, your program is buggy!\n");
            return -ENOTRECOVERABLE;
        }
    }

    if (!DkVirtualMemoryProtect(addr, length, LINUX_PROT_TO_PAL(prot, /*map_flags=*/0)))
        return -PAL_ERRNO();

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

static bool madvise_behavior_valid(int behavior) {
    switch (behavior) {
        case MADV_DOFORK:
        case MADV_DONTFORK:
        case MADV_NORMAL:
        case MADV_SEQUENTIAL:
        case MADV_RANDOM:
        case MADV_REMOVE:
        case MADV_WILLNEED:
        case MADV_DONTNEED:
        case MADV_FREE:
        case MADV_MERGEABLE:
        case MADV_UNMERGEABLE:
        case MADV_HUGEPAGE:
        case MADV_NOHUGEPAGE:
        case MADV_DONTDUMP:
        case MADV_DODUMP:
        case MADV_WIPEONFORK:
        case MADV_KEEPONFORK:
        case MADV_SOFT_OFFLINE:
        case MADV_HWPOISON:
            return true;
    }
    return false;
}

long shim_do_madvise(unsigned long start, size_t len_in, int behavior) {
    if (!madvise_behavior_valid(behavior))
        return -EINVAL;

    if (!IS_ALIGNED_POW2(start, PAGE_SIZE))
        return -EINVAL;

    size_t len = ALIGN_UP(len_in, PAGE_SIZE);
    if (len < len_in)
        return -EINVAL; // overflow when rounding up

    if (!access_ok((void*)start, len))
        return -EINVAL;

    if (len == 0)
        return 0;

    switch (behavior) {
        case MADV_NORMAL:
        case MADV_RANDOM:
        case MADV_SEQUENTIAL:
        case MADV_WILLNEED:
        case MADV_FREE:
        case MADV_SOFT_OFFLINE:
        case MADV_MERGEABLE:
        case MADV_UNMERGEABLE:
        case MADV_HUGEPAGE:
        case MADV_NOHUGEPAGE:
            return 0; // Doing nothing is semantically correct for these modes.

        case MADV_DONTFORK:
        case MADV_DOFORK:
        case MADV_WIPEONFORK:
        case MADV_KEEPONFORK:
        case MADV_HWPOISON:
        case MADV_DONTDUMP:
        case MADV_DODUMP:
        case MADV_REMOVE:
            return -ENOSYS; // Not implemented

        case MADV_DONTNEED: {
            return madvise_dontneed_range(start, start + len);
        }
    }
    return -EINVAL;
}
