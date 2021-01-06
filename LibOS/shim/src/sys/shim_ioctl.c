/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system call "ioctl".
 */

#include <asm/ioctls.h>
#include <sys/eventfd.h>

#include "pal.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_process.h"
#include "shim_signal.h"
#include "shim_table.h"

static void signal_io(IDTYPE caller, void* arg) {
    __UNUSED(caller);
    __UNUSED(arg);
    /* TODO: fill these values e.g. by getting the handle in arg; this is completely unusable now */
    siginfo_t info = {
        .si_signo = SIGIO,
        .si_code = SI_SIGIO,
        .si_band = 0,
        .si_fd = 0,
    };
    if (kill_current_proc(&info) < 0) {
        debug("signal_io: failed to deliver a signal\n");
    }
}

long shim_do_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg) {
    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret;
    switch (cmd) {
        case TIOCGPGRP:
            if (hdl->type != TYPE_FILE || hdl->info.file.type != FILE_TTY) {
                ret = -ENOTTY;
                break;
            }

            if (test_user_memory((void*)arg, sizeof(int), /*write=*/true)) {
                ret = -EFAULT;
                break;
            }
            *(int*)arg = __atomic_load_n(&g_process.pgid, __ATOMIC_ACQUIRE);
            ret = 0;
            break;
        case FIONBIO:
            ret = set_handle_nonblocking(hdl);
            break;
        case FIONCLEX:
            hdl->flags &= ~FD_CLOEXEC;
            ret = 0;
            break;
        case FIOCLEX:
            hdl->flags |= FD_CLOEXEC;
            ret = 0;
            break;
        case FIOASYNC:
            ret = install_async_event(hdl->pal_handle, 0, &signal_io, NULL);
            break;
        case FIONREAD: {
            if (test_user_memory((void*)arg, sizeof(int), /*write=*/true)) {
                ret = -EFAULT;
                break;
            }

            struct shim_mount* fs = hdl->fs;
            if (!fs || !fs->fs_ops) {
                ret = -EACCES;
                break;
            }

            int size = 0;
            if (fs->fs_ops->hstat) {
                struct stat stat;
                ret = fs->fs_ops->hstat(hdl, &stat);
                if (ret < 0)
                    break;
                size = stat.st_size;
            } else if (hdl->pal_handle) {
                PAL_STREAM_ATTR attr;
                if (!DkStreamAttributesQueryByHandle(hdl->pal_handle, &attr)) {
                    ret = -PAL_ERRNO();
                    break;
                }
                size = attr.pending_size;
            }

            int offset = 0;
            if (fs->fs_ops->seek) {
                ret = fs->fs_ops->seek(hdl, 0, SEEK_CUR);
                if (ret < 0)
                    break;
                offset = ret;
            }

            *(int*)arg = size - offset;
            ret = 0;
            break;
        }
        default:
            ret = -ENOSYS;
            break;
    }

    if (ret == -ENOSYS && hdl->type == TYPE_FILE && hdl->info.file.type == FILE_DEV) {
        /* LibOS doesn't know how to handle this IOCTL, forward it to the host */
        ret = 0;
        if (!DkDeviceIoControl(hdl->pal_handle, cmd, arg))
            ret = -PAL_ERRNO();

        /* FIXME: very special case of DRM_IOCTL_I915_GEM_EXECBUFFER2_WR: its arg is of type
         *        drm_i915_gem_execbuffer2 with a field `rsvd2 >> 32` returning a "fence" FD to poll
         *        on (basically, an eventfd type of FD): we need to create a corresponding object in
         *        Graphene, we abuse eventfd for it */
        if (cmd == /*DRM_IOCTL_I915_GEM_EXECBUFFER2_WR*/0xc0406469) {
            char* arg_char = (char*)arg;
            uint64_t rsvd2 = *((uint64_t*)(arg_char + 56)); /* 56 is offset of rsvd2 */
            int fence_fd = rsvd2 >> 32;
            int ret_fd = shim_do_eventfd2(/*count=*/fence_fd, /*flags=*/EFD_SEMAPHORE);
            if (ret_fd >= 0) {
                fence_fd = ret_fd;
                *((uint64_t*)(arg_char + 56)) = (uint64_t)fence_fd << 32;
            }
        }

        /* FIXME: very special case of DRM_IOCTL_I915_GETPARAM(I915_PARAM_HAS_BSD2): Intel Media
         *        Driver uses Sys-V IPC (semget and shmget family of syscalls) for multi-process
         *        user-mode synchronization (to load-balance execution of video encode/decode on
         *        two VCS rings) if I915_PARAM_HAS_BSD2 == true; we don't support shmget() in
         *        Graphene so we stub I915_PARAM_HAS_BSD2 = false; this leads to slightly worse
         *        performance because only one VCS ring is used for video encode/decode but this may
         *        be fixed after Media Driver removes this Sys-V IPC dependency (see comment
         *        https://bugzilla.mozilla.org/show_bug.cgi?id=1619585#c46). */
        if (cmd == /*DRM_IOCTL_I915_GETPARAM*/0xc0106446) {
            typedef struct drm_i915_getparam {int32_t param; int* value;} drm_i915_getparam_t;
            drm_i915_getparam_t* arg_getparam = (drm_i915_getparam_t*)arg;
            if (arg_getparam->param == /*I915_PARAM_HAS_BSD2*/31) {
                /* return BSD2 = false, meaning there is no second VCS ring */
                arg_getparam->value = 0;
            }
        }
    }

    put_handle(hdl);
    return ret;
}
