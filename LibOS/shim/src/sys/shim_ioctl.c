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

        /* FIXME: another very special case, similar to the one above but using another IOCTL:
         *        DRM_IOCTL_I915_QUERY(DRM_I915_QUERY_ENGINE_INFO). Newer Intel Media Driver
         *        uses this IOCTL to collect info on all engines. Some of these engines are of
         *        class I915_ENGINE_CLASS_VIDEO (which corresponds to a VCS ring above). The code
         *        below filters these classes and only allows one to be returned (the others are
         *        marked as I915_ENGINE_CLASS_INVALID so Media Driver doesn't recognize them). */
        if (cmd == /*DRM_IOCTL_I915_QUERY*/0xc0106479) {
            struct i915_engine_class_instance {
                uint16_t engine_class;
                uint16_t engine_instance;
            };
            struct drm_i915_engine_info {
                struct i915_engine_class_instance engine;
                uint32_t rsvd0;
                uint64_t flags;
                uint64_t capabilities;
                uint64_t rsvd1[4];
            };
            struct drm_i915_query_engine_info {
                uint32_t num_engines;
                uint32_t rsvd[3];
                struct drm_i915_engine_info engines[];
            };
            struct drm_i915_query_item {
                uint64_t query_id;
                int32_t length;
                uint32_t flags;
                uint64_t data_ptr;
            };
            struct drm_i915_query {
                uint32_t num_items;
                uint32_t flags;
                struct drm_i915_query_item* query_items;
            };

            uint32_t engine_class_video_num = 0;
            struct drm_i915_query* arg_query = (struct drm_i915_query*)arg;
            for (uint32_t i = 0; i < arg_query->num_items; i++) {
                struct drm_i915_query_item* query_item = &arg_query->query_items[i];
                if (query_item->length <= 0 || query_item->data_ptr == 0)
                    continue;
                if (query_item->query_id != /*DRM_I915_QUERY_ENGINE_INFO*/2)
                    continue;

                struct drm_i915_query_engine_info* query_engine_info =
                    (struct drm_i915_query_engine_info*)query_item->data_ptr;
                for (uint32_t j = 0; j < query_engine_info->num_engines; j++) {
                    struct drm_i915_engine_info* engine_info = &query_engine_info->engines[j];
                    if (engine_info->engine.engine_class == /*I915_ENGINE_CLASS_VIDEO*/2) {
                        engine_class_video_num++;
                        if (engine_class_video_num > 1) {
                            /* this is second, third, ... 'video' engine, mark as invalid */
                            engine_info->engine.engine_class = /*I915_ENGINE_CLASS_INVALID*/-1;
                        }
                    }
                }
            }
        }
    }

    put_handle(hdl);
    return ret;
}
