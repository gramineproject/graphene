/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains code to maintain bookkeeping for handles in library OS.
 */

#include "pal.h"
#include "pal_error.h"
#include "shim_checkpoint.h"
#include "shim_fs.h"
#include "shim_handle.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_thread.h"

static struct shim_lock handle_mgr_lock;

#define HANDLE_MGR_ALLOC 32

#define SYSTEM_LOCK()   lock(&handle_mgr_lock)
#define SYSTEM_UNLOCK() unlock(&handle_mgr_lock)
#define SYSTEM_LOCKED() locked(&handle_mgr_lock)

#define OBJ_TYPE struct shim_handle
#include "memmgr.h"

static MEM_MGR handle_mgr = NULL;

#define INIT_HANDLE_MAP_SIZE 32

//#define DEBUG_REF

static int init_tty_handle(struct shim_handle* hdl, bool write) {
    int ret;

    hdl->type  = TYPE_DEV;
    hdl->flags = write ? (O_WRONLY | O_APPEND) : O_RDONLY;

    struct shim_dentry* dent = NULL;
    if ((ret = path_lookupat(NULL, "/dev/tty", LOOKUP_OPEN, &dent, NULL)) < 0)
        return ret;

    ret = dent->fs->d_ops->open(hdl, dent, hdl->flags);
    if (ret < 0)
        return ret;

    set_handle_fs(hdl, dent->fs);
    hdl->dentry = dent;
    dentry_get_path_into_qstr(dent, &hdl->path);
    return 0;
}

static inline int init_exec_handle(void) {
    if (!PAL_CB(executable))
        return 0;

    struct shim_handle* exec = get_new_handle();
    if (!exec)
        return -ENOMEM;

    qstrsetstr(&exec->uri, PAL_CB(executable), strlen(PAL_CB(executable)));
    exec->type     = TYPE_FILE;
    exec->flags    = O_RDONLY;
    exec->acc_mode = MAY_READ;

    struct shim_mount* fs = find_mount_from_uri(PAL_CB(executable));
    if (fs) {
        const char* p = PAL_CB(executable) + fs->uri.len;
        /*
         * Lookup for PAL_CB(executable) needs to be done under a given
         * mount point. which requires a relative path name.
         * On the other hand, the one in manifest file can be absolute path.
         */
        while (*p == '/') {
            p++;
        }
        path_lookupat(fs->root, p, 0, &exec->dentry, fs);
        set_handle_fs(exec, fs);
        if (exec->dentry)
            dentry_get_path_into_qstr(exec->dentry, &exec->path);
        put_mount(fs);
    } else {
        set_handle_fs(exec, &chroot_builtin_fs);
    }

    lock(&g_process.fs_lock);
    g_process.exec = exec;
    unlock(&g_process.fs_lock);

    return 0;
}

static struct shim_handle_map* get_new_handle_map(FDTYPE size);

static int __init_handle(struct shim_fd_handle** fdhdl, FDTYPE fd, struct shim_handle* hdl,
                         int fd_flags);

static int __enlarge_handle_map(struct shim_handle_map* map, size_t size);

int init_handle(void) {
    if (!create_lock(&handle_mgr_lock)) {
        return -ENOMEM;
    }
    handle_mgr = create_mem_mgr(init_align_up(HANDLE_MGR_ALLOC));
    if (!handle_mgr) {
        return -ENOMEM;
    }
    return 0;
}

int init_important_handles(void) {
    int ret;
    struct shim_thread* thread = get_cur_thread();

    if (thread->handle_map)
        goto done;

    struct shim_handle_map* handle_map = get_thread_handle_map(thread);

    if (!handle_map) {
        handle_map = get_new_handle_map(INIT_HANDLE_MAP_SIZE);
        if (!handle_map)
            return -ENOMEM;

        set_handle_map(thread, handle_map);
        put_handle_map(handle_map);
    }

    /* `handle_map` is set in current thread, no need to increase ref-count. */

    lock(&handle_map->lock);

    if (handle_map->fd_size < 3) {
        ret = __enlarge_handle_map(handle_map, INIT_HANDLE_MAP_SIZE);
        if (ret < 0) {
            unlock(&handle_map->lock);
            return ret;
        }
    }

    /* initialize stdin */
    if (!HANDLE_ALLOCATED(handle_map->map[0])) {
        struct shim_handle* stdin_hdl = get_new_handle();
        if (!stdin_hdl) {
            unlock(&handle_map->lock);
            return -ENOMEM;
        }

        if ((ret = init_tty_handle(stdin_hdl, /*write=*/false)) < 0) {
            unlock(&handle_map->lock);
            put_handle(stdin_hdl);
            return ret;
        }

        __init_handle(&handle_map->map[0], /*fd=*/0, stdin_hdl, /*flags=*/0);
        put_handle(stdin_hdl);
    }

    /* initialize stdout */
    if (!HANDLE_ALLOCATED(handle_map->map[1])) {
        struct shim_handle* stdout_hdl = get_new_handle();
        if (!stdout_hdl) {
            unlock(&handle_map->lock);
            return -ENOMEM;
        }

        if ((ret = init_tty_handle(stdout_hdl, /*write=*/true)) < 0) {
            unlock(&handle_map->lock);
            put_handle(stdout_hdl);
            return ret;
        }

        __init_handle(&handle_map->map[1], /*fd=*/1, stdout_hdl, /*flags=*/0);
        put_handle(stdout_hdl);
    }

    /* initialize stderr as duplicate of stdout */
    if (!HANDLE_ALLOCATED(handle_map->map[2])) {
        struct shim_handle* stdout_hdl = handle_map->map[1]->handle;
        __init_handle(&handle_map->map[2], /*fd=*/2, stdout_hdl, /*flags=*/0);
    }

    if (handle_map->fd_top == FD_NULL || handle_map->fd_top < 2)
        handle_map->fd_top = 2;

    unlock(&handle_map->lock);

done:
    return init_exec_handle();
}

struct shim_handle* __get_fd_handle(FDTYPE fd, int* fd_flags, struct shim_handle_map* map) {
    assert(locked(&map->lock));

    struct shim_fd_handle* fd_handle = NULL;

    if (map->fd_top != FD_NULL && fd <= map->fd_top) {
        fd_handle = map->map[fd];
        if (!HANDLE_ALLOCATED(fd_handle))
            return NULL;

        if (fd_flags)
            *fd_flags = fd_handle->flags;

        return fd_handle->handle;
    }
    return NULL;
}

struct shim_handle* get_fd_handle(FDTYPE fd, int* fd_flags, struct shim_handle_map* map) {
    if (!map)
        map = get_thread_handle_map(NULL);

    struct shim_handle* hdl = NULL;
    lock(&map->lock);
    if ((hdl = __get_fd_handle(fd, fd_flags, map)))
        get_handle(hdl);
    unlock(&map->lock);
    return hdl;
}

struct shim_handle* __detach_fd_handle(struct shim_fd_handle* fd, int* flags,
                                       struct shim_handle_map* map) {
    assert(locked(&map->lock));

    struct shim_handle* handle = NULL;

    if (HANDLE_ALLOCATED(fd)) {
        int vfd = fd->vfd;
        handle  = fd->handle;
        if (flags)
            *flags = fd->flags;

        fd->vfd    = FD_NULL;
        fd->handle = NULL;
        fd->flags  = 0;

        if (vfd == map->fd_top)
            do {
                map->fd_top = vfd ? vfd - 1 : FD_NULL;
                vfd--;
            } while (vfd >= 0 && !HANDLE_ALLOCATED(map->map[vfd]));
    }

    return handle;
}

struct shim_handle* detach_fd_handle(FDTYPE fd, int* flags, struct shim_handle_map* handle_map) {
    struct shim_handle* handle = NULL;

    if (!handle_map && !(handle_map = get_thread_handle_map(NULL)))
        return NULL;

    lock(&handle_map->lock);

    if (fd < handle_map->fd_size)
        handle = __detach_fd_handle(handle_map->map[fd], flags, handle_map);

    unlock(&handle_map->lock);
    return handle;
}

struct shim_handle* get_new_handle(void) {
    struct shim_handle* new_handle =
        get_mem_obj_from_mgr_enlarge(handle_mgr, size_align_up(HANDLE_MGR_ALLOC));
    if (!new_handle)
        return NULL;

    memset(new_handle, 0, sizeof(struct shim_handle));
    REF_SET(new_handle->ref_count, 1);
    if (!create_lock(&new_handle->lock)) {
        free_mem_obj_to_mgr(handle_mgr, new_handle);
        return NULL;
    }
    new_handle->owner = g_process_ipc_info.vmid;
    INIT_LISTP(&new_handle->epolls);
    return new_handle;
}

static int __init_handle(struct shim_fd_handle** fdhdl, FDTYPE fd, struct shim_handle* hdl,
                         int fd_flags) {
    struct shim_fd_handle* new_handle = *fdhdl;
    assert((fd_flags & ~FD_CLOEXEC) == 0);  // The only supported flag right now

    if (!new_handle) {
        new_handle = malloc(sizeof(struct shim_fd_handle));
        if (!new_handle)
            return -ENOMEM;
        *fdhdl = new_handle;
    }

    new_handle->vfd   = fd;
    new_handle->flags = fd_flags;
    get_handle(hdl);
    new_handle->handle = hdl;
    return 0;
}

/*
 * Helper function for set_new_fd_handle*(). If find_free is true, tries to find the first free fd
 * (starting from the provided one), otherwise, tries to use fd as-is.
 */
static int __set_new_fd_handle(FDTYPE fd, struct shim_handle* hdl, int fd_flags,
                               struct shim_handle_map* handle_map, bool find_free) {
    int ret;

    if (!handle_map && !(handle_map = get_thread_handle_map(NULL)))
        return -EBADF;

    lock(&handle_map->lock);

    if (handle_map->fd_top != FD_NULL) {
        assert(handle_map->map);
        if (find_free) {
            // find first free fd
            while (fd <= handle_map->fd_top && HANDLE_ALLOCATED(handle_map->map[fd])) {
                fd++;
            }
        } else {
            // check if requested fd is occupied
            if (fd <= handle_map->fd_top && HANDLE_ALLOCATED(handle_map->map[fd])) {
                ret = -EBADF;
                goto out;
            }
        }
    }

    if (fd >= get_rlimit_cur(RLIMIT_NOFILE)) {
        ret = -EMFILE;
        goto out;
    }

    // Enlarge handle_map->map (or allocate if necessary)
    if (fd >= handle_map->fd_size) {
        size_t new_size = handle_map->fd_size;
        if (new_size == 0)
            new_size = INIT_HANDLE_MAP_SIZE;
        while (new_size <= fd)
            new_size *= 2;

        ret = __enlarge_handle_map(handle_map, new_size);
        if (ret < 0)
            goto out;
    }

    assert(handle_map->map);
    assert(fd < handle_map->fd_size);
    ret = __init_handle(&handle_map->map[fd], fd, hdl, fd_flags);
    if (ret < 0)
        goto out;

    if (handle_map->fd_top == FD_NULL || fd > handle_map->fd_top)
        handle_map->fd_top = fd;

    ret = fd;

out:
    unlock(&handle_map->lock);
    return ret;
}

int set_new_fd_handle(struct shim_handle* hdl, int fd_flags, struct shim_handle_map* handle_map) {
    return __set_new_fd_handle(0, hdl, fd_flags, handle_map, /*find_first=*/true);
}

int set_new_fd_handle_by_fd(FDTYPE fd, struct shim_handle* hdl, int fd_flags,
                            struct shim_handle_map* handle_map) {
    return __set_new_fd_handle(fd, hdl, fd_flags, handle_map, /*find_first=*/false);
}

int set_new_fd_handle_above_fd(FDTYPE fd, struct shim_handle* hdl, int fd_flags,
                               struct shim_handle_map* handle_map) {
    return __set_new_fd_handle(fd, hdl, fd_flags, handle_map, /*find_first=*/true);
}

static inline __attribute__((unused)) const char* __handle_name(struct shim_handle* hdl) {
    if (!qstrempty(&hdl->path))
        return qstrgetstr(&hdl->path);
    if (!qstrempty(&hdl->uri))
        return qstrgetstr(&hdl->uri);
    if (hdl->fs_type[0])
        return hdl->fs_type;
    return "(unknown)";
}

void get_handle(struct shim_handle* hdl) {
#ifdef DEBUG_REF
    int ref_count = REF_INC(hdl->ref_count);

    debug("get handle %p(%s) (ref_count = %d)\n", hdl, __handle_name(hdl), ref_count);
#else
    REF_INC(hdl->ref_count);
#endif
}

static void destroy_handle(struct shim_handle* hdl) {
    destroy_lock(&hdl->lock);

    free_mem_obj_to_mgr(handle_mgr, hdl);
}

void put_handle(struct shim_handle* hdl) {
    int ref_count = REF_DEC(hdl->ref_count);

#ifdef DEBUG_REF
    debug("put handle %p(%s) (ref_count = %d)\n", hdl, __handle_name(hdl), ref_count);
#endif

    if (!ref_count) {
        delete_from_epoll_handles(hdl);

        if (hdl->type == TYPE_DIR) {
            struct shim_dir_handle* dir = &hdl->dir_info;

            if (dir->dot) {
                put_dentry(dir->dot);
                dir->dot = NULL;
            }

            if (dir->dotdot) {
                put_dentry(dir->dotdot);
                dir->dotdot = NULL;
            }

            if (dir->ptr != (void*)-1) {
                while (dir->ptr && *dir->ptr) {
                    struct shim_dentry* dent = *dir->ptr;
                    put_dentry(dent);
                    *(dir->ptr++) = NULL;
                }
            }
        } else {
            if (hdl->fs && hdl->fs->fs_ops && hdl->fs->fs_ops->close)
                hdl->fs->fs_ops->close(hdl);

            if (hdl->type == TYPE_SOCK && hdl->info.sock.peek_buffer) {
                free(hdl->info.sock.peek_buffer);
                hdl->info.sock.peek_buffer = NULL;
            }
        }

        if (hdl->fs && hdl->fs->fs_ops && hdl->fs->fs_ops->hput)
            hdl->fs->fs_ops->hput(hdl);

        qstrfree(&hdl->path);
        qstrfree(&hdl->uri);

        if (hdl->pal_handle) {
#ifdef DEBUG_REF
            debug("handle %p closes PAL handle %p\n", hdl, hdl->pal_handle);
#endif
            DkObjectClose(hdl->pal_handle);
            hdl->pal_handle = NULL;
        }

        if (hdl->dentry)
            put_dentry_maybe_delete(hdl->dentry);

        if (hdl->fs)
            put_mount(hdl->fs);

        destroy_handle(hdl);
    }
}

off_t get_file_size(struct shim_handle* hdl) {
    if (!hdl->fs || !hdl->fs->fs_ops)
        return -EINVAL;

    if (hdl->fs->fs_ops->poll)
        return hdl->fs->fs_ops->poll(hdl, FS_POLL_SZ);

    if (hdl->fs->fs_ops->hstat) {
        struct stat stat;
        int ret = hdl->fs->fs_ops->hstat(hdl, &stat);
        if (ret < 0)
            return ret;
        return stat.st_size;
    }

    return 0;
}

static struct shim_handle_map* get_new_handle_map(FDTYPE size) {
    struct shim_handle_map* handle_map = calloc(1, sizeof(struct shim_handle_map));

    if (!handle_map)
        return NULL;

    handle_map->map = calloc(size, sizeof(*handle_map->map));

    if (!handle_map->map) {
        free(handle_map);
        return NULL;
    }

    handle_map->fd_top  = FD_NULL;
    handle_map->fd_size = size;
    if (!create_lock(&handle_map->lock)) {
        free(handle_map->map);
        free(handle_map);
        return NULL;
    }

    REF_SET(handle_map->ref_count, 1);

    return handle_map;
}

static int __enlarge_handle_map(struct shim_handle_map* map, size_t size) {
    assert(locked(&map->lock));

    if (size <= map->fd_size)
        return 0;

    struct shim_fd_handle** new_map = calloc(size, sizeof(new_map[0]));
    if (!new_map)
        return -ENOMEM;

    memcpy(new_map, map->map, map->fd_size * sizeof(new_map[0]));
    free(map->map);
    map->map     = new_map;
    map->fd_size = size;
    return 0;
}

int dup_handle_map(struct shim_handle_map** new, struct shim_handle_map* old_map) {
    lock(&old_map->lock);

    /* allocate a new handle mapping with the same size as
       the old one */
    struct shim_handle_map* new_map = get_new_handle_map(old_map->fd_size);

    if (!new_map)
        return -ENOMEM;

    new_map->fd_top = old_map->fd_top;

    if (old_map->fd_top == FD_NULL)
        goto done;

    for (int i = 0; i <= old_map->fd_top; i++) {
        struct shim_fd_handle* fd_old = old_map->map[i];
        struct shim_fd_handle* fd_new;

        /* now we go through the handle map and reassign each
           of them being allocated */
        if (HANDLE_ALLOCATED(fd_old)) {
            /* first, get the handle to prevent it from being deleted */
            struct shim_handle* hdl = fd_old->handle;
            get_handle(hdl);

            fd_new = malloc(sizeof(struct shim_fd_handle));
            if (!fd_new) {
                for (int j = 0; j < i; j++) {
                    put_handle(new_map->map[j]->handle);
                    free(new_map->map[j]);
                }
                unlock(&old_map->lock);
                *new = NULL;
                free(new_map);
                return -ENOMEM;
            }

            /* DP: I assume we really need a deep copy of the handle map? */
            new_map->map[i] = fd_new;
            fd_new->vfd     = fd_old->vfd;
            fd_new->handle  = hdl;
            fd_new->flags   = fd_old->flags;
        }
    }

done:
    unlock(&old_map->lock);
    *new = new_map;
    return 0;
}

void get_handle_map(struct shim_handle_map* map) {
    REF_INC(map->ref_count);
}

void put_handle_map(struct shim_handle_map* map) {
    int ref_count = REF_DEC(map->ref_count);

    if (!ref_count) {
        if (map->fd_top == FD_NULL)
            goto done;

        for (int i = 0; i <= map->fd_top; i++) {
            if (!map->map[i])
                continue;

            if (map->map[i]->vfd != FD_NULL) {
                struct shim_handle* handle = map->map[i]->handle;

                if (handle)
                    put_handle(handle);
            }

            free(map->map[i]);
        }

    done:
        destroy_lock(&map->lock);
        free(map->map);
        free(map);
    }
}

int walk_handle_map(int (*callback)(struct shim_fd_handle*, struct shim_handle_map*),
                    struct shim_handle_map* map) {
    int ret = 0;
    lock(&map->lock);

    if (map->fd_top == FD_NULL)
        goto done;

    for (int i = 0; i <= map->fd_top; i++) {
        if (!HANDLE_ALLOCATED(map->map[i]))
            continue;

        if ((ret = (*callback)(map->map[i], map)) < 0)
            break;
    }

done:
    unlock(&map->lock);
    return ret;
}

BEGIN_CP_FUNC(handle) {
    __UNUSED(size);
    assert(size == sizeof(struct shim_handle));

    struct shim_handle* hdl     = (struct shim_handle*)obj;
    struct shim_handle* new_hdl = NULL;

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct shim_handle));
        ADD_TO_CP_MAP(obj, off);
        new_hdl = (struct shim_handle*)(base + off);

        lock(&hdl->lock);
        struct shim_mount* fs = hdl->fs;
        *new_hdl              = *hdl;

        if (fs && fs->fs_ops && fs->fs_ops->checkout)
            fs->fs_ops->checkout(new_hdl);

        new_hdl->dentry = NULL;
        REF_SET(new_hdl->ref_count, 0);
        clear_lock(&new_hdl->lock);

        DO_CP_IN_MEMBER(qstr, new_hdl, path);
        DO_CP_IN_MEMBER(qstr, new_hdl, uri);

        if (fs && fs != &fifo_builtin_fs && hdl->dentry) {
            DO_CP_MEMBER(mount, hdl, new_hdl, fs);
        } else {
            new_hdl->fs = NULL;
        }

        if (hdl->dentry) {
            if (hdl->dentry->state & DENTRY_ISDIRECTORY) {
                /* we don't checkpoint children dentries of a directory dentry, so need to list
                 * directory again in child process; mark handle to indicate no cached dentries */
                hdl->dir_info.buf = (void*)-1;
                hdl->dir_info.ptr = (void*)-1;
            }
            DO_CP_MEMBER(dentry, hdl, new_hdl, dentry);
        }

        if (new_hdl->pal_handle) {
            struct shim_palhdl_entry* entry;
            DO_CP(palhdl, hdl->pal_handle, &entry);
            entry->uri     = &new_hdl->uri;
            entry->phandle = &new_hdl->pal_handle;
        }

        INIT_LISTP(&new_hdl->epolls);

        switch (hdl->type) {
            case TYPE_EPOLL:
                /* `new_hdl->info.epoll.fds_count` stays the same - copied above. */
                DO_CP(epoll_item, &hdl->info.epoll.fds, &new_hdl->info.epoll.fds);
                __atomic_store_n(&new_hdl->info.epoll.waiter_cnt, 0, __ATOMIC_RELAXED);
                memset(&new_hdl->info.epoll.event, '\0', sizeof(new_hdl->info.epoll.event));
                break;
            case TYPE_SOCK:
                /* no support for multiple processes sharing options/peek buffer of the socket */
                new_hdl->info.sock.pending_options = NULL;
                new_hdl->info.sock.peek_buffer     = NULL;
                break;
            default:
                break;
        }

        unlock(&hdl->lock);
        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_hdl = (struct shim_handle*)(base + off);
    }

    if (objp)
        *objp = (void*)new_hdl;
}
END_CP_FUNC(handle)

BEGIN_RS_FUNC(handle) {
    struct shim_handle* hdl = (void*)(base + GET_CP_FUNC_ENTRY());
    __UNUSED(offset);

    CP_REBASE(hdl->fs);
    CP_REBASE(hdl->dentry);
    CP_REBASE(hdl->epolls);

    if (!create_lock(&hdl->lock)) {
        return -ENOMEM;
    }

    if (!hdl->fs) {
        assert(hdl->fs_type);
        search_builtin_fs(hdl->fs_type, &hdl->fs);
        if (!hdl->fs) {
            destroy_lock(&hdl->lock);
            return -EINVAL;
        }
    } else {
        get_mount(hdl->fs);
    }

    if (hdl->dentry) {
        get_dentry(hdl->dentry);
    }

    switch (hdl->type) {
        case TYPE_DEV:
            /* for device handles, info.dev.dev_ops contains function pointers into LibOS; they may
             * have become invalid due to relocation of LibOS text section in the child, update them
             */
            if (dev_update_dev_ops(hdl) < 0) {
                return -EINVAL;
            }
            break;
        case TYPE_EPOLL: ;
            int ret = create_event(&hdl->info.epoll.event);
            if (ret < 0) {
                return ret;
            }

            struct shim_epoll_item* epoll_item;
            size_t count = 0;
            LISTP_FOR_EACH_ENTRY(epoll_item, &hdl->info.epoll.fds, list) {
                epoll_item->epoll = hdl;
                count++;
            }
            assert(hdl->info.epoll.fds_count == count);
            break;
        default:
            break;
    }

    if (hdl->fs && hdl->fs->fs_ops && hdl->fs->fs_ops->checkin)
        hdl->fs->fs_ops->checkin(hdl);

    DEBUG_RS("path=%s,type=%s,uri=%s,flags=%03o", qstrgetstr(&hdl->path), hdl->fs_type,
             qstrgetstr(&hdl->uri), hdl->flags);
}
END_RS_FUNC(handle)

BEGIN_CP_FUNC(fd_handle) {
    __UNUSED(size);
    assert(size == sizeof(struct shim_fd_handle));

    struct shim_fd_handle* fdhdl     = (struct shim_fd_handle*)obj;
    struct shim_fd_handle* new_fdhdl = NULL;

    size_t off = ADD_CP_OFFSET(sizeof(struct shim_fd_handle));
    new_fdhdl = (struct shim_fd_handle*)(base + off);
    *new_fdhdl = *fdhdl;
    DO_CP(handle, fdhdl->handle, &new_fdhdl->handle);
    ADD_CP_FUNC_ENTRY(off);

    if (objp)
        *objp = (void*)new_fdhdl;
}
END_CP_FUNC_NO_RS(fd_handle)

BEGIN_CP_FUNC(handle_map) {
    __UNUSED(size);
    assert(size >= sizeof(struct shim_handle_map));

    struct shim_handle_map* handle_map     = (struct shim_handle_map*)obj;
    struct shim_handle_map* new_handle_map = NULL;
    struct shim_fd_handle** ptr_array;

    lock(&handle_map->lock);

    int fd_size = handle_map->fd_top != FD_NULL ? handle_map->fd_top + 1 : 0;

    size = sizeof(struct shim_handle_map) + (sizeof(struct shim_fd_handle*) * fd_size);

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off            = ADD_CP_OFFSET(size);
        new_handle_map = (struct shim_handle_map*)(base + off);

        *new_handle_map = *handle_map;

        ptr_array = (void*)new_handle_map + sizeof(struct shim_handle_map);

        new_handle_map->fd_size = fd_size;
        new_handle_map->map     = fd_size ? ptr_array : NULL;

        REF_SET(new_handle_map->ref_count, 0);
        clear_lock(&new_handle_map->lock);

        for (int i = 0; i < fd_size; i++) {
            if (HANDLE_ALLOCATED(handle_map->map[i]))
                DO_CP(fd_handle, handle_map->map[i], &ptr_array[i]);
            else
                ptr_array[i] = NULL;
        }

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_handle_map = (struct shim_handle_map*)(base + off);
    }

    unlock(&handle_map->lock);

    if (objp)
        *objp = (void*)new_handle_map;
}
END_CP_FUNC(handle_map)

BEGIN_RS_FUNC(handle_map) {
    struct shim_handle_map* handle_map = (void*)(base + GET_CP_FUNC_ENTRY());
    __UNUSED(offset);

    CP_REBASE(handle_map->map);
    assert(handle_map->map);

    DEBUG_RS("size=%d,top=%d", handle_map->fd_size, handle_map->fd_top);

    if (!create_lock(&handle_map->lock)) {
        return -ENOMEM;
    }
    lock(&handle_map->lock);

    if (handle_map->fd_top != FD_NULL)
        for (int i = 0; i <= handle_map->fd_top; i++) {
            CP_REBASE(handle_map->map[i]);
            if (HANDLE_ALLOCATED(handle_map->map[i])) {
                CP_REBASE(handle_map->map[i]->handle);
                struct shim_handle* hdl = handle_map->map[i]->handle;
                assert(hdl);
                get_handle(hdl);
                DEBUG_RS("[%d]%s", i, qstrempty(&hdl->uri) ? hdl->fs_type : qstrgetstr(&hdl->uri));
            }
        }

    unlock(&handle_map->lock);
}
END_RS_FUNC(handle_map)
