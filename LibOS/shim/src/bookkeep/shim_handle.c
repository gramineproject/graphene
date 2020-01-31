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
 * shim_handle.c
 *
 * This file contains codes to maintain bookkeeping for handles in library OS.
 */

#include <pal.h>
#include <pal_error.h>
#include <shim_checkpoint.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_thread.h>

static struct shim_lock handle_mgr_lock;

#define HANDLE_MGR_ALLOC 32

#define SYSTEM_LOCK()   lock(&handle_mgr_lock)
#define SYSTEM_UNLOCK() unlock(&handle_mgr_lock)
#define SYSTEM_LOCKED() locked(&handle_mgr_lock)

#define OBJ_TYPE struct shim_handle
#include <memmgr.h>

static MEM_MGR handle_mgr = NULL;

#define INIT_HANDLE_MAP_SIZE 32

//#define DEBUG_REF

static inline int init_tty_handle(struct shim_handle* hdl, bool write) {
    struct shim_dentry* dent = NULL;
    int ret;
    struct shim_thread* cur_thread = get_cur_thread();
    __UNUSED(cur_thread);

    /* XXX: Try getting the root FS from current thread? */
    assert(cur_thread);
    assert(cur_thread->root);
    if ((ret = path_lookupat(NULL, "/dev/tty", LOOKUP_OPEN, &dent, NULL)) < 0)
        return ret;

    int flags             = (write ? O_WRONLY : O_RDONLY) | O_APPEND;
    struct shim_mount* fs = dent->fs;
    ret                   = fs->d_ops->open(hdl, dent, flags);
    if (ret < 0)
        return ret;

    set_handle_fs(hdl, fs);
    hdl->dentry = dent;
    hdl->flags  = O_RDWR | O_APPEND | 0100000;

    size_t size;
    char* path = dentry_get_path(dent, true, &size);
    if (path)
        qstrsetstr(&hdl->path, path, size);
    else
        qstrsetstr(&hdl->path, "/dev/tty", 8);

    return 0;
}

static inline int init_exec_handle(struct shim_thread* thread) {
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
        if (exec->dentry) {
            size_t len;
            const char* path = dentry_get_path(exec->dentry, true, &len);
            qstrsetstr(&exec->path, path, len);
        }
        put_mount(fs);
    } else {
        set_handle_fs(exec, &chroot_builtin_fs);
    }

    lock(&thread->lock);
    thread->exec = exec;
    unlock(&thread->lock);

    return 0;
}

static struct shim_handle_map* get_new_handle_map(FDTYPE size);

PAL_HANDLE shim_stdio = NULL;

static int __set_new_fd_handle(struct shim_fd_handle** fdhdl, FDTYPE fd, struct shim_handle* hdl,
                               int flags);

static struct shim_handle_map* __enlarge_handle_map(struct shim_handle_map* map, FDTYPE size);

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
    struct shim_thread* thread = get_cur_thread();

    if (thread->handle_map)
        goto done;

    struct shim_handle_map* handle_map = get_cur_handle_map(thread);

    if (!handle_map) {
        handle_map = get_new_handle_map(INIT_HANDLE_MAP_SIZE);
        if (!handle_map)
            return -ENOMEM;

        set_handle_map(thread, handle_map);
    }

    lock(&handle_map->lock);

    if (handle_map->fd_size < 3) {
        if (!__enlarge_handle_map(handle_map, INIT_HANDLE_MAP_SIZE)) {
            unlock(&handle_map->lock);
            return -ENOMEM;
        }
    }

    struct shim_handle* hdl = NULL;
    int ret;

    for (int fd = 0; fd < 3; fd++)
        if (!HANDLE_ALLOCATED(handle_map->map[fd])) {
            if (!hdl) {
                hdl = get_new_handle();
                if (!hdl)
                    return -ENOMEM;

                if ((ret = init_tty_handle(hdl, fd)) < 0) {
                    put_handle(hdl);
                    return ret;
                }
            } else {
                get_handle(hdl);
            }

            __set_new_fd_handle(&handle_map->map[fd], fd, hdl, 0);
            put_handle(hdl);
            if (fd != 1)
                hdl = NULL;
        } else {
            if (fd == 1)
                hdl = handle_map->map[fd]->handle;
        }

    if (handle_map->fd_top == FD_NULL || handle_map->fd_top < 2)
        handle_map->fd_top = 2;

    unlock(&handle_map->lock);

done:
    init_exec_handle(thread);
    return 0;
}

struct shim_handle* __get_fd_handle(FDTYPE fd, int* flags, struct shim_handle_map* map) {
    assert(locked(&map->lock));

    struct shim_fd_handle* fd_handle = NULL;

    if (map->fd_top != FD_NULL && fd <= map->fd_top) {
        fd_handle = map->map[fd];
        if (!HANDLE_ALLOCATED(fd_handle))
            return NULL;

        if (flags)
            *flags = fd_handle->flags;

        return fd_handle->handle;
    }
    return NULL;
}

struct shim_handle* get_fd_handle(FDTYPE fd, int* flags, struct shim_handle_map* map) {
    if (!map)
        map = get_cur_handle_map(NULL);

    struct shim_handle* hdl = NULL;
    lock(&map->lock);
    if ((hdl = __get_fd_handle(fd, flags, map)))
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

    if (!handle_map && !(handle_map = get_cur_handle_map(NULL)))
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
    new_handle->owner = cur_process.vmid;
    INIT_LISTP(&new_handle->epolls);
    return new_handle;
}

static int __set_new_fd_handle(struct shim_fd_handle** fdhdl, FDTYPE fd, struct shim_handle* hdl,
                               int flags) {
    struct shim_fd_handle* new_handle = *fdhdl;

    if (!new_handle) {
        new_handle = malloc(sizeof(struct shim_fd_handle));
        if (!new_handle)
            return -ENOMEM;
        *fdhdl = new_handle;
    }

    new_handle->vfd   = fd;
    new_handle->flags = flags;
    get_handle(hdl);
    new_handle->handle = hdl;
    return 0;
}

int set_new_fd_handle(struct shim_handle* hdl, int flags, struct shim_handle_map* handle_map) {
    int ret = -EMFILE;

    if (!handle_map && !(handle_map = get_cur_handle_map(NULL)))
        return -EBADF;

    lock(&handle_map->lock);

    FDTYPE fd = 0;
    if (handle_map->fd_top != FD_NULL) {
        // find first free fd
        while (fd <= handle_map->fd_top && HANDLE_ALLOCATED(handle_map->map[fd])) {
            fd++;
        }

        if (fd > handle_map->fd_top) {
            // no free fd found (fd == handle_map->fd_top + 1)

            if (fd >= handle_map->fd_size) {
                // no space left, need to enlarge handle_map->map
                if (!__enlarge_handle_map(handle_map, handle_map->fd_size * 2)) {
                    ret = -ENOMEM;
                    goto out;
                }
            }
        }
    } else {
        fd = 0;
    }

    if ((ret = __set_new_fd_handle(&handle_map->map[fd], fd, hdl, flags)) < 0) {
        goto out;
    }

    ret = fd;

    if (handle_map->fd_top == FD_NULL || fd > handle_map->fd_top) {
        handle_map->fd_top = fd;
    }

out:
    unlock(&handle_map->lock);
    return ret;
}

int set_new_fd_handle_by_fd(FDTYPE fd, struct shim_handle* hdl, int flags,
                            struct shim_handle_map* handle_map) {
    int new_size = 0;
    int ret      = 0;

    if (!handle_map && !(handle_map = get_cur_handle_map(NULL)))
        return -EBADF;

    lock(&handle_map->lock);

    if (!handle_map->map || handle_map->fd_size < INIT_HANDLE_MAP_SIZE)
        new_size = INIT_HANDLE_MAP_SIZE;

    if (!handle_map->map)
        goto extend;

    if (fd >= handle_map->fd_size) {
        new_size = handle_map->fd_size < new_size ? new_size : handle_map->fd_size;
    extend:
        while (new_size <= fd) new_size *= 2;

        if (!__enlarge_handle_map(handle_map, new_size)) {
            ret = -ENOMEM;
            goto out;
        }
    }

    if (handle_map->fd_top != FD_NULL && fd <= handle_map->fd_top &&
        HANDLE_ALLOCATED(handle_map->map[fd])) {
        ret = -EBADF;
        goto out;
    }

    if (handle_map->fd_top == FD_NULL || fd > handle_map->fd_top)
        handle_map->fd_top = fd;

    struct shim_fd_handle* new_handle = handle_map->map[fd];

    if (!new_handle) {
        new_handle = malloc(sizeof(struct shim_fd_handle));
        if (!new_handle) {
            ret = -ENOMEM;
            goto out;
        }
        handle_map->map[fd] = new_handle;
    }

    ret = __set_new_fd_handle(&handle_map->map[fd], fd, hdl, flags);
    if (ret < 0) {
        if (fd == handle_map->fd_top)
            handle_map->fd_top = fd ? fd - 1 : FD_NULL;
    } else {
        ret = fd;
    }
out:
    unlock(&handle_map->lock);
    return ret;
}

void flush_handle(struct shim_handle* hdl) {
    if (hdl->fs && hdl->fs->fs_ops && hdl->fs->fs_ops->flush)
        hdl->fs->fs_ops->flush(hdl);
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

    if (memory_migrated(hdl))
        memset(hdl, 0, sizeof(struct shim_handle));
    else
        free_mem_obj_to_mgr(handle_mgr, hdl);
}

void put_handle(struct shim_handle* hdl) {
    int ref_count = REF_DEC(hdl->ref_count);

#ifdef DEBUG_REF
    debug("put handle %p(%s) (ref_count = %d)\n", hdl, __handle_name(hdl), ref_count);
#endif

    if (!ref_count) {
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

        delete_from_epoll_handles(hdl);

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
            put_dentry(hdl->dentry);

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

void dup_fd_handle(struct shim_handle_map* map, const struct shim_fd_handle* old,
                   struct shim_fd_handle* new) {
    struct shim_handle* replaced = NULL;

    lock(&map->lock);

    if (old->vfd != FD_NULL) {
        get_handle(old->handle);
        replaced    = new->handle;
        new->handle = old->handle;
    }

    unlock(&map->lock);

    if (replaced)
        put_handle(replaced);
}

static struct shim_handle_map* get_new_handle_map(FDTYPE size) {
    struct shim_handle_map* handle_map = calloc(1, sizeof(struct shim_handle_map));

    if (!handle_map)
        return NULL;

    handle_map->map = calloc(size, sizeof(struct shim_fd_handle));

    if (!handle_map->map) {
        free(handle_map);
        return NULL;
    }

    handle_map->fd_top  = FD_NULL;
    handle_map->fd_size = size;
    if (!create_lock(&handle_map->lock)) {
        free(handle_map);
        return NULL;
    }

    return handle_map;
}

static struct shim_handle_map* __enlarge_handle_map(struct shim_handle_map* map, FDTYPE size) {
    assert(locked(&map->lock));

    if (size <= map->fd_size)
        return map;

    struct shim_fd_handle** new_map = calloc(size, sizeof(new_map[0]));

    if (!new_map)
        return NULL;

    memcpy(new_map, map->map, map->fd_size * sizeof(new_map[0]));
    free(map->map);
    map->map     = new_map;
    map->fd_size = size;
    return map;
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

int flush_handle_map(struct shim_handle_map* map) {
    get_handle_map(map);
    lock(&map->lock);

    if (map->fd_top == FD_NULL)
        goto done;

    /* now we go through the handle map and flush each handle */
    for (int i = 0; i <= map->fd_top; i++) {
        if (!HANDLE_ALLOCATED(map->map[i]))
            continue;

        struct shim_handle* handle = map->map[i]->handle;

        if (handle)
            flush_handle(handle);
    }

done:
    unlock(&map->lock);
    put_handle_map(map);
    return 0;
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

    ptr_t off = GET_FROM_CP_MAP(obj);

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

        if (fs && hdl->dentry) {
            DO_CP_MEMBER(mount, hdl, new_hdl, fs);
        } else {
            new_hdl->fs = NULL;
        }

        if (hdl->dentry)
            DO_CP_MEMBER(dentry, hdl, new_hdl, dentry);

        if (new_hdl->pal_handle) {
            struct shim_palhdl_entry* entry;
            DO_CP(palhdl, hdl->pal_handle, &entry);
            entry->uri     = &new_hdl->uri;
            entry->phandle = &new_hdl->pal_handle;
        }

        if (hdl->type == TYPE_EPOLL)
            DO_CP(epoll_item, &hdl->info.epoll.fds, &new_hdl->info.epoll.fds);

        if (hdl->type == TYPE_SOCK) {
            /* no support for multiple processes sharing options/peek buffer of the socket */
            new_hdl->info.sock.pending_options = NULL;
            new_hdl->info.sock.peek_buffer     = NULL;
        }

        INIT_LISTP(&new_hdl->epolls);

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
    }

    if (hdl->type == TYPE_DEV) {
        /* for device handles, info.dev.dev_ops contains function pointers into LibOS; they may
           have become invalid due to relocation of LibOS text section in the child, update them */
        if (dev_update_dev_ops(hdl) < 0) {
            return -EINVAL;
        }
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

    ptr_t off = ADD_CP_OFFSET(sizeof(struct shim_fd_handle));
    new_fdhdl = (struct shim_fd_handle*)(base + off);
    memcpy(new_fdhdl, fdhdl, sizeof(struct shim_fd_handle));
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

    ptr_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off            = ADD_CP_OFFSET(size);
        new_handle_map = (struct shim_handle_map*)(base + off);

        memcpy(new_handle_map, handle_map, sizeof(struct shim_handle_map));

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
