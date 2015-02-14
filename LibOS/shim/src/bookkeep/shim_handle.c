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
 * shim_handle.c
 *
 * This file contains codes to maintain bookkeeping for handles in library OS.
 */

#include <shim_internal.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_checkpoint.h>
#include <shim_fs.h>

#include <pal.h>
#include <pal_error.h>

#include <fcntl.h>

static LOCKTYPE handle_mgr_lock;

#define HANDLE_MGR_ALLOC        32

#define system_lock()   lock(handle_mgr_lock)
#define system_unlock() unlock(handle_mgr_lock)
#define PAGE_SIZE       allocsize

#define OBJ_TYPE struct shim_handle
#include <memmgr.h>

static MEM_MGR handle_mgr = NULL;

#define INIT_HANDLE_MAP_SIZE    32

//#define DEBUG_REF

static inline int init_tty_handle (struct shim_handle * hdl, bool write)
{
    struct shim_dentry * dent = NULL;
    int ret;

    if ((ret = path_lookupat(NULL, "/dev/tty", LOOKUP_OPEN, &dent)) < 0)
        return ret;

    int flags = (write ? O_WRONLY : O_RDONLY)|O_APPEND;
    struct shim_mount * fs = dent->fs;
    ret = fs->d_ops->open(hdl, dent, flags);
    if (ret < 0)
        return ret;

    set_handle_fs(hdl, fs);
    hdl->dentry = dent;
    hdl->flags = O_RDWR|O_APPEND|0100000;

    int size;
    char * path = dentry_get_path(dent, true, &size);
    if (path)
        qstrsetstr(&hdl->path, path, size);
    else
        qstrsetstr(&hdl->path, "/dev/tty", 8);

    return 0;
}

static inline int init_exec_handle (struct shim_thread * thread)
{
    if (!PAL_CB(executable))
        return 0;

    struct shim_handle * exec = get_new_handle();
    if (!exec)
        return -ENOMEM;

    set_handle_fs(exec, &chroot_builtin_fs);
    qstrsetstr(&exec->uri, PAL_CB(executable), strlen(PAL_CB(executable)));
    exec->type     = TYPE_FILE;
    exec->flags    = O_RDONLY;
    exec->acc_mode = MAY_READ;

    lock(thread->lock);
    thread->exec = exec;
    unlock(thread->lock);

    return 0;
}

static struct shim_handle_map * get_new_handle_map (FDTYPE size);

PAL_HANDLE shim_stdio = NULL;

static int __set_new_fd_handle(struct shim_fd_handle ** fdhdl, FDTYPE fd,
                               struct shim_handle * hdl, int flags);

static struct shim_handle_map * __enlarge_handle_map
                     (struct shim_handle_map * map, FDTYPE size);

int init_handle (void)
{
    create_lock(handle_mgr_lock);
    handle_mgr = create_mem_mgr(init_align_up(HANDLE_MGR_ALLOC));
    if (!handle_mgr)
        return -ENOMEM;
    return 0;
}

int init_important_handles (void)
{
    struct shim_thread * thread = get_cur_thread();

    if (thread->handle_map)
        goto done;

    struct shim_handle_map * handle_map = get_cur_handle_map(thread);

    if (!handle_map) {
        handle_map = get_new_handle_map(INIT_HANDLE_MAP_SIZE);
        if (!handle_map)
            return -ENOMEM;

        set_handle_map(thread, handle_map);
    }

    lock(handle_map->lock);

    if (handle_map->fd_size < 3) {
        if (!__enlarge_handle_map(handle_map, INIT_HANDLE_MAP_SIZE)) {
            unlock(handle_map->lock);
            return -ENOMEM;
        }
    }

    struct shim_handle * hdl = NULL;
    int ret;

    for (int fd = 0 ; fd < 3 ; fd++)
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

    unlock(handle_map->lock);

done:
    init_exec_handle(thread);
    return 0;
}

struct shim_handle * __get_fd_handle (FDTYPE fd, int * flags,
                                      struct shim_handle_map * map)
{
    struct shim_fd_handle * fd_handle = NULL;

    if (map->fd_top != FD_NULL &&
        fd <= map->fd_top) {
        fd_handle = map->map[fd];
        if (!HANDLE_ALLOCATED(fd_handle))
            return NULL;

        if (flags)
            *flags = fd_handle->flags;

        return fd_handle->handle;
    }
    return NULL;
}

struct shim_handle * get_fd_handle (FDTYPE fd, int * flags,
                                    struct shim_handle_map * map)
{
    if (!map)
        map = get_cur_handle_map(NULL);

    struct shim_handle * hdl = NULL;
    lock(map->lock);
    if ((hdl = __get_fd_handle(fd, flags, map)))
        get_handle(hdl);
    unlock(map->lock);
    return hdl;
}

struct shim_handle *
__detach_fd_handle (struct shim_fd_handle * fd, int * flags,
                    struct shim_handle_map * map)
{
    struct shim_handle * handle = NULL;

    if (HANDLE_ALLOCATED(fd)) {
        int vfd = fd->vfd;
        handle = fd->handle;
        if (flags)
            *flags = fd->flags;

        fd->vfd = FD_NULL;
        fd->handle = NULL;
        fd->flags = 0;

        if (vfd == map->fd_top)
            do {
                map->fd_top = vfd ? vfd - 1 : FD_NULL;
                vfd--;
            } while (vfd >= 0 &&
                     !HANDLE_ALLOCATED(map->map[vfd]));
    }

    return handle;
}

struct shim_handle * detach_fd_handle (FDTYPE fd, int * flags,
                                       struct shim_handle_map * handle_map)
{
    struct shim_handle * handle = NULL;

    if (!handle_map && !(handle_map = get_cur_handle_map(NULL)))
        return NULL;

    lock(handle_map->lock);

    if (fd < handle_map->fd_size)
        handle = __detach_fd_handle(handle_map->map[fd], flags,
                                    handle_map);

    unlock(handle_map->lock);
    return handle;
}

struct shim_handle * get_new_handle (void)
{
    struct shim_handle * new_handle =
                get_mem_obj_from_mgr_enlarge(handle_mgr,
                                             size_align_up(HANDLE_MGR_ALLOC));
    if (!new_handle)
        return NULL;

    memset(new_handle, 0, sizeof(struct shim_handle));
    REF_SET(new_handle->ref_count, 1);
    create_lock(new_handle->lock);
    new_handle->owner = cur_process.vmid;
    return new_handle;
}

static int __set_new_fd_handle(struct shim_fd_handle ** fdhdl, FDTYPE fd,
                               struct shim_handle * hdl, int flags)
{
    struct shim_fd_handle * new_handle = *fdhdl;

    if (!new_handle) {
        new_handle = malloc(sizeof(struct shim_fd_handle));
        if (!new_handle)
            return -ENOMEM;
        *fdhdl = new_handle;
    }

    new_handle->vfd    = fd;
    new_handle->flags  = flags;
    open_handle(hdl);
    new_handle->handle = hdl;
    return 0;
}

int set_new_fd_handle (struct shim_handle * hdl, int flags,
                       struct shim_handle_map * handle_map)
{
    FDTYPE fd = 0;
    int new_size = 0;
    int ret = 0;

    if (!handle_map && !(handle_map = get_cur_handle_map(NULL)))
        return -EBADF;

    lock(handle_map->lock);

    if (!handle_map->map ||
        handle_map->fd_size < INIT_HANDLE_MAP_SIZE)
        new_size = INIT_HANDLE_MAP_SIZE;

    if (!handle_map->map)
        goto extend;

    if (handle_map->fd_top != FD_NULL)
        do {
            ++fd;
            if (fd == handle_map->fd_size) {
                new_size = handle_map->fd_size < new_size ? new_size :
                           handle_map->fd_size * 2;
extend:
                if (!__enlarge_handle_map(handle_map, new_size)) {
                    ret = -ENOMEM;
                    goto out;
                }
            }
        } while (handle_map->fd_top != FD_NULL &&
                 fd <= handle_map->fd_top &&
                 HANDLE_ALLOCATED(handle_map->map[fd]));

    if (handle_map->fd_top == FD_NULL ||
        fd > handle_map->fd_top)
        handle_map->fd_top = fd;

    ret = __set_new_fd_handle(&handle_map->map[fd], fd, hdl, flags);
    if (ret < 0) {
        if (fd == handle_map->fd_top)
            handle_map->fd_top = fd ? fd - 1 : FD_NULL;
    } else
        ret = fd;
out:
    unlock(handle_map->lock);
    return ret;
}

int set_new_fd_handle_by_fd (FDTYPE fd, struct shim_handle * hdl, int flags,
                             struct shim_handle_map * handle_map)
{
    int new_size = 0;
    int ret = 0;

    if (!handle_map && !(handle_map = get_cur_handle_map(NULL)))
        return -EBADF;

    lock(handle_map->lock);

    if (!handle_map->map ||
        handle_map->fd_size < INIT_HANDLE_MAP_SIZE)
        new_size = INIT_HANDLE_MAP_SIZE;

    if (!handle_map->map)
        goto extend;

    if (fd >= handle_map->fd_size) {
        new_size = handle_map->fd_size < new_size ? new_size :
                   handle_map->fd_size;
extend:
        while (new_size <= fd)
            new_size *= 2;

        if (!__enlarge_handle_map(handle_map, new_size)) {
            ret = -ENOMEM;
            goto out;
        }
    }

    if (handle_map->fd_top != FD_NULL &&
        fd <= handle_map->fd_top &&
        HANDLE_ALLOCATED(handle_map->map[fd])) {
        ret = -EBADF;
        goto out;
    }

    if (handle_map->fd_top == FD_NULL ||
        fd > handle_map->fd_top)
        handle_map->fd_top = fd;

    struct shim_fd_handle * new_handle = handle_map->map[fd];

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
    } else
        ret = fd;
out:
    unlock(handle_map->lock);
    return fd;
}

void flush_handle (struct shim_handle * hdl)
{
    if (hdl->fs && hdl->fs->fs_ops &&
        hdl->fs->fs_ops->flush)
        hdl->fs->fs_ops->flush(hdl);
}

static inline __attribute__((unused))
const char * __handle_name (struct shim_handle * hdl)
{
    if (!qstrempty(&hdl->path))
        return qstrgetstr(&hdl->path);
    if (!qstrempty(&hdl->uri))
        return qstrgetstr(&hdl->uri);
    if (hdl->fs_type[0])
        return hdl->fs_type;
    return "(unknown)";
}

void open_handle (struct shim_handle * hdl)
{
    get_handle(hdl);

#ifdef DEBUG_REF
    int opened = REF_INC(hdl->opened);

    debug("open handle %p(%s) (opened = %d)\n", hdl, __handle_name(hdl),
          opened);
#else
    REF_INC(hdl->opened);
#endif
}

void close_handle (struct shim_handle * hdl)
{
    int opened = REF_DEC(hdl->opened);

#ifdef DEBUG_REF
    debug("close handle %p(%s) (opened = %d)\n", hdl, __handle_name(hdl),
          opened);
#endif

    if (!opened) {
        if (hdl->type == TYPE_DIR) {
            struct shim_dir_handle * dir = &hdl->info.dir;

            if (dir->dot) {
                put_dentry(dir->dot);
                dir->dot = NULL;
            }

            if (dir->dotdot) {
                put_dentry(dir->dotdot);
                dir->dotdot = NULL;
            }

            while (*dir->ptr) {
                struct shim_dentry * dent = *dir->ptr;
                put_dentry(dent);
                *(dir->ptr++) = NULL;
            }
        } else {
            if (hdl->fs && hdl->fs->fs_ops &&
                hdl->fs->fs_ops->close)
                hdl->fs->fs_ops->close(hdl);
        }
    }

    put_handle(hdl);
}

void get_handle (struct shim_handle * hdl)
{
#ifdef DEBUG_REF
    int ref_count = REF_INC(hdl->ref_count);

    debug("get handle %p(%s) (ref_count = %d)\n", hdl, __handle_name(hdl),
          ref_count);
#else
    REF_INC(hdl->ref_count);
#endif
}

static void destroy_handle (struct shim_handle * hdl)
{
    destroy_lock(hdl->lock);

    if (MEMORY_MIGRATED(hdl))
        memset(hdl, 0, sizeof(struct shim_handle));
    else
        free_mem_obj_to_mgr(handle_mgr, hdl);
}

void put_handle (struct shim_handle * hdl)
{
    int ref_count = REF_DEC(hdl->ref_count);

#ifdef DEBUG_REF
    debug("put handle %p(%s) (ref_count = %d)\n", hdl, __handle_name(hdl),
          ref_count);
#endif

    if (!ref_count) {
        if (hdl->fs && hdl->fs->fs_ops &&
            hdl->fs->fs_ops->hput)
            hdl->fs->fs_ops->hput(hdl);

        qstrfree(&hdl->path);
        qstrfree(&hdl->uri);

        if (hdl->pal_handle)
            DkObjectClose(hdl->pal_handle);

        if (hdl->dentry)
            put_dentry(hdl->dentry);

        if (hdl->fs)
            put_mount(hdl->fs);

        destroy_handle(hdl);
    }
}

size_t get_file_size (struct shim_handle * hdl)
{
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

void dup_fd_handle (struct shim_handle_map * map,
                    const struct shim_fd_handle * old,
                    struct shim_fd_handle * new)
{
    struct shim_handle * replaced = NULL;

    lock(map->lock);

    if (old->vfd != FD_NULL) {
        open_handle(old->handle);
        replaced = new->handle;
        new->handle = old->handle;
    }

    unlock(map->lock);

    if (replaced)
        close_handle(replaced);
}

static struct shim_handle_map * get_new_handle_map (FDTYPE size)
{
    struct shim_handle_map * handle_map =
                    malloc(sizeof(struct shim_handle_map));

    if (handle_map == NULL)
        return NULL;

    memset(handle_map, 0, sizeof(struct shim_handle_map));

    handle_map->map = malloc(sizeof(struct shim_fd_handle) * size);

    if (handle_map->map == NULL) {
        free(handle_map);
        return NULL;
    }

    memset(handle_map->map, 0,
           sizeof(struct shim_fd_handle) * size);

    handle_map->fd_top  = FD_NULL;
    handle_map->fd_size = size;
    create_lock(handle_map->lock);

    return handle_map;
}

static struct shim_handle_map * __enlarge_handle_map
                     (struct shim_handle_map * map, FDTYPE size)
{
    if (size <= map->fd_size)
        return NULL;

    struct shim_fd_handle ** old_map = map->map;

    map->map = malloc(sizeof(struct shim_fd_handle *) * size);

    if (map->map == NULL) {
        map->map = old_map;
        return NULL;
    }

    size_t copy_size = sizeof(struct shim_fd_handle *) * map->fd_size;
    map->fd_size = size;
    if (old_map && copy_size)
        memcpy(map->map, old_map, copy_size);
    memset(&map->map[map->fd_size], 0,
           (sizeof(struct shim_fd_handle *) * size) - copy_size);
    if (old_map)
        free(old_map);
    return map;
}

int dup_handle_map (struct shim_handle_map ** new,
                    struct shim_handle_map * old_map)
{
    lock(old_map->lock);

    /* allocate a new handle mapping with the same size as
       the old one */
    struct shim_handle_map * new_map =
                get_new_handle_map(old_map->fd_size);

    new_map->fd_top = old_map->fd_top;

    if (old_map->fd_top == FD_NULL)
        goto done;

    for (int i = 0 ; i <= old_map->fd_top ; i++) {
        struct shim_fd_handle * fd_old = old_map->map[i];
        struct shim_fd_handle * fd_new;

        /* now we go through the handle map and reassign each
           of them being allocated */
        if (HANDLE_ALLOCATED(fd_old)) {
            /* first, get the handle to prevent it from being deleted */
            struct shim_handle * hdl = fd_old->handle;
            open_handle(hdl);
            /* DP: I assume we really need a deep copy of the handle map? */
            fd_new = malloc(sizeof(struct shim_fd_handle));
            new_map->map[i] = fd_new;
            fd_new->vfd    = fd_old->vfd;
            fd_new->handle = hdl;
            fd_new->flags  = fd_old->flags;
        }
    }

done:
    unlock(old_map->lock);
    *new = new_map;

    return 0;
}

void get_handle_map (struct shim_handle_map * map)
{
    REF_INC(map->ref_count);
}

void put_handle_map (struct shim_handle_map * map)
{
    int ref_count = REF_DEC(map->ref_count);

    if (!ref_count) {
        if (map->fd_top == FD_NULL)
            goto done;

        for (int i = 0 ; i <= map->fd_top ; i++) {
            if (!map->map[i])
                continue;

            if (map->map[i]->vfd != FD_NULL) {
                struct shim_handle * handle = map->map[i]->handle;

                if (handle)
                    close_handle(handle);
            }

            free(map->map[i]);
        }

done:
        destroy_lock(map->lock);
        free(map->map);
        free(map);
    }
}

int flush_handle_map (struct shim_handle_map * map)
{
    get_handle_map(map);
    lock(map->lock);

    if (map->fd_top == FD_NULL)
        goto done;

    /* now we go through the handle map and flush each handle */
    for (int i = 0 ; i <= map->fd_top ; i++) {
        if (!HANDLE_ALLOCATED(map->map[i]))
            continue;

        struct shim_handle * handle = map->map[i]->handle;

        if (handle)
            flush_handle(handle);
    }

done:
    unlock(map->lock);
    put_handle_map(map);
    return 0;
}

int walk_handle_map (int (*callback) (struct shim_fd_handle *,
                                      struct shim_handle_map *, void *),
                     struct shim_handle_map * map, void * arg)
{
    int ret = 0;
    lock(map->lock);

    if (map->fd_top == FD_NULL)
        goto done;

    for (int i = 0 ; i <= map->fd_top ; i++) {
        if (!HANDLE_ALLOCATED(map->map[i]))
            continue;

        if ((ret = (*callback) (map->map[i], map, arg)) < 0)
            break;
    }

done:
    unlock(map->lock);
    return ret;
}

DEFINE_MIGRATE_FUNC(handle)

MIGRATE_FUNC_BODY(handle)
{
    assert(size == sizeof(struct shim_handle));

    struct shim_handle * hdl = (struct shim_handle *) obj;
    struct shim_handle * new_hdl = NULL;

    lock(hdl->lock);

   struct shim_mount * fs = hdl->fs, * new_fs = NULL;

    if (fs && fs->mount_point)
        __DO_MIGRATE(mount, fs, &new_fs, 0);

    unsigned long off = ADD_TO_MIGRATE_MAP(obj, *offset,
                                           sizeof(struct shim_handle));

    if (ENTRY_JUST_CREATED(off)) {
        ADD_OFFSET(sizeof(struct shim_handle));
        ADD_FUNC_ENTRY(*offset);
        ADD_ENTRY(SIZE, sizeof(struct shim_handle));

        if (!dry) {
            new_hdl = (struct shim_handle *) (base + *offset);
            memcpy(new_hdl, hdl, sizeof(struct shim_handle));

            if (fs && fs->fs_ops && fs->fs_ops->checkout)
                fs->fs_ops->checkout(new_hdl);

            new_hdl->dentry = NULL;
            new_hdl->fs = new_fs;
            REF_SET(new_hdl->opened, 0);
            REF_SET(new_hdl->ref_count, 0);
            clear_lock(new_hdl->lock);
        }

        ADD_ENTRY(PALHDL, new_hdl->pal_handle ?
                  *offset + offsetof(struct shim_handle, pal_handle) : 0);
    } else if (!dry)
        new_hdl = (struct shim_handle *) (base + off);

    if (new_hdl && objp)
        *objp = (void *) new_hdl;

    DO_MIGRATE_IN_MEMBER(qstr, hdl, new_hdl, path, false);
    DO_MIGRATE_IN_MEMBER(qstr, hdl, new_hdl, uri,  false);

    if (new_hdl)
        assert(new_hdl->uri.len < 1024);

    unlock(hdl->lock);
}
END_MIGRATE_FUNC

DEFINE_PROFILE_CATAGORY(inside_resume_handle, resume_func);
DEFINE_PROFILE_INTERVAL(dentry_lookup_for_handle, inside_resume_handle);

RESUME_FUNC_BODY(handle)
{
    unsigned long off = GET_FUNC_ENTRY();
    assert((size_t) GET_ENTRY(SIZE) == sizeof(struct shim_handle));
    GET_ENTRY(PALHDL);

    BEGIN_PROFILE_INTERVAL();

    struct shim_handle * hdl = (struct shim_handle *) (base + off);

    RESUME_REBASE(hdl->fs);

    create_lock(hdl->lock);

    if (!qstrempty(&hdl->path)) {
        UPDATE_PROFILE_INTERVAL();
        int ret = path_lookupat(NULL, qstrgetstr(&hdl->path), LOOKUP_OPEN,
                                &hdl->dentry);
        if (ret < 0)
            return -EACCES;

        get_dentry(hdl->dentry);
        SAVE_PROFILE_INTERVAL(dentry_lookup_for_handle);
    }

    if (!hdl->fs) {
        if (hdl->dentry) {
            set_handle_fs(hdl, hdl->dentry->fs);
        } else {
            struct shim_mount * fs = NULL;
            assert(hdl->fs_type);
            search_builtin_fs(hdl->fs_type, &fs);
            if (fs)
                set_handle_fs(hdl, fs);
        }
    }

    if (hdl->fs && hdl->fs->fs_ops &&
        hdl->fs->fs_ops->checkin)
        hdl->fs->fs_ops->checkin(hdl);

#ifdef DEBUG_RESUME
    debug("handle: path=%s,fs_type=%s,uri=%s,flags=%03o\n",
          qstrgetstr(&hdl->path), hdl->fs_type, qstrgetstr(&hdl->uri),
          hdl->flags);
#endif
}
END_RESUME_FUNC

DEFINE_MIGRATE_FUNC(fd_handle)

MIGRATE_FUNC_BODY(fd_handle)
{
    assert(size == sizeof(struct shim_fd_handle));

    struct shim_fd_handle * fdhdl = (struct shim_fd_handle *) obj;
    struct shim_fd_handle * new_fdhdl = NULL;

    ADD_OFFSET(sizeof(struct shim_fd_handle));
    ADD_FUNC_ENTRY(*offset);
    ADD_ENTRY(SIZE, sizeof(struct shim_fd_handle));

    if (!dry) {
        new_fdhdl = (struct shim_fd_handle *) (base + *offset);
        memcpy(new_fdhdl, fdhdl, sizeof(struct shim_fd_handle));
    }

    if (new_fdhdl && objp)
        *objp = (void *) new_fdhdl;

    struct shim_handle ** phdl = dry ? NULL : &(new_fdhdl->handle);
    struct shim_handle * hdl = fdhdl->handle;

    DO_MIGRATE_IF_RECURSIVE(handle, hdl, phdl, recursive);
}
END_MIGRATE_FUNC

RESUME_FUNC_BODY(fd_handle)
{
    GET_FUNC_ENTRY();
    assert((size_t) GET_ENTRY(SIZE) == sizeof(struct shim_fd_handle));
}
END_RESUME_FUNC

DEFINE_MIGRATE_FUNC(handle_map)

MIGRATE_FUNC_BODY(handle_map)
{
    assert(size >= sizeof(struct shim_handle_map));

    struct shim_handle_map * handle_map = (struct shim_handle_map *) obj;
    struct shim_handle_map * new_handle_map = NULL;
    struct shim_fd_handle ** ptr_array;

    lock(handle_map->lock);

    int fd_size = handle_map->fd_top != FD_NULL ?
                  handle_map->fd_top + 1 : 0;

    size = sizeof(struct shim_handle_map) +
           (sizeof(struct shim_fd_handle *) * fd_size);

    unsigned long off = ADD_TO_MIGRATE_MAP(obj, *offset, size);

    if (ENTRY_JUST_CREATED(off)) {
        ADD_OFFSET(size);
        ADD_FUNC_ENTRY(*offset);
        ADD_ENTRY(SIZE, size);

        if (!dry) {
            new_handle_map = (struct shim_handle_map *) (base + *offset);

            memcpy(new_handle_map, handle_map,
                   sizeof(struct shim_handle_map));

            ptr_array = (void *) new_handle_map +
                                 sizeof(struct shim_handle_map);

            new_handle_map->fd_size = fd_size;
            new_handle_map->map = fd_size ? ptr_array : NULL;

            REF_SET(new_handle_map->ref_count, 0);
            clear_lock(new_handle_map->lock);
        }

        for (int i = 0 ; i < fd_size ; i++) {
            if (HANDLE_ALLOCATED(handle_map->map[i])) {
                struct shim_fd_handle ** new_hdl = dry ? NULL :
                    &(ptr_array[i]);
                __DO_MIGRATE(fd_handle, handle_map->map[i],
                             new_hdl, 1);
            } else if (!dry)
                ptr_array[i] = NULL;
        }
    } else if (!dry)
        new_handle_map = (struct shim_handle_map *) (base + off);

    unlock(handle_map->lock);

    if (new_handle_map && objp)
        *objp = (void *) new_handle_map;
}
END_MIGRATE_FUNC

RESUME_FUNC_BODY(handle_map)
{
    unsigned long off = GET_FUNC_ENTRY();
    assert((size_t) GET_ENTRY(SIZE) >= sizeof(struct shim_handle_map));
    struct shim_handle_map * handle_map =
                    (struct shim_handle_map *) (base + off);

    RESUME_REBASE(handle_map->map);
    assert(handle_map->map);

#ifdef DEBUG_RESUME
    debug("handle_map: size=%d,top=%d\n", handle_map->fd_size,
          handle_map->fd_top);
#endif

    create_lock(handle_map->lock);
    lock(handle_map->lock);

    if (handle_map->fd_top != FD_NULL)
        for (int i = 0 ; i <= handle_map->fd_top ; i++) {
            RESUME_REBASE(handle_map->map[i]);
            if (HANDLE_ALLOCATED(handle_map->map[i])) {
                RESUME_REBASE(handle_map->map[i]->handle);
                struct shim_handle * hdl = handle_map->map[i]->handle;
                assert(hdl);
                open_handle(hdl);
#ifdef DEBUG_RESUME
                debug("handle_map[%d]: %s\n", i,
                      !qstrempty(&hdl->uri) ? qstrgetstr(&hdl->uri) :
                      hdl->fs_type);
#endif
            }
        }

    unlock(handle_map->lock);
}
END_RESUME_FUNC
