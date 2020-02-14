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
 * fs.c
 *
 * This file contains codes for implementation of 'chroot' filesystem.
 */

#include <shim_internal.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_vma.h>
#include <shim_fs.h>
#include <shim_utils.h>
#include <shim_profile.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>

#include <linux/stat.h>
#include <linux/fcntl.h>

#include <asm/fcntl.h>
#include <asm/mman.h>
#include <asm/unistd.h>
#include <asm/prctl.h>

#define URI_MAX_SIZE    STR_SIZE

#define TTY_FILE_MODE   0666

#define FILE_BUFMAP_SIZE (PAL_CB(alloc_align) * 4)
#define FILE_BUF_SIZE (PAL_CB(alloc_align))

struct mount_data {
    size_t              data_size;
    enum shim_file_type base_type;
    unsigned long       ino_base;
    size_t              root_uri_len;
    char                root_uri[];
};

#define HANDLE_MOUNT_DATA(h) ((struct mount_data*)(h)->fs->data)
#define DENTRY_MOUNT_DATA(d) ((struct mount_data*)(d)->fs->data)

static int chroot_mount (const char * uri, void ** mount_data)
{
    enum shim_file_type type;

    if (strstartswith_static(uri, URI_PREFIX_FILE)) {
        type = FILE_UNKNOWN;
        uri += 5;
    } else if (strstartswith_static(uri, URI_PREFIX_DEV)) {
        type = strstartswith_static(uri + static_strlen(URI_PREFIX_DEV), "tty") ? FILE_TTY : FILE_DEV;
        uri += 4;
    } else {
        return -EINVAL;
    }

    if (!(*uri))
        uri = ".";

    int uri_len = strlen(uri);
    int data_size = uri_len + 1 + sizeof(struct mount_data);

    struct mount_data * mdata = (struct mount_data *) malloc(data_size);

    mdata->data_size = data_size;
    mdata->base_type = type;
    mdata->ino_base = hash_path(uri, uri_len);
    mdata->root_uri_len = uri_len;
    memcpy(mdata->root_uri, uri, uri_len + 1);

    *mount_data = mdata;
    return 0;
}

static int chroot_unmount (void * mount_data)
{
    free(mount_data);
    return 0;
}

static inline ssize_t concat_uri (char * buffer, size_t size, int type,
                                  const char * root, size_t root_len,
                                  const char * trim, size_t trim_len)
{
    char * tmp = NULL;

    switch (type) {
        case FILE_UNKNOWN:
        case FILE_REGULAR:
            tmp = strcpy_static(buffer, URI_PREFIX_FILE, size);
            break;

        case FILE_DIR:
            tmp = strcpy_static(buffer, URI_PREFIX_DIR, size);
            break;

        case FILE_DEV:
        case FILE_TTY:
            tmp = strcpy_static(buffer, URI_PREFIX_DEV, size);
            break;

        default:
            return -EINVAL;
    }

    if (!tmp || tmp + root_len + trim_len + 2 > buffer + size)
        return -ENAMETOOLONG;

    if (root_len) {
        memcpy(tmp, root, root_len + 1);
        tmp += root_len;
    }

    if (trim_len) {
        *(tmp++) = '/';
        memcpy(tmp, trim, trim_len + 1);
        tmp += trim_len;
    }

    return tmp - buffer;
}

/* simply just create data, sometimes it is individually called when the
   handle is not linked to a dentry */
static struct shim_file_data* __create_data(void) {
    struct shim_file_data* data = calloc(1, sizeof(struct shim_file_data));
    if (!data)
        return NULL;

    if (!create_lock(&data->lock)) {
        free(data);
        return NULL;
    }
    return data;
}

static void __destroy_data (struct shim_file_data * data)
{
    qstrfree(&data->host_uri);
    destroy_lock(&data->lock);
    free(data);
}

static ssize_t make_uri (struct shim_dentry * dent)
{
    struct mount_data * mdata = DENTRY_MOUNT_DATA(dent);
    assert(mdata);

    struct shim_file_data * data = FILE_DENTRY_DATA(dent);
    char uri[URI_MAX_SIZE];
    ssize_t len = concat_uri(uri, URI_MAX_SIZE, data->type,
                             mdata->root_uri,
                             mdata->root_uri_len,
                             qstrgetstr(&dent->rel_path),
                             dent->rel_path.len);
    if (len >= 0)
        qstrsetstr(&data->host_uri, uri, len);

    return len;
}

/* create a data in the dentry and compose it's uri. dent->lock needs to
   be held */
static int create_data (struct shim_dentry * dent, const char * uri, size_t len)
{
    assert(locked(&dent->lock));

    if (dent->data)
        return 0;

    struct shim_file_data * data = __create_data();
    if (!data)
        return -ENOMEM;

    dent->data = data;

    struct mount_data * mdata = DENTRY_MOUNT_DATA(dent);
    assert(mdata);
    data->type = (dent->state & DENTRY_ISDIRECTORY) ?
                 FILE_DIR : mdata->base_type;
    data->mode = NO_MODE;

    if (uri) {
        qstrsetstr(&data->host_uri, uri, len);
    } else {
        int ret = make_uri(dent);
        if (ret < 0)
            return ret;
    }

    atomic_set(&data->version, 0);
    return 0;
}

static int chroot_readdir (struct shim_dentry * dent,
                           struct shim_dirent ** dirent);

static int __query_attr (struct shim_dentry * dent,
                         struct shim_file_data * data, PAL_HANDLE pal_handle)
{
    PAL_STREAM_ATTR pal_attr;
    enum shim_file_type old_type = data->type;

    if (pal_handle ?
        !DkStreamAttributesQueryByHandle(pal_handle, &pal_attr) :
        !DkStreamAttributesQuery(qstrgetstr(&data->host_uri), &pal_attr))
        return -PAL_ERRNO;

    /* need to correct the data type */
    if (data->type == FILE_UNKNOWN)
        switch (pal_attr.handle_type) {
            case pal_type_file: data->type = FILE_REGULAR; if (dent) dent->type = S_IFREG; break;
            case pal_type_dir:  data->type = FILE_DIR;     if (dent) dent->type = S_IFDIR; break;
            case pal_type_dev:  data->type = FILE_DEV;     if (dent) dent->type = S_IFCHR; break;
        }

    data->mode = (pal_attr.readable ? S_IRUSR : 0) |
                 (pal_attr.writable ? S_IWUSR : 0) |
                 (pal_attr.runnable ? S_IXUSR : 0);

    atomic_set(&data->size, pal_attr.pending_size);

    if (data->type == FILE_DIR) {
        int ret;
        /* Move up the uri update; need to convert manifest-level file:
         * directives to 'dir:' uris */
        if (old_type != FILE_DIR) {
            dent->state |= DENTRY_ISDIRECTORY;
            if ((ret = make_uri(dent)) < 0) {
                unlock(&data->lock);
                return ret;
            }
        }

        /* DEP 3/18/17: If we have a directory, we need to find out how many
         * children it has by hand. */
        /* XXX: Keep coherent with rmdir/mkdir/creat, etc */
        struct shim_dirent *d, *dbuf = NULL;
        size_t nlink = 0;
        int rv = chroot_readdir(dent, &dbuf);
        if (rv != 0)
            return rv;
        if (dbuf) {
            for (d = dbuf; d; d = d->next)
                nlink++;
            free(dbuf);
        } else {
            nlink = 2; // Educated guess...
        }
        data->nlink = nlink;
    } else {
        /* DEP 3/18/17: Right now, we don't support hard links,
         * so just return 1;
         */
        data->nlink = 1;
    }

    data->queried = true;

    return 0;
}

/* do not need any lock */
static void chroot_update_ino (struct shim_dentry * dent)
{
    if (dent->state & DENTRY_INO_UPDATED)
        return;

    struct mount_data * mdata = DENTRY_MOUNT_DATA(dent);
    unsigned long ino = mdata->ino_base;

    if (!qstrempty(&dent->rel_path))
        ino = rehash_path(mdata->ino_base, qstrgetstr(&dent->rel_path),
                          dent->rel_path.len);

    dent->ino = ino;
    dent->state |= DENTRY_INO_UPDATED;
}

static inline int try_create_data (struct shim_dentry * dent,
                                   const char * uri, size_t len,
                                   struct shim_file_data ** dataptr)
{
    struct shim_file_data * data = FILE_DENTRY_DATA(dent);

    if (!data) {
        lock(&dent->lock);
        int ret = create_data(dent, uri, len);
        data = FILE_DENTRY_DATA(dent);
        unlock(&dent->lock);
        if (ret < 0) {
            return ret;
        }
    }

    *dataptr = data;
    return 0;
}

static int query_dentry (struct shim_dentry * dent, PAL_HANDLE pal_handle,
                         mode_t * mode, struct stat * stat)
{
    int ret = 0;

    struct shim_file_data * data;
    if ((ret = try_create_data(dent, NULL, 0, &data)) < 0)
        return ret;

    lock(&data->lock);

    if (!data->queried && (ret = __query_attr(dent, data, pal_handle)) < 0) {
        unlock(&data->lock);
        return ret;
    }

    if (mode)
        *mode = data->mode;

    if (stat) {
        struct mount_data * mdata = DENTRY_MOUNT_DATA(dent);
        chroot_update_ino(dent);

        memset(stat, 0, sizeof(struct stat));

        stat->st_mode   = (mode_t) data->mode;
        stat->st_dev    = (dev_t) mdata->ino_base;
        stat->st_ino    = (ino_t) dent->ino;
        stat->st_size   = (off_t) atomic_read(&data->size);
        stat->st_atime  = (time_t) data->atime;
        stat->st_mtime  = (time_t) data->mtime;
        stat->st_ctime  = (time_t) data->ctime;
        stat->st_nlink  = data->nlink;

        switch (data->type) {
            case FILE_REGULAR:
                stat->st_mode |= S_IFREG;
                break;
            case FILE_DIR:
                stat->st_mode |= S_IFDIR;
                break;
            case FILE_DEV:
            case FILE_TTY:
                stat->st_mode |= S_IFCHR;
                break;
            default:            break;
        }
    }

    unlock(&data->lock);
    return 0;
}

static int chroot_mode (struct shim_dentry * dent, mode_t * mode)
{
    return query_dentry(dent, NULL, mode, NULL);
}

static int chroot_stat (struct shim_dentry * dent, struct stat * statbuf)
{
    return query_dentry(dent, NULL, NULL, statbuf);
}

static int chroot_lookup (struct shim_dentry * dent)
{

    return query_dentry(dent, NULL, NULL, NULL);
}

static int __chroot_open (struct shim_dentry * dent,
                          const char * uri, int flags, mode_t mode,
                          struct shim_handle * hdl,
                          struct shim_file_data * data)
{
    int ret = 0;

    if (!uri) {
        uri = qstrgetstr(&data->host_uri);
    }

    int version = atomic_read(&data->version);
    int oldmode = flags & O_ACCMODE;
    int accmode = oldmode;
    int creat   = flags & PAL_CREATE_MASK;
    int option  = flags & PAL_OPTION_MASK;

    if ((data->type == FILE_REGULAR || data->type == FILE_UNKNOWN)
        && accmode == O_WRONLY)
        accmode = O_RDWR;

    PAL_HANDLE palhdl;

    if (hdl && hdl->pal_handle) {
        palhdl = hdl->pal_handle;
    } else {
        palhdl = DkStreamOpen(uri, accmode, mode, creat, option);

        if (!palhdl) {
            if (PAL_NATIVE_ERRNO == PAL_ERROR_DENIED &&
                accmode != oldmode)
                palhdl = DkStreamOpen(uri, oldmode, mode, creat, option);

            if (!palhdl)
                return -PAL_ERRNO;
        }

        /* If DENTRY_LISTED is set on the parent dentry, list_directory_dentry() will not update
         * dent's ino, so ino will be actively updated here. */
        if (creat)
            chroot_update_ino(dent);
    }

    if (!data->queried) {
        lock(&data->lock);
        ret = __query_attr(dent, data, palhdl);
        unlock(&data->lock);
    }

    if (!hdl) {
        DkObjectClose(palhdl);
        return 0;
    }

    hdl->pal_handle        = palhdl;
    hdl->info.file.type    = data->type;
    hdl->info.file.version = version;
    hdl->info.file.size    = atomic_read(&data->size);
    hdl->info.file.data    = data;

    return ret;
}

static int chroot_open (struct shim_handle * hdl, struct shim_dentry * dent,
                        int flags)
{
    int ret = 0;
    struct shim_file_data * data;
    if ((ret = try_create_data(dent, NULL, 0, &data)) < 0)
        return ret;

    if (dent->mode == NO_MODE) {
        lock(&data->lock);
        ret = __query_attr(dent, data, NULL);
        dent->mode = data->mode;
        unlock(&data->lock);
    }

    if ((ret = __chroot_open(dent, NULL, flags, dent->mode, hdl, data)) < 0)
        return ret;

    struct shim_file_handle * file = &hdl->info.file;
    off_t size = atomic_read(&data->size);

    /* initialize hdl, does not need a lock because no one is sharing */
    hdl->type       = TYPE_FILE;
    file->marker    = (flags & O_APPEND) ? size : 0;
    file->size      = size;
    hdl->flags      = flags;
    hdl->acc_mode   = ACC_MODE(flags & O_ACCMODE);
    qstrcopy(&hdl->uri, &data->host_uri);

    return 0;
}

static int chroot_creat (struct shim_handle * hdl, struct shim_dentry * dir,
                         struct shim_dentry * dent, int flags, mode_t mode)
{
    int ret = 0;
    struct shim_file_data * data;
    if ((ret = try_create_data(dent, NULL, 0, &data)) < 0)
        return ret;

    if ((ret = __chroot_open(dent, NULL, flags|O_CREAT|O_EXCL, mode, hdl,
                             data)) < 0)
        return ret;

    if (!hdl)
        return 0;

    struct shim_file_handle * file = &hdl->info.file;
    off_t size = atomic_read(&data->size);

    /* initialize hdl, does not need a lock because no one is sharing */
    hdl->type       = TYPE_FILE;
    file->marker    = (flags & O_APPEND) ? size : 0;
    file->size      = size;
    hdl->flags      = flags;
    hdl->acc_mode   = ACC_MODE(flags & O_ACCMODE);
    qstrcopy(&hdl->uri, &data->host_uri);

    /* Increment the parent's link count */
    struct shim_file_data *parent_data = FILE_DENTRY_DATA(dir);
    if (parent_data) {
        lock(&parent_data->lock);
        if (parent_data->queried)
            parent_data->nlink++;
        unlock(&parent_data->lock);
    }
    return 0;
}

static int chroot_mkdir (struct shim_dentry * dir, struct shim_dentry * dent,
                         mode_t mode)
{
    int ret = 0;
    struct shim_file_data * data;
    if ((ret = try_create_data(dent, NULL, 0, &data)) < 0)
        return ret;

    if (data->type != FILE_DIR) {
        data->type = FILE_DIR;
        int ret = make_uri(dent);
        if (ret < 0)
            return ret;
    }

    ret = __chroot_open(dent, NULL, O_CREAT|O_EXCL, mode, NULL, data);

    /* Increment the parent's link count */
    struct shim_file_data *parent_data = FILE_DENTRY_DATA(dir);
    if (parent_data) {
        lock(&parent_data->lock);
        if (parent_data->queried)
            parent_data->nlink++;
        unlock(&parent_data->lock);
    }
    return ret;
}

#define NEED_RECREATE(hdl)   (!FILE_HANDLE_DATA(hdl))

static int chroot_recreate (struct shim_handle * hdl)
{
    struct shim_file_data * data = FILE_HANDLE_DATA(hdl);
    int ret = 0;

    /* quickly bail out if the data is created */
    if (data)
        return 0;

    const char * uri = qstrgetstr(&hdl->uri);
    size_t len = hdl->uri.len;

    if (hdl->dentry) {
        if ((ret = try_create_data(hdl->dentry, uri, len, &data)) < 0)
            return ret;
    } else {
        data = __create_data();
        if (!data)
            return -ENOMEM;
        qstrsetstr(&data->host_uri, uri, len);
    }

    /*
     * when recreating a file handle after migration, the file should
     * not be created again.
     */
    return __chroot_open(hdl->dentry, uri, hdl->flags & ~(O_CREAT|O_EXCL),
                         0, hdl, data);
}

static inline bool check_version (struct shim_handle * hdl)
{
    return atomic_read(&FILE_HANDLE_DATA(hdl)->version)
           == hdl->info.file.version;
}

static void chroot_update_size(struct shim_handle* hdl, struct shim_file_handle* file,
                               struct shim_file_data* data) {
    if (check_version(hdl)) {
        off_t size;
        do {
            if ((size = atomic_read(&data->size)) >= file->size) {
                file->size = size;
                break;
            }
        } while ((off_t)atomic_cmpxchg(&data->size, size, file->size) != size);
    }
}

static int chroot_hstat (struct shim_handle * hdl, struct stat * stat)
{
    int ret;
    if (NEED_RECREATE(hdl) && (ret = chroot_recreate(hdl)) < 0)
        return ret;

    if (!check_version(hdl) || !hdl->dentry) {
        struct shim_file_handle * file = &hdl->info.file;
        struct shim_dentry * dent = hdl->dentry;
        struct mount_data * mdata = dent ? DENTRY_MOUNT_DATA(dent) : NULL;

        if (dent)
            chroot_update_ino(dent);

        if (stat) {
            memset(stat, 0, sizeof(struct stat));
            stat->st_dev  = mdata ? (dev_t) mdata->ino_base : 0;
            stat->st_ino  = dent ? (ino_t) dent->ino : 0;
            stat->st_size = file->size;
            stat->st_mode |= (file->type == FILE_REGULAR) ? S_IFREG : S_IFCHR;
        }

        return 0;
    }

    return query_dentry(hdl->dentry, hdl->pal_handle, NULL, stat);
}

static int chroot_flush(struct shim_handle* hdl) {
    int ret = DkStreamFlush(hdl->pal_handle);
    if (ret < 0)
        return ret;
    return 0;
}

static int chroot_close(struct shim_handle* hdl) {
    __UNUSED(hdl);
    return 0;
}

static ssize_t chroot_read (struct shim_handle * hdl, void * buf, size_t count)
{
    ssize_t ret = 0;

    if (count == 0)
        goto out;

    if (NEED_RECREATE(hdl) && (ret = chroot_recreate(hdl)) < 0) {
        goto out;
    }

    if (!(hdl->acc_mode & MAY_READ)) {
        ret = -EBADF;
        goto out;
    }

    struct shim_file_handle * file = &hdl->info.file;

    off_t dummy_off_t;
    if (file->type != FILE_TTY && __builtin_add_overflow(file->marker, count, &dummy_off_t)) {
        ret = -EFBIG;
        goto out;
    }

    lock(&hdl->lock);

    PAL_NUM pal_ret = DkStreamRead(hdl->pal_handle, file->marker, count, buf, NULL, 0);
    if (pal_ret != PAL_STREAM_ERROR) {
        if (__builtin_add_overflow(pal_ret, 0, &ret))
            BUG();
        if (file->type != FILE_TTY && __builtin_add_overflow(file->marker, pal_ret, &file->marker))
            BUG();
    } else {
        ret = PAL_NATIVE_ERRNO == PAL_ERROR_ENDOFSTREAM ?  0 : -PAL_ERRNO;
    }

    unlock(&hdl->lock);
out:
    return ret;
}

static ssize_t chroot_write (struct shim_handle * hdl, const void * buf, size_t count)
{
    ssize_t ret;

    if (count == 0)
        return 0;

    if (NEED_RECREATE(hdl) && (ret = chroot_recreate(hdl)) < 0) {
        goto out;
    }

    if (!(hdl->acc_mode & MAY_WRITE)) {
        ret = -EBADF;
        goto out;
    }

    struct shim_file_handle * file = &hdl->info.file;

    off_t dummy_off_t;
    if (file->type != FILE_TTY && __builtin_add_overflow(file->marker, count, &dummy_off_t)) {
        ret = -EFBIG;
        goto out;
    }

    lock(&hdl->lock);

    PAL_NUM pal_ret = DkStreamWrite(hdl->pal_handle, file->marker, count, (void *) buf, NULL);
    if (pal_ret != PAL_STREAM_ERROR) {
        if (__builtin_add_overflow(pal_ret, 0, &ret))
            BUG();
        if (file->type != FILE_TTY && __builtin_add_overflow(file->marker, pal_ret, &file->marker))
            BUG();
        if (file->marker > file->size) {
            file->size = file->marker;
            chroot_update_size(hdl, file, FILE_HANDLE_DATA(hdl));
        }
    } else {
        ret = PAL_NATIVE_ERRNO == PAL_ERROR_ENDOFSTREAM ?  0 : -PAL_ERRNO;
    }

    unlock(&hdl->lock);
out:
    return ret;
}

static int chroot_mmap (struct shim_handle * hdl, void ** addr, size_t size,
                        int prot, int flags, off_t offset)
{
    int ret;
    if (NEED_RECREATE(hdl) && (ret = chroot_recreate(hdl)) < 0)
        return ret;

    int pal_prot = PAL_PROT(prot, flags);

#if MAP_FILE == 0
    if (flags & MAP_ANONYMOUS)
#else
    if (!(flags & MAP_FILE))
#endif
        return -EINVAL;

    void * alloc_addr =
        (void *) DkStreamMap(hdl->pal_handle, *addr, pal_prot, offset, size);

    if (!alloc_addr)
        return -PAL_ERRNO;

    *addr = alloc_addr;
    return 0;
}

static off_t chroot_seek (struct shim_handle * hdl, off_t offset, int wence)
{
    off_t ret = -EINVAL;

    if (NEED_RECREATE(hdl) && (ret = chroot_recreate(hdl)) < 0)
        return ret;

    struct shim_file_handle * file = &hdl->info.file;
    lock(&hdl->lock);

    off_t marker = file->marker;
    off_t size = file->size;

    if (check_version(hdl)) {
        struct shim_file_data * data = FILE_HANDLE_DATA(hdl);
        if (data->type != FILE_REGULAR) {
            ret = -ESPIPE;
            goto out;
        }
    }

    switch (wence) {
        case SEEK_SET:
            if (offset < 0)
                goto out;
            marker = offset;
            break;

        case SEEK_CUR:
            marker += offset;
            break;

        case SEEK_END:
            marker = size + offset;
            break;
    }

    ret = file->marker = marker;

out:
    unlock(&hdl->lock);
    return ret;
}

static int chroot_truncate (struct shim_handle * hdl, off_t len)
{
    int ret = 0;

    if (NEED_RECREATE(hdl) && (ret = chroot_recreate(hdl)) < 0)
        return ret;

    if (!(hdl->acc_mode & MAY_WRITE))
        return -EINVAL;

    struct shim_file_handle * file = &hdl->info.file;
    lock(&hdl->lock);

    file->size = len;

    if (check_version(hdl)) {
        struct shim_file_data * data = FILE_HANDLE_DATA(hdl);
        atomic_set(&data->size, len);
    }

    PAL_NUM rv = DkStreamSetLength(hdl->pal_handle, len);
    if (rv) {
        // For an error, cast it back down to an int return code
        ret = -((int)rv);
        goto out;
    }

    // DEP 10/25/16: Truncate returns 0 on success, not the length
    ret = 0;

    if (file->marker > len)
        file->marker = len;

out:
    unlock(&hdl->lock);
    return ret;
}

static int chroot_dput (struct shim_dentry * dent)
{
    struct shim_file_data * data = FILE_DENTRY_DATA(dent);

    if (data) {
        __destroy_data(data);
        dent->data = NULL;
    }

    return 0;
}

static int chroot_readdir(struct shim_dentry* dent, struct shim_dirent** dirent) {
    struct shim_file_data* data = NULL;
    int ret = 0;
    PAL_HANDLE pal_hdl = NULL;
    size_t buf_size = MAX_PATH,
           dirent_buf_size = 0;
    char* buf = NULL;
    char* dirent_buf = NULL;

    if ((ret = try_create_data(dent, NULL, 0, &data)) < 0)
        return ret;

    chroot_update_ino(dent);

    const char* uri = qstrgetstr(&data->host_uri);
    assert(strstartswith_static(uri, URI_PREFIX_DIR));

    pal_hdl = DkStreamOpen(uri, PAL_ACCESS_RDONLY, 0, 0, 0);
    if (!pal_hdl)
        return -PAL_ERRNO;

    buf = malloc(buf_size);
    if (!buf) {
        ret = -ENOMEM;
        goto out;
    }

    while (1) {
        /* DkStreamRead for directory will return as many entries as fits into the buffer. */
        PAL_NUM bytes = DkStreamRead(pal_hdl, 0, buf_size, buf, NULL, 0);
        if (bytes == PAL_STREAM_ERROR) {
            if (PAL_NATIVE_ERRNO == PAL_ERROR_ENDOFSTREAM) {
                /* End of directory listing */
                ret = 0;
                break;
            }

            ret = -PAL_ERRNO;
            goto out;
        }
        /* Last entry must be null-terminated */
        assert(buf[bytes - 1] == '\0');

        size_t dirent_cur_off = dirent_buf_size;
        /* Calculate needed buffer size */
        size_t len = buf[0] != '\0' ? 1 : 0;
        for (size_t i = 1; i < bytes; i++) {
            if (buf[i] == '\0') {
                /* The PAL convention: if a name ends with '/', it is a directory.
                 * struct shim_dirent has a field for a type, hence trailing slash
                 * can be safely discarded. */
                if (buf[i - 1] == '/') {
                    len--;
                }
                dirent_buf_size += SHIM_DIRENT_ALIGNED_SIZE(len + 1);
                len = 0;
            } else {
                len++;
            }
        }

        /* TODO: If realloc gets enabled delete following and uncomment rest */
        char* tmp = malloc(dirent_buf_size);
        if (!tmp) {
            ret = -ENOMEM;
            goto out;
        }
        memcpy(tmp, dirent_buf, dirent_cur_off);
        free(dirent_buf);
        dirent_buf = tmp;
        /*
        dirent_buf = realloc(dirent_buf, dirent_buf_size);
        if (!dirent_buf) {
            ret = -ENOMEM;
            goto out;
        }
        */

        size_t i = 0;
        while (i < bytes) {
            char* name = buf + i;
            size_t len = strnlen(name, bytes - i);
            i += len + 1;
            bool is_dir = false;

            /* Skipping trailing slash - explained above */
            if (name[len - 1] == '/') {
                is_dir = true;
                name[--len] = '\0';
            }

            struct shim_dirent* dptr = (struct shim_dirent*)(dirent_buf + dirent_cur_off);
            dptr->ino = rehash_name(dent->ino, name, len);
            dptr->type = is_dir ? LINUX_DT_DIR : LINUX_DT_REG;
            memcpy(dptr->name, name, len + 1);

            dirent_cur_off += SHIM_DIRENT_ALIGNED_SIZE(len + 1);
        }
    }

    *dirent = (struct shim_dirent*)dirent_buf;

    /*
     * Fix next field of struct shim_dirent to point to the next entry.
     * Since all entries are assumed to come from single allocation
     * (as free gets called just on the head of this list) this should have
     * been just entry size instead of a pointer (and probably needs to be
     * rewritten as such one day).
     */
    struct shim_dirent** last = NULL;
    for (size_t dirent_cur_off = 0; dirent_cur_off < dirent_buf_size; ) {
        struct shim_dirent* dptr = (struct shim_dirent*)(dirent_buf + dirent_cur_off);
        size_t len = SHIM_DIRENT_ALIGNED_SIZE(strlen(dptr->name) + 1);
        dptr->next = (struct shim_dirent*)(dirent_buf + dirent_cur_off + len);
        last = &dptr->next;
        dirent_cur_off += len;
    }
    if (last) {
        *last = NULL;
    }

out:
    /* Need to free output buffer if error is returned */
    if (ret) {
        free(dirent_buf);
    }
    free(buf);
    DkObjectClose(pal_hdl);
    return ret;
}

static int chroot_checkout (struct shim_handle * hdl)
{
    if (hdl->fs == &chroot_builtin_fs)
        hdl->fs = NULL;

    if (hdl->type == TYPE_FILE) {
        struct shim_file_data * data = FILE_HANDLE_DATA(hdl);
        if (data)
            hdl->info.file.data = NULL;
    }

    if (hdl->pal_handle) {
        /*
         * if the file still exists in the host, no need to send
         * the handle over RPC; otherwise, send it.
         */
        PAL_STREAM_ATTR attr;
        if (DkStreamAttributesQuery(qstrgetstr(&hdl->uri), &attr))
            hdl->pal_handle = NULL;
    }

    return 0;
}

static ssize_t chroot_checkpoint (void ** checkpoint, void * mount_data)
{
    struct mount_data * mdata = mount_data;

    *checkpoint = mount_data;
    return mdata->root_uri_len + sizeof(struct mount_data) + 1;
}

static int chroot_migrate (void * checkpoint, void ** mount_data)
{
    struct mount_data * mdata = checkpoint;
    size_t alloc_len = mdata->root_uri_len + sizeof(struct mount_data) + 1;

    void * new_data = malloc(alloc_len);
    if (!new_data)
        return -ENOMEM;

    memcpy(new_data, mdata, alloc_len);
    *mount_data = new_data;

    return 0;
}

static int chroot_unlink (struct shim_dentry * dir, struct shim_dentry * dent)
{
    int ret;
    struct shim_file_data * data;
    if ((ret = try_create_data(dent, NULL, 0, &data)) < 0)
        return ret;

    PAL_HANDLE pal_hdl = DkStreamOpen(qstrgetstr(&data->host_uri), 0, 0, 0, 0);
    if (!pal_hdl)
        return -PAL_ERRNO;

    DkStreamDelete(pal_hdl, 0);
    DkObjectClose(pal_hdl);

    dent->mode = NO_MODE;
    data->mode = 0;

    atomic_inc(&data->version);
    atomic_set(&data->size, 0);

    /* Drop the parent's link count */
    struct shim_file_data *parent_data = FILE_DENTRY_DATA(dir);
    if (parent_data) {
        lock(&parent_data->lock);
        if (parent_data->queried)
            parent_data->nlink--;
        unlock(&parent_data->lock);
    }

    return 0;
}

static off_t chroot_poll (struct shim_handle * hdl, int poll_type)
{
    int ret;
    if (NEED_RECREATE(hdl) && (ret = chroot_recreate(hdl)) < 0)
        return ret;

    struct shim_file_data * data = FILE_HANDLE_DATA(hdl);
    off_t size = atomic_read(&data->size);

    if (poll_type == FS_POLL_SZ)
        return size;

    lock(&hdl->lock);

    struct shim_file_handle * file = &hdl->info.file;
    if (check_version(hdl) &&
        file->size < size)
        file->size = size;

    off_t marker = file->marker;

    if (file->type == FILE_REGULAR) {
        ret = poll_type & FS_POLL_WR;
        if ((poll_type & FS_POLL_RD) && file->size > marker)
            ret |= FS_POLL_RD;
        goto out;
    }

    ret = -EAGAIN;

out:
    unlock(&hdl->lock);
    return ret;
}

static int chroot_rename(struct shim_dentry* old, struct shim_dentry* new) {
    int ret;

    struct shim_file_data* old_data;
    if ((ret = try_create_data(old, NULL, 0, &old_data)) < 0) {
        return ret;
    }

    struct shim_file_data* new_data;
    if ((ret = try_create_data(new, NULL, 0, &new_data)) < 0) {
        return ret;
    }

    PAL_HANDLE pal_hdl = DkStreamOpen(qstrgetstr(&old_data->host_uri), 0, 0, 0, 0);
    if (!pal_hdl) {
        return -PAL_ERRNO;
    }

    if (!DkStreamChangeName(pal_hdl, qstrgetstr(&new_data->host_uri))) {
        DkObjectClose(pal_hdl);
        return -PAL_ERRNO;
    }

    new->mode = new_data->mode = old_data->mode;
    old->mode = NO_MODE;
    old_data->mode = 0;

    new->type = old->type;

    DkObjectClose(pal_hdl);

    atomic_inc(&old_data->version);
    atomic_set(&old_data->size, 0);
    atomic_inc(&new_data->version);

    return 0;
}

static int chroot_chmod (struct shim_dentry * dent, mode_t mode)
{
    int ret;
    struct shim_file_data * data;
    if ((ret = try_create_data(dent, NULL, 0, &data)) < 0)
        return ret;

    PAL_HANDLE pal_hdl = DkStreamOpen(qstrgetstr(&data->host_uri), 0, 0, 0, 0);
    if (!pal_hdl)
        return -PAL_ERRNO;

    PAL_STREAM_ATTR attr = { .share_flags = mode };

    if (!DkStreamAttributesSetByHandle(pal_hdl, &attr)) {
        DkObjectClose(pal_hdl);
        return -PAL_ERRNO;
    }

    DkObjectClose(pal_hdl);
    dent->mode = data->mode = mode;

    return 0;
}

struct shim_fs_ops chroot_fs_ops = {
        .mount       = &chroot_mount,
        .unmount     = &chroot_unmount,
        .flush       = &chroot_flush,
        .close       = &chroot_close,
        .read        = &chroot_read,
        .write       = &chroot_write,
        .mmap        = &chroot_mmap,
        .seek        = &chroot_seek,
        .hstat       = &chroot_hstat,
        .truncate    = &chroot_truncate,
        .checkout    = &chroot_checkout,
        .checkpoint  = &chroot_checkpoint,
        .migrate     = &chroot_migrate,
        .poll        = &chroot_poll,
    };

struct shim_d_ops chroot_d_ops = {
        .open       = &chroot_open,
        .mode       = &chroot_mode,
        .lookup     = &chroot_lookup,
        .creat      = &chroot_creat,
        .mkdir      = &chroot_mkdir,
        .stat       = &chroot_stat,
        .dput       = &chroot_dput,
        .readdir    = &chroot_readdir,
        .unlink     = &chroot_unlink,
        .rename     = &chroot_rename,
        .chmod      = &chroot_chmod,
    };

struct mount_data chroot_data = { .root_uri_len = 5,
                                  .root_uri = URI_PREFIX_FILE, };

struct shim_mount chroot_builtin_fs = { .type   = "chroot",
                                        .fs_ops = &chroot_fs_ops,
                                        .d_ops  = &chroot_d_ops,
                                        .data   = &chroot_data, };
