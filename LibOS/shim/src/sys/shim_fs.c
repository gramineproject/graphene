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
 * shim_fs.c
 *
 * Implementation of system call "unlink", "unlinkat", "mkdir", "mkdirat",
 * "rmdir", "umask", "chmod", "fchmod", "fchmodat", "rename", "renameat" and
 * "sendfile".
 */

#define __KERNEL__

#include <asm/mman.h>
#include <errno.h>
#include <linux/fcntl.h>
#include <linux/stat.h>

#include <pal.h>
#include <pal_error.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_table.h>
#include <shim_thread.h>
#include <shim_utils.h>

/* The kernel would look up the parent directory, and remove the child from the inode. But we are
 * working with the PAL, so we open the file, truncate and close it. */
int shim_do_unlink(const char* file) {
    if (!file)
        return -EINVAL;

    if (test_user_string(file))
        return -EFAULT;

    struct shim_dentry* dent = NULL;
    int ret = 0;

    if ((ret = path_lookupat(NULL, file, LOOKUP_OPEN, &dent, NULL)) < 0)
        return ret;

    if (!dent->parent)
        return -EACCES;

    if (dent->state & DENTRY_ISDIRECTORY)
        return -EISDIR;

    if (dent->fs && dent->fs->d_ops && dent->fs->d_ops->unlink) {
        if ((ret = dent->fs->d_ops->unlink(dent->parent, dent)) < 0)
            return ret;
    } else {
        dent->state |= DENTRY_PERSIST;
    }

    dent->state |= DENTRY_NEGATIVE;
    put_dentry(dent);
    return 0;
}

int shim_do_unlinkat(int dfd, const char* pathname, int flag) {
    if (!pathname)
        return -EINVAL;

    if (test_user_string(pathname))
        return -EFAULT;

    if (flag & ~AT_REMOVEDIR)
        return -EINVAL;

    struct shim_dentry* dir = NULL;
    struct shim_dentry* dent = NULL;
    int ret = 0;

    if ((ret = get_dirfd_dentry(dfd, &dir)) < 0)
        return ret;

    if ((ret = path_lookupat(dir, pathname, LOOKUP_OPEN, &dent, NULL)) < 0)
        goto out;

    if (!dent->parent) {
        ret = -EACCES;
        goto out_dent;
    }

    if (flag & AT_REMOVEDIR) {
        if (!(dent->state & DENTRY_ISDIRECTORY))
            return -ENOTDIR;
    } else {
        if (dent->state & DENTRY_ISDIRECTORY)
            return -EISDIR;
    }

    if (dent->fs && dent->fs->d_ops && dent->fs->d_ops->unlink) {
        if ((ret = dent->fs->d_ops->unlink(dent->parent, dent)) < 0)
            return ret;
    } else {
        dent->state |= DENTRY_PERSIST;
    }

    if (flag & AT_REMOVEDIR)
        dent->state &= ~DENTRY_ISDIRECTORY;

    dent->state |= DENTRY_NEGATIVE;
out_dent:
    put_dentry(dent);
out:
    put_dentry(dir);
    return ret;
}

int shim_do_mkdir(const char* pathname, int mode) {
    return open_namei(NULL, NULL, pathname, O_CREAT | O_EXCL | O_DIRECTORY, mode, NULL);
}

int shim_do_mkdirat(int dfd, const char* pathname, int mode) {
    if (!pathname)
        return -EINVAL;

    if (test_user_string(pathname))
        return -EFAULT;

    struct shim_dentry* dir = NULL;
    int ret = 0;

    if ((ret = get_dirfd_dentry(dfd, &dir)) < 0)
        return ret;

    ret = open_namei(NULL, dir, pathname, O_CREAT | O_EXCL | O_DIRECTORY, mode, NULL);

    put_dentry(dir);
    return ret;
}

int shim_do_rmdir(const char* pathname) {
    int ret = 0;
    struct shim_dentry* dent = NULL;

    if (!pathname)
        return -EINVAL;

    if (test_user_string(pathname))
        return -EFAULT;

    if ((ret = path_lookupat(NULL, pathname, LOOKUP_OPEN | LOOKUP_DIRECTORY, &dent, NULL)) < 0)
        return ret;

    if (!dent->parent) {
        ret = -EACCES;
        goto out;
    }

    if (!(dent->state & DENTRY_ISDIRECTORY)) {
        ret = -ENOTDIR;
        goto out;
    }

    if (dent->fs && dent->fs->d_ops && dent->fs->d_ops->unlink) {
        if ((ret = dent->fs->d_ops->unlink(dent->parent, dent)) < 0)
            goto out;
    } else {
        dent->state |= DENTRY_PERSIST;
    }

    dent->state &= ~DENTRY_ISDIRECTORY;
    dent->state |= DENTRY_NEGATIVE;
out:
    put_dentry(dent);
    return ret;
}

mode_t shim_do_umask(mode_t mask) {
    struct shim_thread* cur = get_cur_thread();
    lock(&cur->lock);
    mode_t old = cur->umask;
    cur->umask = mask & 0777;
    unlock(&cur->lock);
    return old;
}

int shim_do_chmod(const char* path, mode_t mode) {
    struct shim_dentry* dent = NULL;
    int ret = 0;

    if (test_user_string(path))
        return -EFAULT;

    if ((ret = path_lookupat(NULL, path, LOOKUP_OPEN, &dent, NULL)) < 0)
        return ret;

    if (dent->fs && dent->fs->d_ops && dent->fs->d_ops->chmod) {
        if ((ret = dent->fs->d_ops->chmod(dent, mode)) < 0)
            goto out;
    } else {
        dent->state |= DENTRY_PERSIST;
    }

    dent->mode = mode;
out:
    put_dentry(dent);
    return ret;
}

int shim_do_fchmodat(int dfd, const char* filename, mode_t mode) {
    if (!filename)
        return -EINVAL;

    if (test_user_string(filename))
        return -EFAULT;

    struct shim_dentry* dir = NULL;
    struct shim_dentry* dent = NULL;
    int ret = 0;

    if ((ret = get_dirfd_dentry(dfd, &dir)) < 0)
        return ret;

    if ((ret = path_lookupat(dir, filename, LOOKUP_OPEN, &dent, NULL)) < 0)
        goto out;

    if (dent->fs && dent->fs->d_ops && dent->fs->d_ops->chmod) {
        if ((ret = dent->fs->d_ops->chmod(dent, mode)) < 0)
            goto out_dent;
    } else {
        dent->state |= DENTRY_PERSIST;
    }

    dent->mode = mode;
out_dent:
    put_dentry(dent);
out:
    put_dentry(dir);
    return ret;
}

int shim_do_fchmod(int fd, mode_t mode) {
    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    struct shim_dentry* dent = hdl->dentry;
    int ret = 0;

    if (dent->fs && dent->fs->d_ops && dent->fs->d_ops->chmod) {
        if ((ret = dent->fs->d_ops->chmod(dent, mode)) < 0)
            goto out;
    } else {
        dent->state |= DENTRY_PERSIST;
    }

    dent->mode = mode;
out:
    put_handle(hdl);
    return ret;
}

int shim_do_chown(const char* path, uid_t uid, gid_t gid) {
    struct shim_dentry* dent = NULL;
    int ret = 0;
    __UNUSED(uid);
    __UNUSED(gid);

    if (!path)
        return -EINVAL;

    if (test_user_string(path))
        return -EFAULT;

    if ((ret = path_lookupat(NULL, path, LOOKUP_OPEN, &dent, NULL)) < 0)
        return ret;

    /* XXX: do nothing now */
    put_dentry(dent);
    return ret;
}

int shim_do_fchownat(int dfd, const char* filename, uid_t uid, gid_t gid, int flags) {
    __UNUSED(flags);
    __UNUSED(uid);
    __UNUSED(gid);

    if (!filename)
        return -EINVAL;

    if (test_user_string(filename))
        return -EFAULT;

    struct shim_dentry* dir = NULL;
    struct shim_dentry* dent = NULL;
    int ret = 0;

    if ((ret = get_dirfd_dentry(dfd, &dir)) < 0)
        return ret;

    if ((ret = path_lookupat(dir, filename, LOOKUP_OPEN, &dent, NULL)) < 0)
        goto out;

    /* XXX: do nothing now */
    put_dentry(dent);
out:
    put_dentry(dir);
    return ret;
}

int shim_do_fchown(int fd, uid_t uid, gid_t gid) {
    __UNUSED(uid);
    __UNUSED(gid);

    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    /* XXX: do nothing now */
    return 0;
}

#define MAP_SIZE (g_pal_alloc_align * 4)
#define BUF_SIZE 2048

static ssize_t handle_copy(struct shim_handle* hdli, off_t* offseti, struct shim_handle* hdlo,
                           off_t* offseto, ssize_t count) {
    struct shim_mount* fsi = hdli->fs;
    struct shim_mount* fso = hdlo->fs;

    if (!count)
        return 0;

    if (!fsi || !fsi->fs_ops || !fso || !fso->fs_ops)
        return -EACCES;

    bool do_mapi  = fsi->fs_ops->mmap != NULL;
    bool do_mapo  = fso->fs_ops->mmap != NULL;
    bool do_marki = false;
    bool do_marko = false;
    int offi = 0, offo = 0;

    if (offseti) {
        if (!fsi->fs_ops->seek)
            return -EACCES;
        offi = *offseti;
        fsi->fs_ops->seek(hdli, offi, SEEK_SET);
    } else {
        if (!fsi->fs_ops->seek || (offi = fsi->fs_ops->seek(hdli, 0, SEEK_CUR)) < 0)
            do_mapi = false;
    }

    if (offseto) {
        if (!fso->fs_ops->seek)
            return -EACCES;
        offo = *offseto;
        fso->fs_ops->seek(hdlo, offo, SEEK_SET);
    } else {
        if (!fso->fs_ops->seek || (offo = fso->fs_ops->seek(hdlo, 0, SEEK_CUR)) < 0)
            do_mapo = false;
    }

    if (do_mapi) {
        int size;
        if (fsi->fs_ops->poll && (size = fsi->fs_ops->poll(hdli, FS_POLL_SZ)) >= 0) {
            if (count == -1 || count > size - offi)
                count = size - offi;

            if (!count)
                return 0;
        } else {
            do_mapi = false;
        }
    }

    if (do_mapo && count > 0)
        do {
            int size;
            if (!fso->fs_ops->poll || (size = fso->fs_ops->poll(hdlo, FS_POLL_SZ)) < 0) {
                do_mapo = false;
                break;
            }

            if (offo + count < size)
                break;

            if (!fso->fs_ops->truncate || fso->fs_ops->truncate(hdlo, offo + count) < 0) {
                do_mapo = false;
                break;
            }
        } while (0);

    void* bufi = NULL;
    void* bufo = NULL;
    int bytes    = 0;
    int bufsize  = MAP_SIZE;
    int copysize = 0;

    if (!do_mapi && (hdli->flags & O_NONBLOCK) && fsi->fs_ops->setflags) {
        int ret = fsi->fs_ops->setflags(hdli, 0);
        if (!ret) {
            debug("mark handle %s as blocking\n", qstrgetstr(&hdli->uri));
            do_marki = true;
        }
    }

    if (!do_mapo && (hdlo->flags & O_NONBLOCK) && fso->fs_ops->setflags) {
        int ret = fso->fs_ops->setflags(hdlo, 0);
        if (!ret) {
            debug("mark handle %s as blocking\n", qstrgetstr(&hdlo->uri));
            do_marko = true;
        }
    }

    assert(count);
    do {
        int boffi = 0, boffo = 0;
        int expectsize = bufsize;

        if (count > 0 && bufsize > count - bytes)
            expectsize = bufsize = count - bytes;

        if (do_mapi && !bufi) {
            boffi = offi - ALLOC_ALIGN_DOWN(offi);

            if (fsi->fs_ops->mmap(hdli, &bufi, ALLOC_ALIGN_UP(bufsize + boffi), PROT_READ, MAP_FILE,
                                  offi - boffi) < 0) {
                do_mapi = false;
                boffi = 0;
                if ((hdli->flags & O_NONBLOCK) && fsi->fs_ops->setflags) {
                    int ret = fsi->fs_ops->setflags(hdli, 0);
                    if (!ret) {
                        debug("mark handle %s as blocking\n", qstrgetstr(&hdli->uri));
                        do_marki = true;
                    }
                }
                if (fsi->fs_ops->seek)
                    offi = fsi->fs_ops->seek(hdli, offi, SEEK_SET);
            }
        }

        if (do_mapo && !bufo) {
            boffo = offo - ALLOC_ALIGN_DOWN(offo);

            if (fso->fs_ops->mmap(hdlo, &bufo, ALLOC_ALIGN_UP(bufsize + boffo), PROT_WRITE,
                                  MAP_FILE, offo - boffo) < 0) {
                do_mapo = false;
                boffo = 0;
                if ((hdlo->flags & O_NONBLOCK) && fso->fs_ops->setflags) {
                    int ret = fso->fs_ops->setflags(hdlo, 0);
                    if (!ret) {
                        debug("mark handle %s as blocking\n", qstrgetstr(&hdlo->uri));
                        do_marko = true;
                    }
                }
                if (fso->fs_ops->seek)
                    offo = fso->fs_ops->seek(hdlo, offo, SEEK_SET);
            }
        }

        if (do_mapi && do_mapo) {
            copysize = count - bytes > bufsize ? bufsize : count - bytes;
            memcpy(bufo + boffo, bufi + boffi, copysize);
            DkVirtualMemoryFree(bufi, ALLOC_ALIGN_UP(bufsize + boffi));
            bufi = NULL;
            DkVirtualMemoryFree(bufo, ALLOC_ALIGN_UP(bufsize + boffo));
            bufo = NULL;
        } else if (do_mapo) {
            copysize = fsi->fs_ops->read(hdli, bufo + boffo, bufsize);
            DkVirtualMemoryFree(bufo, ALLOC_ALIGN_UP(bufsize + boffo));
            bufo = NULL;
            if (copysize < 0)
                break;
        } else if (do_mapi) {
            copysize = fso->fs_ops->write(hdlo, bufi + boffi, bufsize);
            DkVirtualMemoryFree(bufi, ALLOC_ALIGN_UP(bufsize + boffi));
            bufi = NULL;
            if (copysize < 0)
                break;
        } else {
            if (!bufi)
                bufi = __alloca((bufsize = (bufsize > BUF_SIZE) ? BUF_SIZE : bufsize));

            copysize = fsi->fs_ops->read(hdli, bufi, bufsize);

            if (copysize <= 0)
                break;

            expectsize = copysize;
            copysize = fso->fs_ops->write(hdlo, bufi, expectsize);
            if (copysize < 0)
                break;
        }

        debug("copy %d bytes\n", copysize);
        bytes += copysize;
        offi += copysize;
        offo += copysize;
        if (copysize < expectsize)
            break;
    } while (bytes < count);

    if (copysize < 0 || (count > 0 && bytes < count)) {
        int ret = copysize < 0 ? copysize : -EAGAIN;

        if (bytes) {
            if (fsi->fs_ops->seek)
                fsi->fs_ops->seek(hdli, offi - bytes, SEEK_SET);
            if (fso->fs_ops->seek)
                fso->fs_ops->seek(hdlo, offo - bytes, SEEK_SET);
        }

        return ret;
    }

    if (do_marki && (hdli->flags & O_NONBLOCK)) {
        debug("mark handle %s as nonblocking\n", qstrgetstr(&hdli->uri));
        fsi->fs_ops->setflags(hdli, O_NONBLOCK);
    }

    if (do_marko && (hdlo->flags & O_NONBLOCK)) {
        debug("mark handle %s as nonblocking\n", qstrgetstr(&hdlo->uri));
        fso->fs_ops->setflags(hdlo, O_NONBLOCK);
    }

    if (do_mapi) {
        if (fsi->fs_ops->seek)
            fsi->fs_ops->seek(hdli, offi, SEEK_SET);
    }

    if (offseti)
        *offseti = offi;

    if (do_mapo) {
        if (fso->fs_ops->seek)
            fso->fs_ops->seek(hdlo, offo, SEEK_SET);
    }

    if (offseto)
        *offseto = offo;

    return bytes;
}

static int do_rename(struct shim_dentry* old_dent, struct shim_dentry* new_dent) {
    if ((old_dent->type != S_IFREG) ||
            (!(new_dent->state & DENTRY_NEGATIVE) && (new_dent->type != S_IFREG))) {
        /* Current implementation of fs does not allow for renaming anything but regular files */
        return -ENOSYS;
    }

    if (old_dent->fs != new_dent->fs) {
        /* Disallow cross mount renames */
        return -EXDEV;
    }

    if (!old_dent->fs || !old_dent->fs->d_ops || !old_dent->fs->d_ops->rename) {
        return -EPERM;
    }

    if (old_dent->state & DENTRY_ISDIRECTORY) {
        if (!(new_dent->state & DENTRY_NEGATIVE)) {
            if (!(new_dent->state & DENTRY_ISDIRECTORY)) {
                return -ENOTDIR;
            }
            if (new_dent->nchildren > 0) {
                return -ENOTEMPTY;
            }
        } else {
            /* destination is a negative dentry and needs to be marked as a directory, since source
             * is a directory */
            new_dent->state |= DENTRY_ISDIRECTORY;
        }
    } else if (new_dent->state & DENTRY_ISDIRECTORY) {
        return -EISDIR;
    }

    if (dentry_is_ancestor(old_dent, new_dent) || dentry_is_ancestor(new_dent, old_dent)) {
        return -EINVAL;
    }

    /* TODO: Add appropriate checks for hardlinks once they get implemented. */

    int ret = old_dent->fs->d_ops->rename(old_dent, new_dent);
    if (!ret) {
        old_dent->state |= DENTRY_NEGATIVE;
        new_dent->state &= ~DENTRY_NEGATIVE;
    }

    return ret;
}

int shim_do_rename(const char* oldpath, const char* newpath) {
    return shim_do_renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath);
}

int shim_do_renameat(int olddirfd, const char* oldpath, int newdirfd, const char* newpath) {
    struct shim_dentry* old_dir_dent = NULL;
    struct shim_dentry* old_dent     = NULL;
    struct shim_dentry* new_dir_dent = NULL;
    struct shim_dentry* new_dent     = NULL;
    int ret = 0;

    if (!oldpath || test_user_string(oldpath) || !newpath || test_user_string(newpath)) {
        return -EFAULT;
    }

    if ((ret = get_dirfd_dentry(olddirfd, &old_dir_dent)) < 0) {
        goto out;
    }

    if ((ret = path_lookupat(old_dir_dent, oldpath, LOOKUP_OPEN, &old_dent, NULL)) < 0) {
        goto out;
    }

    if (old_dent->state & DENTRY_NEGATIVE) {
        ret = -ENOENT;
        goto out;
    }

    if ((ret = get_dirfd_dentry(newdirfd, &new_dir_dent)) < 0) {
        goto out;
    }

    ret = path_lookupat(new_dir_dent, newpath, LOOKUP_OPEN | LOOKUP_CREATE, &new_dent, NULL);
    if (ret < 0) {
        if (ret != -ENOENT || !new_dent ||
            (new_dent->state & (DENTRY_NEGATIVE | DENTRY_VALID)) !=
                (DENTRY_NEGATIVE | DENTRY_VALID)) {
            goto out;
        }
    }

    // Both dentries should have a ref count of at least 2 at this point
    assert(REF_GET(old_dent->ref_count) >= 2);
    assert(REF_GET(new_dent->ref_count) >= 2);

    ret = do_rename(old_dent, new_dent);

out:
    if (old_dir_dent)
        put_dentry(old_dir_dent);
    if (old_dent)
        put_dentry(old_dent);
    if (new_dir_dent)
        put_dentry(new_dir_dent);
    if (new_dent)
        put_dentry(new_dent);
    return ret;
}

ssize_t shim_do_sendfile(int ofd, int ifd, off_t* offset, size_t count) {
    struct shim_handle* hdli = get_fd_handle(ifd, NULL, NULL);
    struct shim_handle* hdlo = get_fd_handle(ofd, NULL, NULL);

    if (!hdli || !hdlo)
        return -EBADF;

    off_t old_offset = 0;
    int ret = -EACCES;

    if (offset) {
        if (!hdli->fs || !hdli->fs->fs_ops || !hdli->fs->fs_ops->seek)
            goto out;

        old_offset = hdli->fs->fs_ops->seek(hdli, 0, SEEK_CUR);
        if (old_offset < 0) {
            ret = old_offset;
            goto out;
        }
    }

    ret = handle_copy(hdli, offset, hdlo, NULL, count);

    if (ret >= 0 && offset)
        hdli->fs->fs_ops->seek(hdli, old_offset, SEEK_SET);

out:
    put_handle(hdli);
    put_handle(hdlo);
    return ret;
}

int shim_do_chroot(const char* filename) {
    int ret = 0;
    struct shim_dentry* dent = NULL;
    if ((ret = path_lookupat(NULL, filename, 0, &dent, NULL)) < 0)
        goto out;

    if (!dent) {
        ret = -ENOENT;
        goto out;
    }

    struct shim_thread* thread = get_cur_thread();
    lock(&thread->lock);
    put_dentry(thread->root);
    thread->root = dent;
    unlock(&thread->lock);
out:
    return ret;
}
