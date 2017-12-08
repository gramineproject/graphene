/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

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
 * shim_fs.h
 *
 * Definitions of types and functions for file system bookkeeping.
 */

#ifndef _SHIM_FS_H_
#define _SHIM_FS_H_

#include <shim_types.h>
#include <shim_defs.h>
#include <shim_handle.h>
#include <shim_utils.h>

#include <pal.h>
#include <list.h>

struct shim_handle;

#define FS_POLL_RD         0x01
#define FS_POLL_WR         0x02
#define FS_POLL_ER         0x04
#define FS_POLL_SZ         0x08

struct shim_fs_ops {
    /* mount: moun an uri to the certain location */
    int (*mount) (const char * uri, const char * root, void ** mount_data);
    int (*unmount) (void * mount_data);

    /* close: clean up the file state inside the handle */
    int (*close) (struct shim_handle * hdl);

    /* read: the content from the file opened as handle */
    int (*read) (struct shim_handle * hdl, void * buf, size_t count);

    /* write: the content from the file opened as handle */
    int (*write) (struct shim_handle * hdl, const void * buf, size_t count);

    /* mmap: mmap handle to address */
    int (*mmap) (struct shim_handle * hdl, void ** addr, size_t size,
                 int prot, int flags, off_t offset);

    /* flush: flush out user buffer */
    int (*flush) (struct shim_handle * hdl);

    /* seek: the content from the file opened as handle */
    int (*seek) (struct shim_handle * hdl, off_t offset, int wence);

    /* move, copy: rename or duplicate the file */
    int (*move) (const char * trim_old_name, const char * trim_new_name);
    int (*copy) (const char * trim_old_name, const char * trim_new_name);

    int (*truncate) (struct shim_handle * hdl, uint64_t len);

    /* hstat: get status of the file */
    int (*hstat) (struct shim_handle * hdl, struct stat * buf);

    /* setflags: set flags of the file */
    int (*setflags) (struct shim_handle * hdl, int flags);

    /* hput: delete the handle and close the PAL handle. */
    void (*hput) (struct shim_handle * hdl);

    /* lock and unlock the file */
    int (*lock) (const char * trim_name);
    int (*unlock) (const char * trim_name);

    /* lock and unlock the file system */
    int (*lockfs) (void);
    int (*unlockfs) (void);

    /* checkout/reowned/checkin a single handle for migration */
    int (*checkout) (struct shim_handle * hdl);
    int (*checkin) (struct shim_handle * hdl);

    /* poll a single handle */
    /* POLL_RD|POLL_WR: return POLL_RD|POLL_WR for readable|writeable,
       POLL_ER for failure, -EAGAIN for unknown. */
    /* POLL_SZ: return total size */
    int (*poll) (struct shim_handle * hdl, int poll_type);

    /* checkpoint/migrate the filesystem */
    int (*checkpoint) (void ** checkpoint, void * mount_data);
    int (*migrate) (void * checkpoint, void ** mount_data);
};

#define DENTRY_VALID        0x0001  /* this dentry is verified to be valid */
#define DENTRY_NEGATIVE     0x0002  /* negative, recently deleted */
#define DENTRY_RECENTLY     0x0004  /* recently used */
#define DENTRY_PERSIST      0x0008  /* added as a persistent dentry */
#define DENTRY_HASHED       0x0010  /* added in the dcache */
#define DENTRY_MOUNTPOINT   0x0040  /* this dentry is a mount point */
#define DENTRY_ISLINK       0x0080  /* this dentry is a link */
#define DENTRY_ISDIRECTORY  0x0100  /* this dentry is a directory */
#define DENTRY_LOCKED       0x0200  /* locked by mountpoints at children */
/* These flags are not used */
//#define DENTRY_REACHABLE    0x0400  /* permission checked to be reachable */
//#define DENTRY_UNREACHABLE  0x0800  /* permission checked to be unreachable */
#define DENTRY_LISTED       0x1000  /* children in directory listed */
#define DENTRY_INO_UPDATED  0x2000  /* ino updated */
#define DENTRY_ANCESTOR     0x4000 /* Auto-generated dentry to connect a mount
                                    * point in the manifest to the root, when
                                    * one or more intermediate directories do
                                    * not exist on the underlying FS. The
                                    * semantics of subsequent changes to such
                                    * directories (or attempts to really
                                    * create them) are not currently
                                    * well-defined. */

// Catch memory corruption issues by checking for invalid state values
#define DENTRY_INVALID_FLAGS ~0x7FFF

#define DCACHE_HASH_SIZE    1024
#define DCACHE_HASH(hash) ((hash) & (DCACHE_HASH_SIZE - 1))

DEFINE_LIST(shim_dentry);
DEFINE_LISTP(shim_dentry);
struct shim_dentry {
    int state;  /* flags for managing state */

    struct shim_mount * fs;         /* this dentry's mounted fs */
    struct shim_qstr rel_path;      /* the path is relative to
                                       its mount point */
    struct shim_qstr name;          /* caching the file's name. */


    /* DEP 6/16/17: For now, let's try not hashing; I suspect it is 
     * overkill for most purposes.  I'll leave the field here for now,
     * but propose we move to a per-directory table to accelerate lookups,
     * rather than a global table, since this just supports one process.
     */
    LIST_TYPE(shim_dentry) hlist;    /* to resolve collisions in
                                       the hash table */
    LIST_TYPE(shim_dentry) list;     /* put dentry to different list
                                       according to its availability,
                                       persistent or freeable */

    struct shim_dentry * parent;
    int nchildren;
    LISTP_TYPE(shim_dentry) children; /* These children and siblings link */
    LIST_TYPE(shim_dentry) siblings;

    struct shim_mount * mounted;
    void * data;
    unsigned long ino;
    mode_t type;
    mode_t mode;

    LOCKTYPE lock;
    REFTYPE ref_count;
};

struct shim_d_ops {
    /* open: provide a filename relative to the mount point and flags,
       modify the shim handle, file_data is "inode" equivalent */
    int (*open) (struct shim_handle * hdl, struct shim_dentry * dent,
                 int flags);

    /* look up dentry and allocate internal data.
     * 
     * On a successful lookup  (non-error, can be negative),
     * this function should call get_new_dentry(), populating additional fields,
     * and storing the new dentry in dent.
     * 
     * Maybe drop force?
     */
    int (*lookup) (struct shim_dentry * dent, bool force);
    
    /* this is to check file type and access, returning the stat.st_mode */
    int (*mode) (struct shim_dentry * dent, mode_t * mode, bool force);

    /* detach internal data from dentry */
    int (*dput) (struct shim_dentry * dent);

    /* create a dentry inside a directory */
    int (*creat) (struct shim_handle * hdl, struct shim_dentry * dir,
                  struct shim_dentry * dent, int flags, mode_t mode);

    /* unlink a dentry inside a directory */
    int (*unlink) (struct shim_dentry * dir, struct shim_dentry * dent);

    /* create a directory inside a directory */
    int (*mkdir) (struct shim_dentry * dir, struct shim_dentry * dent,
                  mode_t mode);

    /* stat: get status of the file */
    int (*stat) (struct shim_dentry * dent, struct stat * buf);

    /* extracts the symlink name and saves in link */
    int (*follow_link) (struct shim_dentry * dent, struct shim_qstr * link);
    /* set up symlink name to a dentry */
    int (*set_link) (struct shim_dentry * dent, const char * link);

    /* change the mode or owner of a dentry */
    int (*chmod) (struct shim_dentry * dent, mode_t mode);
    int (*chown) (struct shim_dentry * dent, int uid, int gid);

    /* change the name of a dentry */
    int (*rename) (struct shim_dentry * old, struct shim_dentry * new);

    /* readdir: given the path relative to the mount point, read the childs
       into the the buffer.  This call always returns everything under
       the directory in one big buffer; you do not need to try again
       or keep a cursor in the directory.  You do need to free the 
       returned buffer. */
    int (*readdir) (struct shim_dentry * dent, struct shim_dirent ** dirent);
};

#define MAX_PATH        4096

DEFINE_LIST(shim_mount);
struct shim_mount {
    char type[8];

    struct shim_dentry * mount_point;

    struct shim_qstr path;
    struct shim_qstr uri;

    struct shim_fs_ops * fs_ops;
    struct shim_d_ops * d_ops;

    struct shim_dentry * root;

    void * data;

    void * cpdata;
    size_t cpsize;

    REFTYPE ref_count;
    LIST_TYPE(shim_mount) hlist;
    LIST_TYPE(shim_mount) list;
};

extern struct shim_dentry * dentry_root;

#define LOOKUP_FOLLOW            001
#define LOOKUP_DIRECTORY         002
#define LOOKUP_CONTINUE          004 // No longer needed
#define LOOKUP_PARENT            010 // Not sure we need this

#define F_OK          0
// XXX: Duplicate definition; should probably weed out includes of host system
//include of unistd.h in future work
//#define R_OK        001
//#define W_OK        002
//#define X_OK        004
#define MAY_EXEC    001
#define MAY_WRITE   002
#define MAY_READ    004
#if 0
#define MAY_APPEND  010
#endif

#define NO_MODE     ((mode_t) -1)

#define ACC_MODE(x) ((((x) == O_RDONLY || (x) == O_RDWR) ? MAY_READ : 0) | \
                     (((x) == O_WRONLY || (x) == O_RDWR) ? MAY_WRITE : 0))

#define LOOKUP_OPEN             0100 // Appears to be ignored
#define LOOKUP_CREATE           0200 
#define LOOKUP_ACCESS           0400 // Appears to be ignored
#define LOOKUP_SYNC     (LOOKUP_OPEN|LOOKUP_CREATE|LOOKUP_ACCESS)

enum lookup_type {
    LAST_NORM,
    LAST_ROOT,
    LAST_DOT,
    LAST_DOTDOT,
    LAST_BIND
};

struct lookup {
    struct shim_dentry * dentry;
    struct shim_mount * mount;
    const char * last;
    int depth;
    int flags;
    enum lookup_type last_type;
};


/* initialization for fs and mounts */
int init_fs (void);
int init_mount_root (void);
int init_mount (void);

/* path utilities */
const char * get_file_name (const char * path, size_t len);

/* file system operations */
int mount_fs (const char * mount_type, const char * mount_uri,
              const char * mount_point, struct shim_dentry *parent,
              struct shim_dentry **dentp, int make_ancestor);
int unmount_fs (const char * mount_point);
int search_builtin_fs (const char * type, struct shim_mount ** fs);

void get_mount (struct shim_mount * mount);
void put_mount (struct shim_mount * mount);

struct shim_mount * find_mount_from_uri (const char * uri);

#include <shim_utils.h>

static inline void set_handle_fs (struct shim_handle * hdl,
                                  struct shim_mount * fs)
{
    get_mount(fs);
    hdl->fs = fs;
    memcpy(hdl->fs_type, fs->type, sizeof(hdl->fs_type));
}

int walk_mounts (int (*walk) (struct shim_mount * mount, void * arg),
                 void * arg);

/* functions for dcache supports */
int init_dcache (void);

extern LOCKTYPE dcache_lock;

/* check permission (specified by mask) of a dentry. If force is not set,
 * permission is considered granted on invalid dentries */
/* Assume caller has acquired dcache_lock */
int permission (struct shim_dentry * dent, int mask, bool force);

/* This function looks up a single dentry based on its parent dentry pointer
 * and the name.  Namelen is the length of char * name.
 * The dentry is returned in pointer *new.
 * 
 * The force flag causes the libOS to query the underlying file system for the
 * existence of the dentry, whereas without force, a negative dentry is
 * treated as definitive.  In some cases, this can be elided as an
 * optimization.
 * 
 * The caller should hold the dcache_lock.
 */
int lookup_dentry (struct shim_dentry * parent, const char * name, int namelen,
                   bool force, struct shim_dentry ** new, struct shim_mount * fs);

/* Looks up path under start dentry.  Saves in dent.
 * 
 * Assumes dcache_lock is held; main difference from path_lookupat is that
 * dcache_lock is not released on return.
 * 
 * The refcount is dropped by one on the returned dentry.
 * 
 * The make_ancestor flag creates pseudo-dentries for any parent paths that
 * are not in cache and do not exist on the underlying file system.  This is
 * intended for use only in setting up the file system view specified in the manifest.
 *
 * If the file isnt' found, returns -ENOENT.
 * 
 * If the LOOKUP_DIRECTORY flag is set, and the found file isn't a directory, 
 *  returns -ENOTDIR.
 */
int __path_lookupat (struct shim_dentry * start, const char * path, int flags,
                     struct shim_dentry ** dent, int link_depth,
                     struct shim_mount *fs, int make_ancestor);

/* Just wraps __path_lookupat, but also acquires and releases the dcache_lock.
 */
int path_lookupat (struct shim_dentry * start, const char * name, int flags,
                   struct shim_dentry ** dent, struct shim_mount *fs);

/* This function initializes dir to before a search, to either point
 * to the current working directory (if dfd == AT_FDCWD), or to the handle pointed to by dfd,
 * depending on the argument.  
 * 
 * Returns -EBADF if dfd is <0 or not a valid handle. 
 * Returns -ENOTDIR if dfd is not a directory.
 */
int path_startat (int dfd, struct shim_dentry ** dir);

/* Open path with given flags, in mode, similar to Unix open.
 * 
 * The start dentry specifies where to begin the search.
 * hdl is an optional argument; if passed in, it is initialized to 
 *   refer to the opened path.
 * 
 * The result is stored in dent.
 */

int open_namei (struct shim_handle * hdl, struct shim_dentry * start,
                const char * path, int flags, int mode,
                struct shim_dentry ** dent);

/* This function calls the low-level file system to do the work
 * of opening file indicated by dent, and initializing it in hdl.
 * Flags are standard open flags.
 *
 * If O_TRUNC is specified, this function is responsible for calling
 * the underlying truncate function.
 */

int dentry_open (struct shim_handle * hdl, struct shim_dentry * dent,
                 int flags);

/* This function enumerates a directory and caches the results in the dentry.
 * 
 * Input: A dentry for a directory in the DENTRY_ISDIRECTORY and not in the
 * DENTRY_LISTED state.  The dentry DENTRY_LISTED flag is set upon success.
 * 
 * Return value: 0 on success, <0 on error
 */
int list_directory_dentry (struct shim_dentry *dir);

/* This function caches the contents of a directory (dent), already
 * in the listed state, in a buffer associated with a handle (hdl).
 * 
 * This function should only be called once on a handle.
 * 
 * Returns 0 on success, <0 on failure.
 */
int list_directory_handle (struct shim_dentry *dent, struct shim_handle *hdl );


/* Increment the reference count on dent */
void get_dentry (struct shim_dentry * dent);
/* Decrement the reference count on dent */
void put_dentry (struct shim_dentry * dent);

static_inline
void fast_pathcpy (char * dst, const char * src, int size, char ** ptr)
{
    char * d = dst;
    const char * s = src;
    for (int i = 0 ; i < size ; i++, s++, d++)
        *d = *s;
    *ptr = d;
}

static_inline
char * dentry_get_path (struct shim_dentry * dent, bool on_stack,
                        int * sizeptr)
{
    struct shim_mount * fs = dent->fs;
    char * buffer, * c;
    int bufsize = dent->rel_path.len + 1;

    if (fs)
        bufsize += fs->path.len + 1;

    if (on_stack) {
        c = buffer = __alloca(bufsize);
    } else {
        if (!(c = buffer = malloc(bufsize)))
            return NULL;
    }

    if (fs && !qstrempty(&fs->path))
        fast_pathcpy(c, qstrgetstr(&fs->path), fs->path.len, &c);

    if (dent->rel_path.len) {
        const char * path = qstrgetstr(&dent->rel_path);
        int len = dent->rel_path.len;

        if (c > buffer && *(c - 1) == '/') {
            if (*path == '/')
                path++;
        } else {
            if (*path != '/')
                *(c++) = '/';
        }

        fast_pathcpy(c, path, len, &c);
    }

    if (sizeptr)
        *sizeptr = c - buffer;

    *c = 0;
    return buffer;
}

static inline __attribute__((always_inline))
const char * dentry_get_name (struct shim_dentry * dent)
{
    return qstrgetstr(&dent->name);
}

/* Allocate and initialize a new dentry for path name, under
 * parent.  Return the dentry.  
 * 
 * mount is the mountpoint the dentry is under; this is typically
 * the parent->fs, but is passed explicitly for initializing 
 * the dentry of a mountpoint.
 * 
 * If hashptr is passed (as an optimization), this is a hash
 * of the name.
 * 
 * If parent is non-null, the ref count is 1; else it is zero.
 * 
 * This function also sets up both a name and a relative path
 */
struct shim_dentry * get_new_dentry (struct shim_mount *mount,
                                     struct shim_dentry * parent,
                                     const char * name, int namelen,
                                     HASHTYPE * hashptr);

/* This function searches for name/namelen (as the relative path; 
 * path/pathlen is the fully-qualified path), 
 * under parent dentry (start).
 * 
 * If requested, the expected hash of the dentry is returned in hashptr,
 * primarily so that the hashing can be reused to add the dentry later.
 * 
 * The reference count on the found dentry is incremented by one.
 *
 * Used only by shim_namei.c 
 */
struct shim_dentry *
__lookup_dcache (struct shim_dentry * start, const char * name, int namelen,
                 const char * path, int pathlen, HASHTYPE * hashptr);

/* This function recursively deletes and frees all dentries under root 
 * 
 * XXX: Current code doesn't do a free..
 */
int __del_dentry_tree(struct shim_dentry * root);

/* XXX: Future work: current dcache never shrinks.  Would be nice 
 * to be able to do something like LRU under space pressure, although
 * for a single app, this may be over-kill. */

/* hashing utilities */
#define MOUNT_HASH_BYTE     1
#define MOUNT_HASH_WIDTH    8
#define MOUNT_HASH_SIZE     256

#define MOUNT_HASH(hash) ((hash) & (MOUNT_HASH_SIZE - 1))

HASHTYPE hash_path (const char * path, int size,
                    const char * sep);
HASHTYPE hash_parent_path (HASHTYPE hbuf, const char * name,
                           int * size, const char * sep);
HASHTYPE rehash_name (HASHTYPE parent_hbuf,
                      const char * name, int size);
HASHTYPE rehash_path (HASHTYPE ancester_hbuf,
                      const char * path, int size, const char * sep);

extern struct shim_fs_ops chroot_fs_ops;
extern struct shim_d_ops  chroot_d_ops;

extern struct shim_fs_ops str_fs_ops;
extern struct shim_d_ops  str_d_ops;

extern struct shim_fs_ops dev_fs_ops;
extern struct shim_d_ops  dev_d_ops;

extern struct shim_fs_ops config_fs_ops;
extern struct shim_d_ops  config_d_ops;

extern struct shim_fs_ops proc_fs_ops;
extern struct shim_d_ops  proc_d_ops;

extern struct shim_mount chroot_builtin_fs;
extern struct shim_mount pipe_builtin_fs;
extern struct shim_mount socket_builtin_fs;
extern struct shim_mount epoll_builtin_fs;

/* proc file system */
struct proc_nm_ops {
    int (*match_name) (const char * name);
    int (*list_name) (const char * name, struct shim_dirent ** buf,
                      int count);
};

struct proc_fs_ops {
    int (*open) (struct shim_handle * hdl, const char * name, int flags);
    int (*mode) (const char * name, mode_t * mode);
    int (*stat) (const char * name, struct stat * buf);
    int (*follow_link) (const char * name, struct shim_qstr * link);
};

struct proc_dir;

struct proc_ent {
    const char * name;                      /* a proc_callback should at least
                                               have a name or nm_ops.
                                               Otherwise, it is a NULL-end. */
    const struct proc_nm_ops * nm_ops;
    const struct proc_fs_ops * fs_ops;
    const struct proc_dir * dir;
};

struct proc_dir {
    int size;
    const struct proc_ent ent[];
};

/* string-type file system */
int str_add_dir (const char * path, mode_t mode, struct shim_dentry ** dent);
int str_add_file (const char * path, mode_t mode, struct shim_dentry ** dent);
int str_open (struct shim_handle * hdl, struct shim_dentry * dent, int flags);
int str_dput (struct shim_dentry * dent);
int str_close (struct shim_handle * hdl);
int str_read (struct shim_handle * hdl, void * buf, size_t count);
int str_write (struct shim_handle * hdl, const void * buf, size_t count);
int str_seek (struct shim_handle * hdl, off_t offset, int whence);
int str_flush (struct shim_handle * hdl);

#endif /* _SHIM_FS_H_ */
