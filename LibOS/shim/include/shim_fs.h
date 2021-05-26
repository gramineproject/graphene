/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Definitions of types and functions for file system bookkeeping.
 */

#ifndef _SHIM_FS_H_
#define _SHIM_FS_H_

#include <asm/stat.h>
#include <stdbool.h>
#include <stdint.h>

#include "list.h"
#include "pal.h"
#include "shim_defs.h"
#include "shim_handle.h"
#include "shim_types.h"
#include "shim_utils.h"

struct shim_handle;

#define FS_POLL_RD 0x01
#define FS_POLL_WR 0x02
#define FS_POLL_ER 0x04
#define FS_POLL_SZ 0x08

struct shim_fs_ops {
    /* mount: mount an uri to the certain location */
    int (*mount)(const char* uri, void** mount_data);
    int (*unmount)(void* mount_data);

    /* close: clean up the file state inside the handle */
    int (*close)(struct shim_handle* hdl);

    /* read: the content from the file opened as handle */
    ssize_t (*read)(struct shim_handle* hdl, void* buf, size_t count);

    /* write: the content from the file opened as handle */
    ssize_t (*write)(struct shim_handle* hdl, const void* buf, size_t count);

    /* mmap: mmap handle to address */
    int (*mmap)(struct shim_handle* hdl, void** addr, size_t size, int prot, int flags,
                uint64_t offset);

    /* flush: flush out user buffer */
    int (*flush)(struct shim_handle* hdl);

    /* seek: the content from the file opened as handle */
    off_t (*seek)(struct shim_handle* hdl, off_t offset, int whence);

    /* move, copy: rename or duplicate the file */
    int (*move)(const char* trim_old_name, const char* trim_new_name);
    int (*copy)(const char* trim_old_name, const char* trim_new_name);

    /* Returns 0 on success, -errno on error */
    int (*truncate)(struct shim_handle* hdl, off_t len);

    /* hstat: get status of the file; `st_ino` will be taken from dentry, if there's one */
    int (*hstat)(struct shim_handle* hdl, struct stat* buf);

    /* setflags: set flags of the file */
    int (*setflags)(struct shim_handle* hdl, int flags);

    /* hput: delete the handle and close the PAL handle. */
    void (*hput)(struct shim_handle* hdl);

    /* lock and unlock the file */
    int (*lock)(const char* trim_name);
    int (*unlock)(const char* trim_name);

    /* lock and unlock the file system */
    int (*lockfs)(void);
    int (*unlockfs)(void);

    /* checkout/reowned/checkin a single handle for migration */
    int (*checkout)(struct shim_handle* hdl);
    int (*checkin)(struct shim_handle* hdl);

    /* poll a single handle */
    /* POLL_RD|POLL_WR: return POLL_RD|POLL_WR for readable|writable,
       POLL_ER for failure, -EAGAIN for unknown. */
    /* POLL_SZ: return total size */
    off_t (*poll)(struct shim_handle* hdl, int poll_type);

    /* checkpoint/migrate the file system */
    ssize_t (*checkpoint)(void** checkpoint, void* mount_data);
    int (*migrate)(void* checkpoint, void** mount_data);
};

#define DENTRY_VALID       0x0001 /* this dentry is verified to be valid */
#define DENTRY_NEGATIVE    0x0002 /* recently deleted or inaccessible */
#define DENTRY_RECENTLY    0x0004 /* recently used */
#define DENTRY_PERSIST     0x0008 /* added as a persistent dentry */
#define DENTRY_MOUNTPOINT  0x0040 /* this dentry is a mount point */
#define DENTRY_ISLINK      0x0080 /* this dentry is a link */
#define DENTRY_ISDIRECTORY 0x0100 /* this dentry is a directory */
#define DENTRY_LOCKED      0x0200 /* locked by mountpoints at children */
/* These flags are not used */
//#define DENTRY_REACHABLE    0x0400  /* permission checked to be reachable */
//#define DENTRY_UNREACHABLE  0x0800  /* permission checked to be unreachable */
#define DENTRY_LISTED      0x1000 /* children in directory listed */
#define DENTRY_SYNTHETIC   0x4000 /* Auto-generated dentry to connect a mount point in the        \
                                   * manifest to the root, when one or more intermediate          \
                                   * directories do not exist on the underlying FS. The semantics \
                                   * of subsequent changes to such directories (or attempts to    \
                                   * really create them) are not currently well-defined. */

// Catch memory corruption issues by checking for invalid state values
#define DENTRY_INVALID_FLAGS (~0x7FFF)

#define DCACHE_HASH_SIZE  1024
#define DCACHE_HASH(hash) ((hash) & (DCACHE_HASH_SIZE - 1))

/* Limit for the number of dentry children. This is mostly to prevent overflow if (untrusted) host
 * pretends to have many files in a directory. */
#define DENTRY_MAX_CHILDREN 1000000

DEFINE_LIST(shim_dentry);
DEFINE_LISTP(shim_dentry);
struct shim_dentry {
    int state; /* flags for managing state */

    /* File name, maximum of NAME_MAX characters. By convention, the root has an empty name. */
    struct shim_qstr name;

    /* Mounted filesystem this dentry belongs to */
    struct shim_mount* mount;

    /* Filesystem to use for operations on this file: this is usually `mount->fs`, but can be
     * different in case of special files (such as named pipes or sockets). */
    struct shim_fs* fs;

    struct shim_dentry* parent;
    size_t nchildren;
    LISTP_TYPE(shim_dentry) children; /* These children and siblings link */
    LIST_TYPE(shim_dentry) siblings;

    struct shim_mount* mounted;

    /* file type: S_IFREG, S_IFDIR, S_IFLNK etc. */
    mode_t type;

    /* file permissions: PERM_rwxrwxrwx, etc. */
    mode_t perm;

    void* data;

    struct shim_lock lock;
    REFTYPE ref_count;
};

typedef int (*readdir_callback_t)(const char* name, void* arg);

struct shim_d_ops {
    /* open: provide a filename relative to the mount point and flags,
       modify the shim handle, file_data is "inode" equivalent */
    int (*open)(struct shim_handle* hdl, struct shim_dentry* dent, int flags);

    /* look up dentry and allocate internal data.
     *
     * On a successful lookup  (non-error, can be negative),
     * this function should call get_new_dentry(), populating additional fields,
     * and storing the new dentry in dent.
     */
    int (*lookup)(struct shim_dentry* dent);

    /* this is to check file type and access, returning the stat.st_mode */
    int (*mode)(struct shim_dentry* dent, mode_t* mode);

    /* detach internal data from dentry */
    int (*dput)(struct shim_dentry* dent);

    /* create a dentry inside a directory */
    int (*creat)(struct shim_handle* hdl, struct shim_dentry* dir, struct shim_dentry* dent,
                 int flags, mode_t mode);

    /* unlink a dentry inside a directory */
    int (*unlink)(struct shim_dentry* dir, struct shim_dentry* dent);

    /* create a directory inside a directory */
    int (*mkdir)(struct shim_dentry* dir, struct shim_dentry* dent, mode_t mode);

    /* stat: get status of the file; `st_ino` will be taken from dentry */
    int (*stat)(struct shim_dentry* dent, struct stat* buf);

    /* extracts the symlink name and saves in link */
    int (*follow_link)(struct shim_dentry* dent, struct shim_qstr* link);
    /* set up symlink name to a dentry */
    int (*set_link)(struct shim_dentry* dent, const char* link);

    /* change the mode or owner of a file; the caller has to update dentry */
    int (*chmod)(struct shim_dentry* dent, mode_t mode);
    int (*chown)(struct shim_dentry* dent, int uid, int gid);

    /* change the name of a dentry */
    int (*rename)(struct shim_dentry* old, struct shim_dentry* new);

    /*!
     * \brief List all files in the directory
     *
     * \param dentry the dentry, must be valid, non-negative and describing a directory
     * \param callback the callback to invoke on each file name
     * \param arg argument to pass to the callback
     *
     * Calls `callback(name, arg)` for all file names in the directory. `name` is not guaranteed to
     * be valid after callback returns, so the callback should copy it if necessary.
     *
     * `arg` can be used to pass additional data to the callback, e.g. a list to add a name to.
     *
     * If the callback returns a negative error code, it's interpreted as a failure and `readdir`
     * stops, returning the same error code.
     */
    int (*readdir)(struct shim_dentry* dent, readdir_callback_t callback, void* arg);
};

/*
 * Limits for path and filename length, as defined in Linux. Note that, same as Linux, PATH_MAX only
 * applies to paths processed by syscalls such as getcwd() - there is no limit on paths you can
 * open().
 */
#define NAME_MAX 255   /* filename length, NOT including null terminator */
#define PATH_MAX 4096  /* path size, including null terminator */

struct shim_fs {
    /* Null-terminated, used in manifest and for uniquely identifying a filesystem. */
    char name[8];
    struct shim_fs_ops* fs_ops;
    struct shim_d_ops* d_ops;
};

DEFINE_LIST(shim_mount);
struct shim_mount {
    struct shim_fs* fs;

    /*
     * TODO: this field currently functions as both the mountpoint AND the mount root. Instead,
     * `mount_point` should be the dentry from the parent filesystem, and `root` should be the mount
     * root.
     */
    struct shim_dentry* mount_point;

    struct shim_qstr path;
    struct shim_qstr uri;

    /* TODO: this is unused right now (see `mount_point`) */
    struct shim_dentry* root;

    void* data;

    void* cpdata;
    size_t cpsize;

    REFTYPE ref_count;
    LIST_TYPE(shim_mount) hlist;
    LIST_TYPE(shim_mount) list;
};

/* TODO: This actually does not get migrated after a fork. We migrate `g_process.root`, which is
 * enough for Graphene to function, but leaves `g_dentry_root` in child process pointing to an empty
 * directory. */
extern struct shim_dentry* g_dentry_root;

#define F_OK 0
// XXX: Duplicate definition; should probably weed out includes of host system
// include of unistd.h in future work
//#define R_OK        001
//#define W_OK        002
//#define X_OK        004
#define MAY_EXEC  001
#define MAY_WRITE 002
#define MAY_READ  004
#if 0
#define MAY_APPEND 010
#endif

#define ACC_MODE(x)                                        \
    ((((x) == O_RDONLY || (x) == O_RDWR) ? MAY_READ : 0) | \
     (((x) == O_WRONLY || (x) == O_RDWR) ? MAY_WRITE : 0))

/* initialization for fs and mounts */
int init_fs(void);
int init_mount_root(void);
int init_mount(void);

/* file system operations */
int mount_fs(const char* mount_type, const char* mount_uri, const char* mount_point,
             struct shim_dentry* parent, struct shim_dentry** dentp, bool make_ancestor);
int unmount_fs(const char* mount_point);

void get_mount(struct shim_mount* mount);
void put_mount(struct shim_mount* mount);

struct shim_mount* find_mount_from_uri(const char* uri);

int walk_mounts(int (*walk)(struct shim_mount* mount, void* arg), void* arg);

/* functions for dcache supports */
int init_dcache(void);

extern struct shim_lock g_dcache_lock;

/*!
 * \brief Dump dentry cache
 *
 * \param dent the starting dentry, or NULL (will default to dentry root)
 *
 * Dumps the dentry cache using `log_always`, starting from the provided dentry. Intended for
 * debugging the filesystem - just add it manually to the code.
 */
void dump_dcache(struct shim_dentry* dent);

/*!
 * \brief Check file permissions, similar to Unix access
 *
 * \param dentry the dentry to check
 * \param mask mask, same as for Unix access
 *
 * Checks permissions for a dentry. Because Graphene currently has no notion of users, this will
 * always use the "user" part of file mode.
 *
 * The caller should hold `g_dcache_lock`.
 *
 * `dentry` should be a valid dentry, but can be negative (in which case the function will return
 * -ENOENT).
 */
int check_permissions(struct shim_dentry* dent, mode_t mask);

/*
 * Flags for `path_lookupat`.
 *
 * Note that, opposite to user-level O_NOFOLLOW, we define LOOKUP_FOLLOW as a positive flag, and add
 * LOOKUP_NO_FOLLOW as a pseudo-flag for readability.
 *
 * This is modeled after Linux and BSD codebases, which define a positive FOLLOW flag, and a
 * negative pseudo-flag was introduced by FreeBSD.
 */
#define LOOKUP_NO_FOLLOW       0
#define LOOKUP_FOLLOW          0x1
#define LOOKUP_CREATE          0x2
#define LOOKUP_DIRECTORY       0x4
#define LOOKUP_MAKE_SYNTHETIC  0x8

/* Maximum number of nested symlinks that `path_lookupat` and related functions will follow */
#define MAX_LINK_DEPTH 8

/*!
 * \brief Look up a path, retrieving a dentry
 *
 * \param start the start dentry for relative paths, or NULL (in which case it will default to
 * process' cwd)
 * \param path the path to look up
 * \param flags lookup flags (see description below)
 * \param[out] found pointer to retrieved dentry
 *
 * The caller should hold `g_dcache_lock`. If you do not already hold `g_dcache_lock`, use
 * `path_lookupat` instead.
 *
 * On success, returns 0, and puts the retrieved dentry in `*found`. The reference count of the
 * dentry will be increased by one.
 *
 * The retrieved dentry is always valid, and can only be negative if LOOKUP_CREATE is set.
 *
 * On failure, returns a negative error code, and sets `*found` to NULL.
 *
 * Supports the following flags:
 *
 * - LOOKUP_FOLLOW: if `path` refers to a symbolic link, follow it (the default is to return the
 *   dentry to the link). Note that symbolic links for intermediate path segments are always
 *   followed.
 *
 * - LOOKUP_NO_FOLLOW: this is a pseudo-flag defined as 0. You can use it to indicate to the reader
 *   that symbolic links are intentionally not being followed.
 *
 * - LOOKUP_CREATE: if the file under `path` does not exist, but can be created (i.e. the parent
 *   directory exists), the function will succeed and a negative dentry will be put in `*found`. If
 *   the parent directory also does not exist, the function will still fail with -ENOENT.
 *
 * - LOOKUP_DIRECTORY: expect the file under `path` to be a directory, and fail with -ENOTDIR
 *   otherwise
 *
 * - LOOKUP_MAKE_SYNTHETIC: create pseudo-files (DENTRY_SYNTHETIC) for any components on the path
 *   that do not exist. This is intended for use when creating mountpoints specified in manifest.
 *
 * Note that a path with trailing slash is always treated as a directory, and LOOKUP_FOLLOW /
 * LOOKUP_CREATE do not apply.
 *
 * TODO: This function doesn't check any permissions. It should return -EACCES on inaccessible
 * directories.
 */
int _path_lookupat(struct shim_dentry* start, const char* path, int flags,
                   struct shim_dentry** found);

/*!
 * \brief Look up a path, retrieving a dentry
 *
 * This is a version of `_path_lookupat` that does not require caller to hold `g_dcache_lock`, but
 * acquires and releases it by itself. See the documentation for `_path_lookupat` for details.
 */
int path_lookupat(struct shim_dentry* start, const char* path, int flags,
                  struct shim_dentry** found);

/*!
 * This function returns a dentry (in *dir) from a handle corresponding to dirfd.
 * If dirfd == AT_FDCWD returns current working directory.
 *
 * Returned dentry must be a directory.
 *
 * Increments dentry ref count by one.
 */
int get_dirfd_dentry(int dirfd, struct shim_dentry** dir);

/*!
 * \brief Open a file under a given path, similar to Unix open
 *
 * \param hdl handle to associate with dentry, can be NULL
 * \param start the start dentry for relative paths, or NULL (in which case it will default to
 * process' cwd)
 * \param path the path to look up
 * \param flags Unix open flags (see below)
 * \param mode Unix file mode, used when creating a new file/directory
 * \param[out] found pointer to retrieved dentry, can be NULL
 *
 * If `hdl` is provided, on success it will be associated with the dentry. Otherwise, the file will
 * just be retrieved or created.
 *
 * If `found` is provided, on success it will be set to the file's dentry (and its reference count
 * will be increased), and on failure it will be set to NULL.
 *
 * Similar to Unix open, `flags` must include one of O_RDONLY, O_WRONLY or O_RDWR. In addition,
 * the following flags are supported by this function:
 * - O_CREAT: create a new file if one does not exist
 * - O_EXCL: fail if the file already exists
 * - O_DIRECTORY: expect/create a directory instead of regular file
 * - O_NOFOLLOW: don't follow symbolic links when resolving a path
 * - O_TRUNC: truncate the file after opening
 *
 * The flags (including any not listed above), as well as file mode, are passed to the underlying
 * filesystem.
 *
 * Note that unlike Linux `open`, this function called with O_CREAT and O_DIRECTORY will attempt to
 * create a directory (Linux `open` ignores the O_DIRECTORY flag and creates a regular file).
 * However, that behaviour of Linux `open` is a bug, and emulating it is inconvenient for us
 * (because we use this function for both `open` and `mkdir`).
 *
 * TODO: This function checks permissions of the opened file (if it exists) and parent directory (if
 * the file is being created), but not permissions for the whole path. That check probably should be
 * added to `path_lookupat`.
 *
 * TODO: The set of allowed flags should be checked in syscalls that use this function.
 */
int open_namei(struct shim_handle* hdl, struct shim_dentry* start, const char* path, int flags,
               int mode, struct shim_dentry** found);

/*!
 * \brief Open an already retrieved dentry, and associate a handle with it
 *
 * \param hdl handle to associate with dentry
 * \param dent the dentry to open
 * \param flags Unix open flags
 *
 * The dentry has to already correspond to a file (i.e. has to be valid and non-negative).
 *
 * The `flags` parameter will be passed to the underlying filesystem's `open` function. If O_TRUNC
 * flag is specified, the filesystem's `truncate` function will also be called.
 */
int dentry_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags);

/*!
 * \brief Populate a directory handle with current dentries
 *
 * \param hdl a directory handle
 *
 * This function populates the `hdl->dir_info` structure with current dentries in a directory, so
 * that the directory can be listed using `getdents/getdents64` syscalls.
 *
 * The caller should hold `g_dcache_lock` and `hdl->lock`.
 *
 * If the handle is currently populated (i.e. `hdl->dir_info.dents` is not null), this function is a
 * no-op. If you want to refresh the handle with new contents, call `clear_directory_handle` first.
 */
int populate_directory_handle(struct shim_handle* hdl);

/*!
 * \brief Clear dentries from a directory handle
 *
 * \param hdl a directory handle
 *
 * This function discards an array of dentries previously prepared by `populate_directory_handle`.
 *
 * If the handle is currently not populated (i.e. `hdl->dir_info.dents` is null), this function is a
 * no-op.
 */
void clear_directory_handle(struct shim_handle* hdl);

/* Increment the reference count on dent */
void get_dentry(struct shim_dentry* dent);
/* Decrement the reference count on dent */
void put_dentry(struct shim_dentry* dent);

/*!
 * \brief Garbage-collect a dentry, if possible
 *
 * \param dentry the dentry (has to have a parent)
 *
 * This function checks if a dentry is unused, and deletes it if that's true. The caller must hold
 * `g_dcache_lock`.
 *
 * A dentry is unused if it has no external references and does not correspond to a real file
 * (i.e. is invalid or negative). Such dentries can remain after failed lookups or file deletion.
 *
 * The function should be called when processing a list of children, after you're done with a given
 * dentry. It guarantees that the amortized cost of processing such dentries is constant, i.e. they
 * will be only encountered once.
 *
 * \code
 * struct shim_dentry* child;
 * struct shim_dentry* tmp;
 *
 * LISTP_FOR_EACH_ENTRY_SAFE(child, tmp, &dent->children, siblings) {
 *     // do something with `child`, increase ref count if used
 *     ...
 *     dentry_gc(child);
 * }
 * \endcode
 */
void dentry_gc(struct shim_dentry* dent);

/*!
 * \brief Compute an absolute path for dentry, allocating memory for it
 *
 * \param dent the dentry
 * \param[out] path will be set to computed path
 * \param[out] size if not NULL, will be set to path size, including null terminator
 *
 * \return 0 on success, negative error code otherwise
 *
 * This function computes an absolute path for dentry, allocating a new buffer for it. The path
 * should later be freed using `free`.
 *
 * An absolute path is a combination of all names up to the root (not including the root, which by
 * convention has an empty name), separated by `/`, and beginning with `/`.
 */
int dentry_abs_path(struct shim_dentry* dent, char** path, size_t* size);

/*!
 * \brief Compute a relative path for dentry, allocating memory for it
 *
 * \param dent the dentry
 * \param[out] path will be set to computed path
 * \param[out] size if not NULL, will be set to path size, including null terminator
 *
 * \return 0 on success, negative error code otherwise
 *
 * This function computes a relative path for dentry, allocating a new buffer for it. The path
 * should later be freed using `free`.
 *
 * A relative path is a combination of all names up to the mountpoint (not including the
 * mountpoint), separated by `/`. A relative path never begins with `/`.
 */
int dentry_rel_path(struct shim_dentry* dent, char** path, size_t* size);

int dentry_abs_path_into_qstr(struct shim_dentry* dent, struct shim_qstr* str);

static inline const char* dentry_get_name(struct shim_dentry* dent) {
    return qstrgetstr(&dent->name);
}

ino_t dentry_ino(struct shim_dentry* dent);

/*!
 * \brief Allocate and initialize a new dentry
 *
 * \param parent the parent node, or NULL if this is supposed to be the dentry root
 * \param mount the mount the dentry is under
 * \param name name of the new dentry
 * \param name_len length of the name
 *
 * \return the new dentry, or NULL in case of allocation failure
 *
 * The caller should hold `g_dcache_lock`.
 *
 * The function will initialize the following fields: `mount` and `fs` (if `mount` provided),
 * `name`, and parent/children links.
 *
 * The reference count of the returned dentry will be 2 if `parent` was provided, 1 otherwise.
 *
 * The `mount` parameter should typically be `parent->mount`, but is passed explicitly to support
 * initializing the root dentry of a newly mounted filesystem. The `fs` field will be initialized to
 * `mount->fs`, but you can later change it to support special files.
 */
struct shim_dentry* get_new_dentry(struct shim_mount* mount, struct shim_dentry* parent,
                                   const char* name, size_t name_len);

/*!
 * \brief Search for a child of a dentry with a given name
 *
 * \param parent the dentry to search under
 * \param name name of searched dentry
 * \param name_len length of the name
 *
 * \return the dentry, or NULL if not found
 *
 * The caller should hold `g_dcache_lock`.
 *
 * If found, the reference count on the returned dentry is incremented.
 */
struct shim_dentry* lookup_dcache(struct shim_dentry* parent, const char* name, size_t name_len);

/* This function recursively deletes and frees all dentries under root
 *
 * XXX: Current code doesn't do a free..
 */
int __del_dentry_tree(struct shim_dentry* root);

/*
 * Returns true if `anc` is an ancestor of `dent`.
 */
bool dentry_is_ancestor(struct shim_dentry* anc, struct shim_dentry* dent);

/* XXX: Future work: current dcache never shrinks. Would be nice to be able to do something like LRU
 * under space pressure, although for a single app, this may be over-kill. */

/*
 * Hashing utilities for paths.
 *
 * TODO: The following functions are used for inode numbers and in a few other places where we need
 * a (mostly) unique number for a given path. Unfortunately, they do not guarantee full
 * uniqueness. We might need a better solution for the filesystem to be fully consistent.
 */

HASHTYPE hash_str(const char* str);
HASHTYPE hash_name(HASHTYPE parent_hbuf, const char* name);
HASHTYPE hash_abs_path(struct shim_dentry* dent);

#define READDIR_BUF_SIZE 4096

extern struct shim_fs_ops chroot_fs_ops;
extern struct shim_d_ops chroot_d_ops;

extern struct shim_fs_ops str_fs_ops;
extern struct shim_d_ops str_d_ops;

extern struct shim_fs_ops tmp_fs_ops;
extern struct shim_d_ops tmp_d_ops;

extern struct shim_fs chroot_builtin_fs;
extern struct shim_fs proc_builtin_fs;
extern struct shim_fs dev_builtin_fs;
extern struct shim_fs sys_builtin_fs;
extern struct shim_fs tmp_builtin_fs;
extern struct shim_fs pipe_builtin_fs;
extern struct shim_fs fifo_builtin_fs;
extern struct shim_fs socket_builtin_fs;
extern struct shim_fs epoll_builtin_fs;
extern struct shim_fs eventfd_builtin_fs;

struct shim_fs* find_fs(const char* name);

/* pseudo file systems (separate treatment since they don't have associated dentries) */
#define DIR_RX_MODE  0555
#define FILE_RW_MODE 0666
#define FILE_R_MODE  0444

extern struct shim_fs_ops dev_fs_ops;
extern struct shim_d_ops dev_d_ops;

extern struct shim_fs_ops proc_fs_ops;
extern struct shim_d_ops proc_d_ops;

extern struct shim_fs_ops sys_fs_ops;
extern struct shim_d_ops sys_d_ops;

struct pseudo_name_ops {
    int (*match_name)(const char* name);
    int (*list_name)(const char* name, readdir_callback_t callback, void* arg);
};

static inline dev_t makedev(unsigned int major, unsigned int minor) {
    dev_t dev;
    dev  = (((dev_t)(major & 0x00000fffu)) <<  8);
    dev |= (((dev_t)(major & 0xfffff000u)) << 32);
    dev |= (((dev_t)(minor & 0x000000ffu)) <<  0);
    dev |= (((dev_t)(minor & 0xffffff00u)) << 12);
    return dev;
}

struct pseudo_fs_ops {
    int (*open)(struct shim_handle* hdl, const char* name, int flags);
    int (*mode)(const char* name, mode_t* mode);
    int (*stat)(const char* name, struct stat* buf);
    int (*follow_link)(const char* name, struct shim_qstr* link);
};

struct pseudo_dir;

struct pseudo_ent {
    /* pseudo-FS entry is identified by either hardcoded name or at-runtime name_ops */
    const char* name;
    const struct pseudo_name_ops* name_ops;
    const struct pseudo_fs_ops* fs_ops;
    const struct pseudo_dir* dir; /* NULL if pseudo-FS entry is a file */
    int type; /* LINUX_DT_REG, LINUX_DT_CHR, etc (if dir != NULL, then always LINUX_DT_DIR) */
};

struct pseudo_dir {
    int size;
    const struct pseudo_ent ent[];
};

int pseudo_mount(const char* uri, void** mount_data);
int pseudo_unmount(void* mount_data);
int pseudo_dir_mode(const char* name, mode_t* mode);
int pseudo_dir_stat(const char* name, struct stat* buf);
int pseudo_dir_open(struct shim_handle* hdl, const char* name, int flags);
int pseudo_mode(struct shim_dentry* dent, mode_t* mode, const struct pseudo_ent* root_ent);
int pseudo_lookup(struct shim_dentry* dent, const struct pseudo_ent* root_ent);
int pseudo_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags,
                const struct pseudo_ent* root_ent);
int pseudo_readdir(struct shim_dentry* dent, readdir_callback_t callback, void* arg,
                   const struct pseudo_ent* root_ent);
int pseudo_stat(struct shim_dentry* dent, struct stat* buf, const struct pseudo_ent* root_ent);
int pseudo_hstat(struct shim_handle* hdl, struct stat* buf, const struct pseudo_ent* root_ent);
int pseudo_follow_link(struct shim_dentry* dent, struct shim_qstr* link,
                       const struct pseudo_ent* root_ent);

/* string-type file system */
int str_add_dir(const char* path, mode_t mode, struct shim_dentry** dent);
int str_add_file(const char* path, mode_t mode, struct shim_dentry** dent);
int str_open(struct shim_handle* hdl, struct shim_dentry* dent, int flags);
int str_dput(struct shim_dentry* dent);
int str_close(struct shim_handle* hdl);
ssize_t str_read(struct shim_handle* hdl, void* buf, size_t count);
ssize_t str_write(struct shim_handle* hdl, const void* buf, size_t count);
off_t str_seek(struct shim_handle* hdl, off_t offset, int whence);
int str_flush(struct shim_handle* hdl);
int str_truncate(struct shim_handle* hdl, off_t len);

/* /sys fs related common APIs */
/* This function extracts first number from a string. Returns a negative error code if no number is
 * found. For example, "3" will be extracted from "cpu/cpu3/topology/core_siblings" */
int extract_first_num_from_string(const char* path);
int sys_info_mode(const char* name, mode_t* mode);
int sys_info_stat(const char* name, struct stat* buf);
int sys_dir_open(struct shim_handle* hdl, const char* name, int flags);
int sys_dir_mode(const char* name, mode_t* mode);
int sys_dir_stat(const char* name, struct stat* buf);
/* Checks if pathname is a valid path under /sys/; returns 1 on success and 0 on failure */
int sys_match_resource_num(const char* pathname);
/* Lists path under /sys/, same as readdir */
int sys_list_resource_num(const char* pathname, readdir_callback_t callback, void* arg);

#endif /* _SHIM_FS_H_ */
