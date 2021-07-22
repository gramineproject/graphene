/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Definitions of types and functions for file/handle bookkeeping.
 */

#ifndef _SHIM_HANDLE_H_
#define _SHIM_HANDLE_H_

#include <asm/fcntl.h>
#include <asm/resource.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/shm.h>
#include <linux/un.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>

#include "atomic.h"  // TODO: migrate to stdatomic.h
#include "list.h"
#include "pal.h"
#include "shim_defs.h"
#include "shim_fs_mem.h"
#include "shim_sync.h"
#include "shim_types.h"

/* Handle types. Many of these are used by a single filesystem. */
enum shim_handle_type {
    /* Files: */
    TYPE_FILE,       /* host files, used by `chroot` filesystem */
    TYPE_DEV,        /* emulated devices, used by `dev` filesystem */
    TYPE_STR,        /* string-based files (with data inside handle), handled by `pseudo_*`
                      * functions */
    TYPE_PSEUDO,     /* pseudo nodes (currently directories), handled by `pseudo_*` functions */
    TYPE_TMPFS,      /* string-based files (with data inside dentry), used by `tmpfs` filesystem */

    /* Pipes and sockets: */
    TYPE_PIPE,       /* pipes, used by `pipe` filesystem */
    TYPE_SOCK,       /* sockets, used by `socket` filesystem */

    /* Special handles: */
    TYPE_EPOLL,      /* epoll handles, see `shim_epoll.c` */
    TYPE_EVENTFD,    /* eventfd handles, used by `eventfd` filesystem */
};

struct shim_handle;
struct shim_thread;
struct shim_vma;

enum shim_file_type {
    FILE_UNKNOWN,
    FILE_REGULAR,
    FILE_DIR,
    FILE_DEV,
    FILE_TTY,
};

struct shim_file_data {
    struct shim_lock lock;
    struct atomic_int version;
    bool queried;
    enum shim_file_type type;
    struct atomic_int size;
    struct shim_qstr host_uri;
    unsigned long atime;
    unsigned long mtime;
    unsigned long ctime;
    unsigned long nlink;
};

struct shim_file_handle {
    unsigned int version;
    struct shim_file_data* data;

    enum shim_file_type type;
    file_off_t size;
    file_off_t marker;

    struct sync_handle* sync;
};

#define FILE_HANDLE_DATA(hdl)  ((hdl)->info.file.data)
#define FILE_DENTRY_DATA(dent) ((struct shim_file_data*)(dent)->data)

struct shim_pipe_handle {
    bool ready_for_ops; /* true for pipes, false for FIFOs that were mknod'ed but not open'ed */
    char name[PIPE_URI_SIZE];
};

#define SOCK_STREAM   1
#define SOCK_DGRAM    2
#define SOCK_NONBLOCK 04000
#define SOCK_CLOEXEC  02000000

#define SOL_TCP 6

#define PF_LOCAL 1
#define PF_UNIX  PF_LOCAL
#define PF_FILE  PF_LOCAL
#define PF_INET  2
#define PF_INET6 10

#define AF_UNIX  PF_UNIX
#define AF_INET  PF_INET
#define AF_INET6 PF_INET6

#define SOCK_URI_SIZE 108

enum shim_sock_state {
    SOCK_CREATED,
    SOCK_BOUND,
    SOCK_CONNECTED,
    SOCK_BOUNDCONNECTED,
    SOCK_LISTENED,
    SOCK_ACCEPTED,
    SOCK_SHUTDOWN,
};

struct shim_sock_handle {
    int domain;
    int sock_type;
    int protocol;
    int error;

    enum shim_sock_state sock_state;

    union shim_sock_addr {
        // INET addr
        struct {
            struct addr_inet {
                unsigned short port;
                unsigned short ext_port;
                union {
                    struct in_addr v4;
                    struct in6_addr v6;
                } addr;
            } bind, conn;
        } in;
        // UNIX addr
        struct addr_unix {
            struct shim_dentry* dentry;
            char name[PIPE_URI_SIZE];
        } un;
    } addr;

    struct shim_sock_option {
        struct shim_sock_option* next;
        int level;
        int optname;
        int optlen;
        char optval[];
    }* pending_options;

    struct shim_peek_buffer {
        size_t size;             /* total size (capacity) of buffer `buf` */
        size_t start;            /* beginning of buffered but yet unread data in `buf` */
        size_t end;              /* end of buffered but yet unread data in `buf` */
        char uri[SOCK_URI_SIZE]; /* cached URI for recvfrom(udp_socket) case */
        char buf[];              /* peek buffer of size `size` */
    }* peek_buffer;
};

struct shim_dir_handle {
    /* The first two dentries are always "." and ".." */
    struct shim_dentry** dents;
    size_t count;
    size_t pos;
};

struct shim_str_handle {
    struct shim_mem_file mem;
    bool dirty;
    file_off_t pos;
};

struct shim_tmpfs_handle {
    file_off_t pos;
};

DEFINE_LIST(shim_epoll_item);
DEFINE_LISTP(shim_epoll_item);
struct shim_epoll_item {
    FDTYPE fd;
    uint64_t data;
    unsigned int events;
    unsigned int revents;
    /* The two references below are not ref-counted (to prevent cycles). When a handle is dropped
     * (ref-count goes to 0) it is also removed from all epoll instances. When an epoll instance is
     * destroyed, all handles that it traced are removed from it. */
    struct shim_handle* handle;      /* reference to monitored object (socket, pipe, file, etc) */
    struct shim_handle* epoll;       /* reference to epoll object that monitors handle object */
    LIST_TYPE(shim_epoll_item) list; /* list of shim_epoll_items, used by epoll object (via `fds`) */
    LIST_TYPE(shim_epoll_item) back; /* list of epolls, used by handle object (via `epolls`) */
};

struct shim_epoll_handle {
    size_t waiter_cnt;

    /* Number of items on fds list. */
    size_t fds_count;

    AEVENTTYPE event;
    LISTP_TYPE(shim_epoll_item) fds;
};

struct shim_fs;
struct shim_qstr;
struct shim_dentry;

/* The epolls list links to the back field of the shim_epoll_item structure
 */
struct shim_handle {
    enum shim_handle_type type;
    bool is_dir;

    REFTYPE ref_count;

    struct shim_fs* fs;
    struct shim_dentry* dentry;

    /* If this handle is registered for any epoll handle, this list contains
     * a shim_epoll_item object in correspondence with the epoll handle. */
    LISTP_TYPE(shim_epoll_item) epolls;
    /* Only meaningful if the handle is registered in some epoll instance with `EPOLLET` semantics.
     * `false` if it already triggered an `EPOLLIN` event for the current portion of data otherwise
     * `true` and the next `epoll_wait` will consider this handle and report events for it. */
    bool needs_et_poll_in;
    /* Same as above but for `EPOLLOUT` events. */
    bool needs_et_poll_out;

    struct shim_qstr uri; /* URI representing this handle, it is not
                           * necessary to be set. */

    PAL_HANDLE pal_handle;

    /* Type-specific fields: when accessing, ensure that `type` field is appropriate first (at least
     * by using assert()) */
    union {
        struct shim_file_handle file;    /* TYPE_FILE */
        /* (no data) */                  /* TYPE_DEV */
        struct shim_str_handle str;      /* TYPE_STR */
        /* (no data) */                  /* TYPE_PSEUDO */
        struct shim_tmpfs_handle tmpfs;  /* TYPE_TMPFS */

        struct shim_pipe_handle pipe;    /* TYPE_PIPE */
        struct shim_sock_handle sock;    /* TYPE_SOCK */

        struct shim_epoll_handle epoll;  /* TYPE_EPOLL */
        /* (no data) */                  /* TYPE_EVENTFD */
    } info;

    struct shim_dir_handle dir_info;

    int flags; /* Linux' O_* flags */
    int acc_mode;
    struct shim_lock lock;
};

/* allocating / manage handle */
struct shim_handle* get_new_handle(void);
void get_handle(struct shim_handle* hdl);
void put_handle(struct shim_handle* hdl);

/* Set handle to non-blocking or blocking mode. */
int set_handle_nonblocking(struct shim_handle* hdl, bool on);

/* file descriptor table */
struct shim_fd_handle {
    FDTYPE vfd; /* virtual file descriptor */
    int flags;  /* file descriptor flags, only FD_CLOEXEC */

    struct shim_handle* handle;
};

struct shim_handle_map {
    /* the top of created file descriptors */
    FDTYPE fd_size;
    FDTYPE fd_top;

    /* refrence count and lock */
    REFTYPE ref_count;
    struct shim_lock lock;

    /* An array of file descriptor belong to this mapping */
    struct shim_fd_handle** map;
};

/* allocating file descriptors */
#define FD_NULL                     ((FDTYPE)-1)
#define HANDLE_ALLOCATED(fd_handle) ((fd_handle) && (fd_handle)->vfd != FD_NULL)

struct shim_handle* __get_fd_handle(FDTYPE fd, int* flags, struct shim_handle_map* map);
struct shim_handle* get_fd_handle(FDTYPE fd, int* flags, struct shim_handle_map* map);

/*!
 * \brief Assign new fd to a handle.
 *
 * \param hdl A handle to be mapped to the new fd.
 * \param flags Flags assigned to new shim_fd_handle.
 * \param handle_map Handle map to be used. If NULL is passed, current thread's handle map is used.
 *
 * Creates mapping for the given handle to a new file descriptor which is then returned.
 * Uses the lowest, non-negative available number for the new fd.
 */
int set_new_fd_handle(struct shim_handle* hdl, int fd_flags, struct shim_handle_map* map);
int set_new_fd_handle_by_fd(FDTYPE fd, struct shim_handle* hdl, int fd_flags,
                            struct shim_handle_map* map);
int set_new_fd_handle_above_fd(FDTYPE fd, struct shim_handle* hdl, int fd_flags,
                               struct shim_handle_map* map);
struct shim_handle* __detach_fd_handle(struct shim_fd_handle* fd, int* flags,
                                       struct shim_handle_map* map);
struct shim_handle* detach_fd_handle(FDTYPE fd, int* flags, struct shim_handle_map* map);

/* manage handle mapping */
int dup_handle_map(struct shim_handle_map** new_map, struct shim_handle_map* old_map);
void get_handle_map(struct shim_handle_map* map);
void put_handle_map(struct shim_handle_map* map);
int walk_handle_map(int (*callback)(struct shim_fd_handle*, struct shim_handle_map*),
                    struct shim_handle_map* map);

int init_handle(void);
int init_important_handles(void);

int open_executable(struct shim_handle* hdl, const char* path);

int get_file_size(struct shim_handle* file, uint64_t* size);

ssize_t do_handle_read(struct shim_handle* hdl, void* buf, size_t count);
ssize_t do_handle_write(struct shim_handle* hdl, const void* buf, size_t count);

#endif /* _SHIM_HANDLE_H_ */
