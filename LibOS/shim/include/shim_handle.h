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
 * shim_handle.h
 *
 * Definitions of types and functions for file/handle bookkeeping.
 */

#ifndef _SHIM_HANDLE_H_
#define _SHIM_HANDLE_H_

#include <asm/fcntl.h>
#include <asm/resource.h>
#include <atomic.h>  // TODO: migrate to stdatomic.h
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/shm.h>
#include <linux/un.h>
#include <list.h>
#include <pal.h>
#include <shim_defs.h>
#include <shim_sysv.h>
#include <shim_types.h>
#include <stdalign.h>

/* start definition of shim handle */
enum shim_handle_type {
    TYPE_FILE,
    TYPE_DEV,
    TYPE_PIPE,
    TYPE_SOCK,
    TYPE_DIR,
    TYPE_SHM,
    TYPE_SEM,
    TYPE_MSG,
    TYPE_FUTEX,
    TYPE_STR,
    TYPE_EPOLL,
    TYPE_EVENTFD
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
    mode_t mode;
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
    off_t size;
    off_t marker;
};

#define FILE_HANDLE_DATA(hdl)  ((hdl)->info.file.data)
#define FILE_DENTRY_DATA(dent) ((struct shim_file_data*)(dent)->data)

struct shim_dev_ops {
    /* open: provide a filename relative to the mount point and flags,
       modify the shim handle */
    int (*open)(struct shim_handle* hdl, const char* name, int flags);

    /* close: clean up the file state inside the handle */
    int (*close)(struct shim_handle* hdl);

    /* read: the content from the file opened as handle */
    ssize_t (*read)(struct shim_handle* hdl, void* buf, size_t count);

    /* write: the content from the file opened as handle */
    ssize_t (*write)(struct shim_handle* hdl, const void* buf, size_t count);

    /* flush: flush out user buffer */
    int (*flush)(struct shim_handle* hdl);

    /* seek: the content from the file opened as handle */
    off_t (*seek)(struct shim_handle* hdl, off_t offset, int wence);

    int (*truncate)(struct shim_handle* hdl, uint64_t len);

    int (*mode)(const char* name, mode_t* mode);

    /* stat, hstat: get status of the file */
    int (*stat)(const char* name, struct stat* buf);
    int (*hstat)(struct shim_handle* hdl, struct stat* buf);
};

int dev_update_dev_ops(struct shim_handle* hdl);

struct shim_dev_handle {
    struct shim_dev_ops dev_ops;
};

struct shim_pipe_handle {
#if USE_SIMPLE_PIPE == 1
    struct shim_handle* pair;
#else
    IDTYPE pipeid;
#endif
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

struct shim_unix_data {
    unsigned int pipeid;
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
            unsigned int pipeid;
            struct shim_unix_data* data;
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

struct shim_dirent {
    struct shim_dirent* next;
    unsigned long ino; /* Inode number */
    unsigned char type;
    char name[]; /* File name (null-terminated) */
};

#define SHIM_DIRENT_SIZE      offsetof(struct shim_dirent, name)
#define SHIM_DIRENT_ALIGNMENT alignof(struct shim_dirent)
/* Size of struct shim_dirent instance together with alignment,
 * which might be different depending on the length of the name field */
#define SHIM_DIRENT_ALIGNED_SIZE(len) ALIGN_UP(SHIM_DIRENT_SIZE + (len), SHIM_DIRENT_ALIGNMENT)

struct shim_dir_handle {
    int offset;
    struct shim_dentry* dotdot;
    struct shim_dentry* dot;
    struct shim_dentry** buf;
    struct shim_dentry** ptr;
};

struct shim_shm_handle {
    /* XXX: need to implement */
    void* __reserved;
};

struct msg_type;
struct msg_item;
struct msg_client;

#define MAX_SYSV_CLIENTS 32

DEFINE_LIST(shim_msg_handle);
struct shim_msg_handle {
    unsigned long msqkey; /* msg queue key from user */
    IDTYPE msqid;         /* msg queue identifier */
    bool owned;           /* owned by current process */
    struct shim_ipc_info* owner;
    LEASETYPE lease;
    int perm;        /* access permissions */
    bool deleted;    /* marking the queue deleted */
    int nmsgs;       /* number of msgs */
    int currentsize; /* current size in bytes */
    struct msg_qobj* queue;
    int queuesize;
    int queueused;
    struct msg_qobj* freed;
    PAL_HANDLE event; /* event for waiting */
    int ntypes;
    int maxtypes;
    struct msg_type* types;
    struct sysv_score scores[MAX_SYSV_CLIENTS];
    LIST_TYPE(shim_msg_handle) list;
    LIST_TYPE(shim_msg_handle) key_hlist;
    LIST_TYPE(shim_msg_handle) qid_hlist;
};

struct sem_objs;

DEFINE_LIST(shim_sem_handle);
struct shim_sem_handle {
    unsigned long semkey;
    IDTYPE semid;
    bool owned;
    struct shim_ipc_info* owner;
    LEASETYPE lease;
    int perm;
    bool deleted;
    PAL_HANDLE event;
    int nsems;
    struct sem_obj* sems;
    int nreqs;
    struct sysv_score scores[MAX_SYSV_CLIENTS];
    LISTP_TYPE(sem_ops) migrated;
    LIST_TYPE(shim_sem_handle) list;
    LIST_TYPE(shim_sem_handle) key_hlist;
    LIST_TYPE(shim_sem_handle) sid_hlist;
};

struct shim_str_data {
    REFTYPE ref_count;
    char* str;
    off_t len;
    size_t buf_size;
    bool dirty;
    int (*update)(struct shim_handle* hdl);
    int (*modify)(struct shim_handle* hdl);
};

struct shim_str_handle {
    struct shim_str_data* data; /* inode is stored in dentry, too.
                                   store pointer here for efficiency */
    char* ptr;
};

DEFINE_LIST(shim_epoll_item);
DEFINE_LISTP(shim_epoll_item);
struct shim_epoll_handle {
    int maxfds;
    int waiter_cnt;

    int pal_cnt;
    PAL_HANDLE* pal_handles;

    AEVENTTYPE event;
    LISTP_TYPE(shim_epoll_item) fds;
};

struct shim_mount;
struct shim_qstr;
struct shim_dentry;

/* The epolls list links to the back field of the shim_epoll_item structure
 */
struct shim_handle {
    enum shim_handle_type type;

    REFTYPE ref_count;

    char fs_type[8];
    struct shim_mount* fs;
    struct shim_qstr path;
    struct shim_dentry* dentry;

    /* If this handle is registered for any epoll handle, this list contains
     * a shim_epoll_item object in correspondence with the epoll handle. */
    LISTP_TYPE(shim_epoll_item) epolls;

    struct shim_qstr uri; /* URI representing this handle, it is not
                           * necessary to be set. */

    PAL_HANDLE pal_handle;

    union {
        struct shim_file_handle file;
        struct shim_dev_handle dev;
        struct shim_pipe_handle pipe;
        struct shim_sock_handle sock;
        struct shim_shm_handle shm;
        struct shim_msg_handle msg;
        struct shim_sem_handle sem;
        struct shim_str_handle str;
        struct shim_epoll_handle epoll;
    } info;

    struct shim_dir_handle dir_info;

    int flags;
    int acc_mode;
    IDTYPE owner;
    struct shim_lock lock;
};

/* allocating / manage handle */
struct shim_handle* get_new_handle(void);
void flush_handle(struct shim_handle* hdl);
void get_handle(struct shim_handle* hdl);
void put_handle(struct shim_handle* hdl);

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
int set_new_fd_handle(struct shim_handle* hdl, int flags, struct shim_handle_map* map);
int set_new_fd_handle_by_fd(FDTYPE fd, struct shim_handle* hdl, int flags,
                            struct shim_handle_map* map);
struct shim_handle* __detach_fd_handle(struct shim_fd_handle* fd, int* flags,
                                       struct shim_handle_map* map);
struct shim_handle* detach_fd_handle(FDTYPE fd, int* flags, struct shim_handle_map* map);

/* manage handle mapping */
int dup_handle_map(struct shim_handle_map** new_map, struct shim_handle_map* old_map);
int flush_handle_map(struct shim_handle_map* map);
void get_handle_map(struct shim_handle_map* map);
void put_handle_map(struct shim_handle_map* map);
int walk_handle_map(int (*callback)(struct shim_fd_handle*, struct shim_handle_map*),
                    struct shim_handle_map* map);

int init_handle(void);
int init_important_handles(void);

off_t get_file_size(struct shim_handle* file);

int do_handle_read(struct shim_handle* hdl, void* buf, int count);
int do_handle_write(struct shim_handle* hdl, const void* buf, int count);

#endif /* _SHIM_HANDLE_H_ */
