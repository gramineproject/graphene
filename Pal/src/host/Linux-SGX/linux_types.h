/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#ifndef __LINUX_TYPES_H__
#define __LINUX_TYPES_H__

#include <linux/socket.h>
#include <linux/time.h>
#define __timespec_defined
#undef __USE_POSIX199309
#include <linux/poll.h>
#include <linux/sched.h>
#include <asm/posix_types.h>
#include <asm/stat.h>
#include <asm/fcntl.h>
#include <sigset.h>
#include <stdint.h>

#ifndef size_t
typedef __kernel_size_t size_t;
#endif

struct linux_dirent64 {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

#define DT_UNKNOWN      0
#define DT_FIFO         1
#define DT_CHR          2
#define DT_DIR          4
#define DT_BLK          6
#define DT_REG          8
#define DT_LNK          10
#define DT_SOCK         12
#define DT_WHT          14

typedef unsigned short int sa_family_t;

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[128 - sizeof(unsigned short)];
};

#ifndef AF_UNIX
# define AF_UNIX 1
#endif

#ifndef AF_INET
# define AF_INET 2
#endif

#ifndef AF_INET6
# define AF_INET6 10
#endif

#ifndef SOCK_STREAM
# define SOCK_STREAM 1
#endif

#ifndef SOCK_DGRAM
# define SOCK_DGRAM 2
#endif

#ifndef SOCK_NONBLOCK
# define SOCK_NONBLOCK 04000
#endif

#ifndef SOCK_CLOEXEC
# define SOCK_CLOEXEC 02000000
#endif

#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0x4000
#endif

#ifndef SHUT_RD
# define SHUT_RD 0
#endif

#ifndef SHUT_WR
# define SHUT_WR 1
#endif

#ifndef SHUT_RDWR
# define SHUT_RDWR 2
#endif

typedef unsigned int socklen_t;

struct msghdr {
    void *msg_name;
    socklen_t msg_namelen;
    struct iovec *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    int msg_flags;
};

struct cmsghdr {
    size_t cmsg_len;
    int cmsg_level;
    int cmsg_type;
};

#ifndef SCM_RIGHTS
# define SCM_RIGHTS 1
#endif

#define CMSG_DATA(cmsg) ((unsigned char *) ((struct cmsghdr *) (cmsg) + 1))
#define CMSG_NXTHDR(mhdr, cmsg) __cmsg_nxthdr (mhdr, cmsg)
#define CMSG_FIRSTHDR(mhdr) \
  ((size_t) (mhdr)->msg_controllen >= sizeof (struct cmsghdr)		      \
   ? (struct cmsghdr *) (mhdr)->msg_control : (struct cmsghdr *) 0)
#define CMSG_ALIGN(len) (((len) + sizeof (size_t) - 1) \
                         & (size_t) ~(sizeof (size_t) - 1))
#define CMSG_SPACE(len) (CMSG_ALIGN (len) \
                         + CMSG_ALIGN (sizeof (struct cmsghdr)))
#define CMSG_LEN(len)   (CMSG_ALIGN (sizeof (struct cmsghdr)) + (len))

#include <linux/uio.h>

struct sockopt {
    int receivebuf, sendbuf;
    int receivetimeout, sendtimeout;
    int linger;
    int reuseaddr:1;
    int tcp_cork:1;
    int tcp_keepalive:1;
    int tcp_nodelay:1;
};

#endif
