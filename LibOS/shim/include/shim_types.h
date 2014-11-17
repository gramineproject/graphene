/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#ifndef _SHIM_TYPES_H_
#define _SHIM_TYPES_H_

#define _GNU_SOURCE
#include <features.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ustat.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <asm/statfs.h>
#include <asm/ldt.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/utsname.h>
#include <linux/times.h>
#include <linux/shm.h>
#include <linux/msg.h>
#include <linux/sem.h>
#include <linux/kernel.h>
#include <linux/utime.h>
#include <linux/futex.h>
#include <linux/aio_abi.h>
#include <linux/perf_event.h>

typedef unsigned int __u32;

/* linux/time.h */
struct __kernel_timespec {
    __kernel_time_t tv_sec;         /* seconds */
    long            tv_nsec;        /* nanoseconds */
};

struct __kernel_timeval {
    __kernel_time_t         tv_sec;         /* seconds */
    __kernel_suseconds_t    tv_usec;        /* microsecond */
};

struct __kernel_itimerspec {
    struct __kernel_timespec it_interval;    /* timer period */
    struct __kernel_timespec it_value;       /* timer expiration */
};

struct __kernel_itimerval {
    struct __kernel_timeval it_interval;     /* time interval */
    struct __kernel_timeval it_value;        /* current value */
};

struct __kernel_timezone {
    int tz_minuteswest; /* minutes west of Greenwich */
    int tz_dsttime;     /* type of dst correction */
};


/* linux/time.h
 * syscall interface - used (mainly by NTP daemon)
 * to discipline kernel clock oscillator
 */
struct __kernel_timex {
    unsigned int modes; /* mode selector */
    long offset;        /* time offset (usec) */
    long freq;          /* frequency offset (scaled ppm) */
    long maxerror;      /* maximum error (usec) */
    long esterror;      /* estimated error (usec) */
    int status;         /* clock command/status */
    long constant;      /* pll time constant */
    long precision;     /* clock precision (usec) (read only) */
    long tolerance;     /* clock frequency tolerance (ppm)
                         * (read only) */
    struct __kernel_timeval time;    /* (read only) */
    long tick;              /* (modified) usecs between clock ticks */

    long ppsfreq;           /* pps frequency (scaled ppm) (ro) */
    long jitter;            /* pps jitter (us) (ro) */
    int shift;              /* interval duration (s) (shift) (ro) */
    long stabil;            /* pps stability (scaled ppm) (ro) */
    long jitcnt;            /* jitter limit exceeded (ro) */
    long calcnt;            /* calibration intervals (ro) */
    long errcnt;            /* calibration errors (ro) */
    long stbcnt;            /* stability limit exceeded (ro) */

    int tai;                /* TAI offset (ro) */

    int  :32; int  :32; int  :32; int  :32;
    int  :32; int  :32; int  :32; int  :32;
    int  :32; int  :32; int  :32;
};


/* /arch/x86/include/asm/posix_types_64.h */
typedef unsigned int   __kernel_uid_t;
typedef __kernel_uid_t __kernel_uid32_t;


/* quota.h */
typedef __kernel_uid32_t qid_t; /* Type in which we store ids in memory */


/* capability.h */
typedef struct __user_cap_header_struct {
    __u32 version;
    int pid;
} *cap_user_header_t;

typedef struct __user_cap_data_struct {
    __u32 effective;
    __u32 permitted;
    __u32 inheritable;
} *cap_user_data_t;


/* defined in function in sysdeps/unix/sysv/linux/sysctl.c */
struct __kernel_sysctl_args {
    int    *name;    /* integer vector describing variable */
    int     nlen;    /* length of this vector */
    void   *oldval;  /* 0 or address where to store old value */
    size_t *oldlenp; /* available room for old value,
                        overwritten by actual size of old value */
    void   *newval;  /* 0 or address of new value */
    size_t  newlen;  /* size of new value */
};

struct __kernel_sched_param {
    int __sched_priority;
};

struct __kernel_sigaction {
    __sighandler_t k_sa_handler;
    unsigned long sa_flags;
    void (*sa_restorer) (void);
    sigset_t sa_mask;
};

/* linux/aio_abi.h (for io_setup which has no glibc wrapper) */
typedef unsigned long aio_context_t;

/* linux/rlimit.h */
struct __kernel_rusage {
    struct __kernel_timeval ru_utime;    /* user time used */
    struct __kernel_timeval ru_stime;    /* system time used */
    long    ru_maxrss;          /* maximum resident set size */
    long    ru_ixrss;           /* integral shared memory size */
    long    ru_idrss;           /* integral unshared data size */
    long    ru_isrss;           /* integral unshared stack size */
    long    ru_minflt;          /* page reclaims */
    long    ru_majflt;          /* page faults */
    long    ru_nswap;           /* swaps */
    long    ru_inblock;         /* block input operations */
    long    ru_oublock;         /* block output operations */
    long    ru_msgsnd;          /* messages sent */
    long    ru_msgrcv;          /* messages received */
    long    ru_nsignals;        /* signals received */
    long    ru_nvcsw;           /* voluntary context switches */
    long    ru_nivcsw;          /* involuntary " */
};

struct __kernel_rlimit {
    unsigned long    rlim_cur;
    unsigned long    rlim_max;
};

/* linux/eventpoll.h
 * On x86-64 make the 64bit structure have the same alignment as the
 * 32bit structure. This makes 32bit emulation easier.
 *
 * UML/x86_64 needs the same packing as x86_64
 */
struct __kernel_epoll_event {
    __u32 events;
    __u64 data;
}
#ifdef __x86_64__
__attribute__((packed));
#else
;
#endif

/* buts/socket.h */
#ifndef __USE_GNU
/* For `recvmmsg'.  */
struct mmsghdr {
    struct msghdr msg_hdr;  /* Actual message header.  */
    unsigned int msg_len;   /* Number of received bytes for the entry.  */
};
#endif


/* linux/mqueue.h */
struct __kernel_mq_attr {
    long    mq_flags;       /* message queue flags */
    long    mq_maxmsg;      /* maximum number of messages */
    long    mq_msgsize;     /* maximum message size */
    long    mq_curmsgs;     /* number of messages currently queued */
    long    __reserved[4];  /* ignored for input, zeroed for output */
};


/* bits/sched.h */
/* Type for array elements in 'cpu_set_t'.  */
typedef unsigned long int __kernel_cpu_mask;

/* Size definition for CPU sets.  */
# define __CPU_SETSIZE 1024
# define __NCPUBITS (8 * sizeof (__kernel_cpu_mask))

/* Data structure to describe CPU mask.  */
typedef struct {
  __kernel_cpu_mask __bits[__CPU_SETSIZE / __NCPUBITS];
} __kernel_cpu_set_t;

# undef __CPU_SETSIZE
# undef __NCPUBITS

#define LINUX_DT_UNKNOWN  0
#define LINUX_DT_FIFO     1
#define LINUX_DT_CHR      2
#define LINUX_DT_DIR      4
#define LINUX_DT_BLK      6
#define LINUX_DT_REG      8
#define LINUX_DT_LNK      10
#define LINUX_DT_SOCK     12
#define LINUX_DT_WHT      14

struct linux_dirent64 {
    uint64_t            d_ino;      /* Inode number */
    uint64_t            d_off;      /* Offset to next linux_dirent */
    unsigned short int  d_reclen;   /* Length of this linux_dirent */
    unsigned char       d_type;
    char                d_name[];   /* File name (null-terminated) */
};

struct linux_dirent {
    unsigned long       d_ino;      /* Inode number */
    unsigned long       d_off;      /* Offset to next linux_dirent */
    unsigned short int  d_reclen;   /* Length of this linux_dirent */
    char                d_name[];   /* File name (null-terminated) */
};

struct linux_dirent_tail {
    char                pad;
    unsigned char       d_type;
};

struct __kernel_addrinfo
{
  int ai_flags;			/* Input flags.  */
  int ai_family;		/* Protocol family for socket.  */
  int ai_socktype;		/* Socket type.  */
  int ai_protocol;		/* Protocol for socket.  */
  socklen_t ai_addrlen;		/* Length of socket address.  */
  struct sockaddr *ai_addr;	/* Socket address for socket.  */
  char *ai_canonname;		/* Canonical name for service location.  */
  struct addrinfo *ai_next;	/* Pointer to next in list.  */
};

#include "elf.h"

#ifdef __x86_64__
typedef Elf64_auxv_t elf_auxv_t;
#else
typedef Elf64_auxv_t elf_auxv_t;
#endif

/* typedef for shim internal types */
typedef unsigned int IDTYPE;
typedef uint16_t FDTYPE;
typedef unsigned long LEASETYPE;
typedef unsigned long HASHTYPE;

struct shim_atomic {
#ifndef __i386__
    long counter;
#else
    int counter;
#endif
};

typedef struct shim_atomic REFTYPE;

#include <pal.h>

typedef struct shim_lock {
    PAL_HANDLE lock;
    IDTYPE owner;
} LOCKTYPE;

typedef struct shim_aevent {
    PAL_HANDLE event;
} AEVENTTYPE;

#define STR_SIZE    256

struct shim_str {
    char str[STR_SIZE];
};

#define QSTR_SIZE   32

/* Use qstr for names. This has fix size string + string object
 * if len > SHIM_QSTR_SIZE then use overflow string */
struct shim_qstr {
    HASHTYPE    hash;
    size_t      len;
    char        name[QSTR_SIZE];
    struct shim_str * oflow;
};

#endif /* _SHIM_TYPES_H_ */
