#ifndef _SHIM_TYPES_H_
#define _SHIM_TYPES_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define __KERNEL__

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
#include <linux/timex.h>
#include <linux/version.h>

#include <asm/posix_types.h>
#include <asm/statfs.h>
#include <asm/stat.h>
#include <asm/ldt.h>
#include <asm/signal.h>
#include <asm/siginfo.h>
#include <asm/poll.h>

typedef unsigned int        __u32;

typedef unsigned long int   nfds_t;
typedef unsigned long int   nlink_t;

typedef uint32_t            socklen_t;
typedef __kernel_uid_t      uid_t;
typedef __kernel_gid_t      gid_t;
typedef __kernel_pid_t      pid_t;
typedef __kernel_caddr_t    caddr_t;
typedef __kernel_mode_t     mode_t;
typedef __kernel_off_t      off_t;
typedef __kernel_loff_t     loff_t;
typedef __kernel_time_t     time_t;
typedef __kernel_old_dev_t  dev_t;
typedef __kernel_ino_t      ino_t;
typedef __kernel_clockid_t  clockid_t;
typedef __kernel_key_t      key_t;
typedef __kernel_timer_t    timer_t;
typedef __kernel_fd_set     fd_set;

/* linux/time.h */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
struct __kernel_timespec {
    __kernel_time_t tv_sec;         /* seconds */
    long            tv_nsec;        /* nanoseconds */
};

struct __kernel_itimerspec {
    struct __kernel_timespec it_interval;    /* timer period */
    struct __kernel_timespec it_value;       /* timer expiration */
};
#endif

struct __kernel_timeval {
    __kernel_time_t         tv_sec;         /* seconds */
    __kernel_suseconds_t    tv_usec;        /* microsecond */
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
struct ____kernel_timex {
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

/* asm/signal.h */
#define NUM_SIGS            64
#define NUM_KNOWN_SIGS      32

typedef struct {
    unsigned long __val[NUM_SIGS / (8 * sizeof(unsigned long))];
} __sigset_t;

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
    unsigned long rlim_cur, rlim_max;
};

struct __kernel_rlimit64 {
    uint64_t rlim_cur, rlim_max;
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

/* sys/ucontext.h */
/* Type for general register.  */
typedef long int greg_t;

/* Number of general registers.  */
#define NGREG    23

/* Container for all general registers.  */
typedef greg_t gregset_t[NGREG];

/* Number of each register in the `gregset_t' array.  */
enum
{
    REG_R8 = 0,
# define REG_R8     REG_R8
    REG_R9,
# define REG_R9     REG_R9
    REG_R10,
# define REG_R10    REG_R10
    REG_R11,
# define REG_R11    REG_R11
    REG_R12,
# define REG_R12    REG_R12
    REG_R13,
# define REG_R13    REG_R13
    REG_R14,
# define REG_R14    REG_R14
    REG_R15,
# define REG_R15    REG_R15
    REG_RDI,
# define REG_RDI    REG_RDI
    REG_RSI,
# define REG_RSI    REG_RSI
    REG_RBP,
# define REG_RBP    REG_RBP
    REG_RBX,
# define REG_RBX    REG_RBX
    REG_RDX,
# define REG_RDX    REG_RDX
    REG_RAX,
# define REG_RAX    REG_RAX
    REG_RCX,
# define REG_RCX    REG_RCX
    REG_RSP,
# define REG_RSP    REG_RSP
    REG_RIP,
# define REG_RIP    REG_RIP
    REG_EFL,
# define REG_EFL    REG_EFL
    REG_CSGSFS,        /* Actually short cs, gs, fs, __pad0.  */
# define REG_CSGSFS REG_CSGSFS
    REG_ERR,
# define REG_ERR    REG_ERR
    REG_TRAPNO,
# define REG_TRAPNO REG_TRAPNO
    REG_OLDMASK,
# define REG_OLDMASK REG_OLDMASK
    REG_CR2
# define REG_CR2    REG_CR2
};

struct _libc_fpxreg {
    unsigned short int significand[4];
    unsigned short int exponent;
    unsigned short int padding[3];
};

struct _libc_xmmreg {
    __uint32_t    element[4];
};

struct _libc_fpstate {
    /* 64-bit FXSAVE format.  */
    __uint16_t          cwd;
    __uint16_t          swd;
    __uint16_t          ftw;
    __uint16_t          fop;
    __uint64_t          rip;
    __uint64_t          rdp;
    __uint32_t          mxcsr;
    __uint32_t          mxcr_mask;
    struct _libc_fpxreg st[8];
    struct _libc_xmmreg _xmm[16];
    __uint32_t          padding[24];
};

/* Structure to describe FPU registers.  */
typedef struct _libc_fpstate *fpregset_t;

/* Context to describe whole processor state.  */
typedef struct {
    gregset_t gregs;
    /* Note that fpregs is a pointer.  */
    fpregset_t fpregs;
    unsigned long __reserved1 [8];
} mcontext_t;

/* Userlevel context.  */
typedef struct ucontext {
    unsigned long int uc_flags;
    struct ucontext *uc_link;
    stack_t uc_stack;
    mcontext_t uc_mcontext;
    __sigset_t uc_sigmask;
    struct _libc_fpstate __fpregs_mem;
} ucontext_t;

#define RED_ZONE_SIZE   128

/* bits/ustat.h */
struct __kernel_ustat
  {
    __daddr_t f_tfree;		/* Number of free blocks.  */
    __ino_t f_tinode;		/* Number of free inodes.  */
    char f_fname[6];
    char f_fpack[6];
  };

/* bits/socket.h */
enum
{
    MSG_OOB  = 0x01, /* Process out-of-band data. */
    MSG_PEEK = 0x02, /* Peek at incoming messages. */
#define MSG_OOB MSG_OOB
#define MSG_PEEK MSG_PEEK
};

struct msghdr {
    void *msg_name;         /* Address to send to/receive from.  */
    socklen_t msg_namelen;  /* Length of address data.  */

    struct iovec *msg_iov;  /* Vector of data to send/receive into.  */
    size_t msg_iovlen;      /* Number of elements in the vector.  */

    void *msg_control;      /* Ancillary data (eg BSD filedesc passing). */
    size_t msg_controllen;  /* Ancillary data buffer length.
                               !! The type should be socklen_t but the
                               definition of the kernel is incompatible
                               with this.  */

    int msg_flags;          /* Flags on received message.  */
};

/* For `recvmmsg'.  */
struct mmsghdr {
    struct msghdr msg_hdr;  /* Actual message header.  */
    unsigned int msg_len;   /* Number of received bytes for the entry.  */
};

/* POSIX.1g specifies this type name for the `sa_family' member.  */
typedef unsigned short int sa_family_t;

/* This macro is used to declare the initial common members
   of the data types used for socket addresses, `struct sockaddr',
   `struct sockaddr_in', `struct sockaddr_un', etc.  */

#define	__SOCKADDR_COMMON(sa_prefix) \
  sa_family_t sa_prefix##family


/* Structure describing a generic socket address.  */
struct sockaddr {
    __SOCKADDR_COMMON (sa_);    /* Common data: address family and length.  */
    char sa_data[14];           /* Address data.  */
};

/* linux/mqueue.h */
struct __kernel_mq_attr {
    long    mq_flags;       /* message queue flags */
    long    mq_maxmsg;      /* maximum number of messages */
    long    mq_msgsize;     /* maximum message size */
    long    mq_curmsgs;     /* number of messages currently queued */
    long    __reserved[4];  /* ignored for input, zeroed for output */
};

/* bits/uio.h */
/* Structure for scatter/gather I/O.  */
struct iovec {
    void * iov_base;    /* Pointer to data.  */
    size_t iov_len;     /* Length of data.  */
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

struct getcpu_cache {
    unsigned long blob[128 / sizeof(long)];
};

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

struct linux_file_handle {
    unsigned int handle_bytes;
    int handle_type;
    unsigned char f_handle[0];
};

struct __kernel_addrinfo
{
  int ai_flags;                 /* Input flags.  */
  int ai_family;                /* Protocol family for socket.  */
  int ai_socktype;              /* Socket type.  */
  int ai_protocol;              /* Protocol for socket.  */
  socklen_t ai_addrlen;         /* Length of socket address.  */
  struct sockaddr *ai_addr;     /* Socket address for socket.  */
  char *ai_canonname;           /* Canonical name for service location.  */
  struct addrinfo *ai_next;     /* Pointer to next in list.  */
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
typedef uint64_t HASHTYPE;

typedef struct atomic_int REFTYPE;

#include <pal.h>

struct shim_lock {
    PAL_HANDLE lock;
    IDTYPE owner;
};

typedef struct shim_aevent {
    PAL_HANDLE event;
} AEVENTTYPE;

#define STR_SIZE    4096

struct shim_str {
    char str[STR_SIZE];
};

#define QSTR_SIZE   32

/* Use qstr for names. This has fixed size string + string object
 * if len > SHIM_QSTR_SIZE then use overflow string */
struct shim_qstr {
    HASHTYPE    hash;
    size_t      len;
    char        name[QSTR_SIZE];
    struct shim_str * oflow;
};

#endif /* _SHIM_TYPES_H_ */
