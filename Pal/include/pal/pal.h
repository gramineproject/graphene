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

/*!
 * \file pal.h
 *
 * This file contains definition of PAL host ABI.
 */

#ifndef PAL_H
#define PAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

typedef uint64_t      PAL_NUM; /*!< a number */
typedef const char *  PAL_STR; /*!< a pointer to a C-string */
typedef void *        PAL_PTR; /*!< a pointer to memory or buffer (something other than string) */
typedef uint32_t      PAL_FLG; /*!< a set of flags */
typedef uint32_t      PAL_IDX; /*!< an index */

/*!
 * \brief a boolean value (either #PAL_TRUE or #PAL_FALSE)
 *
 * This data type is commonly used as the return value of
 * a PAL API to determine whether the call succeeded
 */
typedef bool          PAL_BOL;

/*!
 * True value for #PAL_BOL.
 */
#define PAL_TRUE  true

/*!
 * False value for #PAL_BOL.
 */
#define PAL_FALSE false

/* Moved MAX_FDS from <host_kernel>/pal_host.h to here,
 * since it is 3, across all host kernels. */
#define MAX_FDS 3

#ifdef IN_PAL
#include <atomic.h>
typedef struct atomic_int PAL_REF;

typedef struct {
    PAL_IDX type;
    PAL_FLG flags;
} PAL_HDR;

# include "pal_host.h"

# ifndef HANDLE_HDR
#  define HANDLE_HDR(handle) (&((handle)->hdr))
# endif

static inline void init_handle_hdr(PAL_HDR *hdr, int pal_type) {
    hdr->type = pal_type;
    hdr->flags = 0;
}

# define SET_HANDLE_TYPE(handle, t) init_handle_hdr(HANDLE_HDR(handle), pal_type_##t)
# define IS_HANDLE_TYPE(handle, t) (HANDLE_HDR(handle)->type == pal_type_##t)

#else
typedef union pal_handle
{
    struct {
        PAL_IDX type;
        /* the PAL-level reference counting is deprecated */
    } hdr;
}* PAL_HANDLE;

# ifndef HANDLE_HDR
#  define HANDLE_HDR(handle) (&((handle)->hdr))
# endif

#endif /* !IN_PAL */

#define PAL_LIBOS_TCB_SIZE  256

typedef struct pal_tcb {
    struct pal_tcb * self;
    /* uint64_t for alignment */
    uint64_t libos_tcb[(PAL_LIBOS_TCB_SIZE + sizeof(uint64_t) - 1) / sizeof(uint64_t)];
    /* data private to PAL implementation follows this struct. */
} PAL_TCB;

static inline PAL_TCB * pal_get_tcb (void)
{
    PAL_TCB * tcb;
    __asm__ ("movq %%gs:%c1,%q0"
             : "=r" (tcb)
             : "i" (offsetof(struct pal_tcb, self)));
    return tcb;
}

#ifdef __x86_64__
union pal_csgsfs {
    struct {
        uint16_t cs;
        uint16_t gs;
        uint16_t fs;
        uint16_t ss;
    };
    uint64_t csgsfs;
};

/* Adopt Linux style fp layout, _libc_fpstate of glibc:
 * Because self-contained definition is needed for Pal definition,
 * same layout is defined with PAL prefix.
 */
#define PAL_FP_XSTATE_MAGIC1        0x46505853U
#define PAL_FP_XSTATE_MAGIC2        0x46505845U
#define PAL_FP_XSTATE_MAGIC2_SIZE   (sizeof(PAL_FP_XSTATE_MAGIC2))

enum PAL_XFEATURE {
    PAL_XFEATURE_FP,
    PAL_XFEATURE_SSE,
    PAL_XFEATURE_YMM,
    PAL_XFEATURE_BNDREGS,
    PAL_XFEATURE_BNDCSR,
    PAL_XFEATURE_OPMASK,
    PAL_XFEATURE_ZMM_Hi256,
    PAL_XFEATURE_Hi16_ZMM,
    PAL_XFEATURE_PT,
    PAL_XFEATURE_PKRU,

    PAL_XFEATURE_MAX,
};

#define PAL_XFEATURE_MASK_FP                (1UL << PAL_XFEATURE_FP)
#define PAL_XFEATURE_MASK_SSE               (1UL << PAL_XFEATURE_SSE)
#define PAL_XFEATURE_MASK_YMM               (1UL << PAL_XFEATURE_YMM)
#define PAL_XFEATURE_MASK_BNDREGS           (1UL << PAL_XFEATURE_BNDREGS)
#define PAL_XFEATURE_MASK_BNDCSR            (1UL << PAL_XFEATURE_BNDCSR)
#define PAL_XFEATURE_MASK_OPMASK            (1UL << PAL_XFEATURE_OPMASK)
#define PAL_XFEATURE_MASK_ZMM_Hi256         (1UL << PAL_XFEATURE_ZMM_Hi256)
#define PAL_XFEATURE_MASK_Hi16_ZMM          (1UL << PAL_XFEATURE_Hi16_ZMM)
#define PAL_XFEATURE_MASK_PT                (1UL << PAL_XFEATURE_PT)
#define PAL_XFEATURE_MASK_PKRU              (1UL << PAL_XFEATURE_PKRU)

#define PAL_XFEATURE_MASK_FPSSE             (PAL_XFEATURE_MASK_FP \
                                             | PAL_XFEATURE_MASK_SSE)
#define PAL_XFEATURE_MASK_AVX512            (PAL_XFEATURE_MASK_OPMASK \
                                             | PAL_XFEATURE_MASK_ZMM_Hi256 \
                                             | PAL_XFEATURE_MASK_Hi16_ZMM)

typedef struct {
    uint32_t magic1;        /*!< PAL_FP_XSTATE_MAGIC1 */
    uint32_t extended_size; /*!< xsave_size */
    uint64_t xfeatures;     /*!< XSAVE feature */
    uint32_t xstate_size;   /*!< xsave_size + PAL_FP_STATE_MAGIC2_SIZE */
    uint32_t padding[7];
} PAL_FPX_SW_BYTES;

typedef struct {
    uint32_t cwd;
    uint32_t swd;
    uint32_t twd;
    uint32_t fip;
    uint32_t fcs;
    uint32_t foo;
    uint32_t fos;
    uint32_t st_space[20];
    uint8_t ftop;
    uint8_t changed;
    uint8_t lookahead;
    uint8_t no_update;
    uint8_t rm;
    uint8_t alimit;
    void* info; /* struct math_emu_info */
    uint32_t entry_eip;
} PAL_SWREGS_STATE;

typedef struct {
    uint16_t significand[4];
    uint16_t exponent;
    uint16_t padding[3];
} PAL_FPXREG;

typedef struct {
    uint32_t element[4];
} PAL_XMMREG;

typedef struct {
    /* 64-bit FXSAVE format.  */
    uint16_t cwd;
    uint16_t swd;
    uint16_t ftw;
    uint16_t fop;
    uint64_t rip;
    uint64_t rdp;
    uint32_t mxcsr;
    uint32_t mxcr_mask;
    PAL_FPXREG st[8];
    PAL_XMMREG xmm[16];
    union {
        uint32_t padding[24];
        struct {
            uint32_t padding2[12];
            PAL_FPX_SW_BYTES sw_reserved;
        };
    };
} PAL_FPSTATE;

typedef struct {
    uint64_t xfeatures;
    uint64_t xcomp_bv;
    uint64_t reserved[6];
} __attribute__((packed)) PAL_XSTATE_HEADER;

#define PAL_XSTATE_ALIGN 64

typedef struct {
    PAL_FPSTATE fpstate;
    PAL_XSTATE_HEADER header;
} __attribute__((packed, aligned(PAL_XSTATE_ALIGN))) PAL_XREGS_STATE;
#else
# error "Unsupported architecture"
#endif

typedef struct PAL_CONTEXT_ {
#ifdef __x86_64__
    PAL_NUM r8, r9, r10, r11, r12, r13, r14, r15;
    PAL_NUM rdi, rsi, rbp, rbx, rdx, rax, rcx;
    PAL_NUM rsp, rip;
    PAL_NUM efl, csgsfs, err, trapno, oldmask, cr2;
    PAL_XREGS_STATE* fpregs;
#else
# error "Unsupported architecture"
#endif
} PAL_CONTEXT;

/********** PAL TYPE DEFINITIONS **********/
enum {
    pal_type_file,
    pal_type_pipe,
    pal_type_pipesrv,
    pal_type_pipecli,
    pal_type_pipeprv,
    pal_type_dev,
    pal_type_dir,
    pal_type_tcp,
    pal_type_tcpsrv,
    pal_type_udp,
    pal_type_udpsrv,
    pal_type_process,
    pal_type_thread,
    pal_type_mutex,
    pal_type_event,
    pal_type_eventfd,
    PAL_HANDLE_TYPE_BOUND,
};

#define PAL_IDX_POISON          ((PAL_IDX)-1) /* PAL identifier poison value */
#define PAL_GET_TYPE(h)         (HANDLE_HDR(h)->type)
#define PAL_CHECK_TYPE(h, t)    (PAL_GET_TYPE(h) == pal_type_##t)
#define UNKNOWN_HANDLE(handle)  (PAL_GET_TYPE(handle) >= PAL_HANDLE_TYPE_BOUND)

typedef struct PAL_PTR_RANGE_ { PAL_PTR start, end; } PAL_PTR_RANGE;

typedef struct PAL_CPU_INFO_ {
    PAL_NUM cpu_num;
    PAL_STR cpu_vendor;
    PAL_STR cpu_brand;
    PAL_NUM cpu_family;
    PAL_NUM cpu_model;
    PAL_NUM cpu_stepping;
    double  cpu_bogomips;
    PAL_STR cpu_flags;
} PAL_CPU_INFO;

typedef struct PAL_MEM_INFO_ {
    PAL_NUM mem_total;
} PAL_MEM_INFO;

/********** PAL APIs **********/
typedef struct PAL_CONTROL_ {
    PAL_STR host_type;
    PAL_NUM process_id; /*!< An identifier of current picoprocess */
    PAL_NUM host_id;

    /*
     * Handles and executables
     */
    PAL_HANDLE manifest_handle; /*!< program manifest */
    PAL_STR executable; /*!< executable name */
    PAL_HANDLE parent_process; /*!< handle of parent process */
    PAL_HANDLE first_thread; /*!< handle of first thread */
    PAL_HANDLE debug_stream; /*!< debug stream */

    /*
     * Memory layout
     */
    PAL_PTR_RANGE user_address; /*!< The range of user addresses */

    /*!
     * \brief Reserved memory range inside of user address.
     *
     * Used for example by SGX for exec area (including memory gap) in the
     * middle of the heap. If unused set start == end.
     */
    PAL_PTR_RANGE user_address_hole;

    PAL_PTR_RANGE executable_range; /*!< address where executable is loaded */
    PAL_PTR_RANGE manifest_preload; /*!< manifest preloaded here */

    /*
     * Host information
     */

    /*!
     * \brief Host allocation alignment.
     *
     * This currently is (and most likely will always be) indistinguishable from the page size,
     * looking from the LibOS perspective. The two values can be different on the PAL level though,
     * see e.g. SYSTEM_INFO::dwAllocationGranularity on Windows.
     */
    PAL_NUM alloc_align;

    PAL_CPU_INFO cpu_info; /*!< CPU information (only required ones) */
    PAL_MEM_INFO mem_info; /*!< memory information (only required ones) */

    /* Purely for profiling */
    PAL_NUM startup_time;
    PAL_NUM host_specific_startup_time;
    PAL_NUM relocation_time;
    PAL_NUM linking_time;
    PAL_NUM manifest_loading_time;
    PAL_NUM allocation_time;
    PAL_NUM tail_startup_time;
    PAL_NUM child_creation_time;
} PAL_CONTROL;

#define pal_control (*pal_control_addr())
PAL_CONTROL * pal_control_addr (void);

/*
 * MEMORY ALLOCATION
 */

/*! Memory Allocation Flags */
enum PAL_ALLOC {
    PAL_ALLOC_RESERVE  = 0x0001, /*!< Only reserve the memory */
    PAL_ALLOC_INTERNAL = 0x8000, /*!< Allocate for PAL (valid only if #IN_PAL) */
};

/*! Memory Protection Flags */
enum PAL_PROT {
    PAL_PROT_NONE      = 0x0,
    PAL_PROT_READ      = 0x1,
    PAL_PROT_WRITE     = 0x2,
    PAL_PROT_EXEC      = 0x4,
    PAL_PROT_WRITECOPY = 0x8, /*!< Copy on write */

    PAL_PROT_MASK      = 0xF,
};


/*!
 * \brief Allocate virtual memory for the library OS.
 *
 * \param addr
 *  can be either `NULL` or any valid address aligned at the allocation alignment. When `addr` is
 *  non-NULL, the API will try to allocate the memory at the given address and potentially rewrite
 *  any memory previously allocated at the same address. Overwriting any part of PAL and host kernel
 *  is forbidden.
 * \param size must be a positive number, aligned at the allocation alignment.
 * \param alloc_type can be a combination of any of the #PAL_ALLOC flags
 * \param prot can be a combination of the #PAL_PROT flags
 */
PAL_PTR
DkVirtualMemoryAlloc(PAL_PTR addr, PAL_NUM size, PAL_FLG alloc_type, PAL_FLG prot);

/*!
 * \brief This API deallocates a previously allocated memory mapping.
 *
 * \param addr the address
 * \param size the size
 *
 * Both `addr` and `size` must be non-zero and aligned at the allocation alignment.
 */
void
DkVirtualMemoryFree(PAL_PTR addr, PAL_NUM size);


/*!
 * \brief Modify the permissions of a previously allocated memory mapping.
 *
 * \param addr the address
 * \param size the size
 * \param prot see #DkVirtualMemoryAlloc()
 *
 * Both `addr` and `size` must be non-zero and aligned at the allocation alignment.
 */
PAL_BOL
DkVirtualMemoryProtect(PAL_PTR addr, PAL_NUM size, PAL_FLG prot);


/*
 * PROCESS CREATION
 */

#define PAL_PROCESS_MASK         0x0

/*!
* \brief Create a new process to run a separate executable.
*
* \param uri the URI of the manifest file or the executable to be loaded in the new process.
* \param args an array of strings -- the arguments to be passed to the new process.
*/
PAL_HANDLE
DkProcessCreate(PAL_STR uri, PAL_STR* args);

/*!
 * \brief Magic exit code that instructs the exiting process to wait for its children
 *
 * Required for a corner case when the parent exec's the child in a new Graphene process: for
 * correctness, the parent cannot immediately exit since it may have a parent that waits on it.
 * If an application by coincidence picks this magic number as its exit code, it is changed to
 * another exit code so as to not confuse the PAL code.
 */
#define PAL_WAIT_FOR_CHILDREN_EXIT (1024 * 1024)

/*!
 * \brief Terminate all threads in the process immediately.
 *
 * \param exitCode the exit value returned to the host.
 */
noreturn void
DkProcessExit(PAL_NUM exitCode);

/*
 * STREAMS
 */

/*! Stream Access Flags */
enum PAL_ACCESS {
    PAL_ACCESS_RDONLY = 00,
    PAL_ACCESS_WRONLY = 01,
    PAL_ACCESS_RDWR   = 02,
    PAL_ACCESS_APPEND = 04,
    PAL_ACCESS_MASK   = 07,
};

/*! Stream Sharing Flags */
enum PAL_SHARE {
    PAL_SHARE_GLOBAL_X =   01,
    PAL_SHARE_GLOBAL_W =   02,
    PAL_SHARE_GLOBAL_R =   04,
    PAL_SHARE_GROUP_X  =  010,
    PAL_SHARE_GROUP_W  =  020,
    PAL_SHARE_GROUP_R  =  040,
    PAL_SHARE_OWNER_X  = 0100,
    PAL_SHARE_OWNER_W  = 0200,
    PAL_SHARE_OWNER_R  = 0400,
    PAL_SHARE_MASK     = 0777,
};

/*! Stream Create Flags */
enum PAL_CREATE {
    PAL_CREATE_TRY       = 0100,  /*!< Create file if file not exist (O_CREAT) */
    PAL_CREATE_ALWAYS    = 0200,  /*!< Create file and fail if file already exist
                                       (O_CREAT|O_EXCL) */
    PAL_CREATE_DUALSTACK = 0400,  /*!< Create dual-stack socket (opposite of IPV6_V6ONLY) */

    PAL_CREATE_MASK      = 0700,
};

/*! Stream Option Flags */
enum PAL_OPTION {
    PAL_OPTION_CLOEXEC       = 01000,
    PAL_OPTION_EFD_SEMAPHORE = 02000, /*!< specific to `eventfd` syscall */
    PAL_OPTION_NONBLOCK      = 04000,

    PAL_OPTION_MASK          = 07000,
};


/*! error value of read/write */
#define PAL_STREAM_ERROR        ((PAL_NUM)-1L)

#define WITHIN_MASK(val, mask)  (((val)|(mask)) == (mask))

/*!
 * \brief Open/create a stream resource specified by `uri`
 *
 * \param uri is the URI of the stream to be opened/created
 * \param access can be a combination of the #PAL_ACCESS flags
 * \param share_flags can be a combination of the #PAL_SHARE flags
 * \param create can be a combination of the #PAL_CREATE flags
 * \param options can be a combination of the #PAL_OPTION flags
 *
 * \return If the resource is successfully opened or created, a PAL handle will be returned for
 * further access such as reading or writing.
 *
 * The following is a list of URIs that are supported:
 * * `%file:...`, `dir:...`: Files or directories on the host file system. If #PAL_CREATE_TRY is
 *   given in `create` flags, the file/directory will be created.
 * * `dev:...`: Open a device as a stream. For example, `dev:tty` represents the standard I/O.
 * * `pipe.srv:<ID>`, `pipe:<ID>`, `pipe:`: Open a byte stream that can be used for RPC between
 *   processes. Pipes are located by numeric IDs. The server side of a pipe can accept any number
 *   of connections. If `pipe:` is given as the URI, it will open an anonymous bidirectional pipe.
 * * `tcp.srv:<ADDR>:<PORT>`, `tcp:<ADDR>:<PORT>`: Open a TCP socket to listen or connect to
 *   a remote TCP socket.
 * * `udp.srv:<ADDR>:<PORT>`, `udp:<ADDR>:<PORT>`: Open a UDP socket to listen or connect to
 *   a remote UDP socket.
 */
PAL_HANDLE
DkStreamOpen(PAL_STR uri, PAL_FLG access, PAL_FLG share_flags, PAL_FLG create, PAL_FLG options);

/*!
 * \brief Blocks until a new connection is accepted and returns the PAL handle for the connection.
 *
 * This API is only available for handles that are opened with `pipe.srv:...`, `tcp.srv:...`, and
 * `udp.srv:...`.
 */
PAL_HANDLE
DkStreamWaitForClient(PAL_HANDLE handle);

/*!
 * \brief Read data from an opened stream.
 *
 * If the handle is a file, `offset` must be specified at each call of DkStreamRead. `source` and
 * `size` can be used to return the remote socket address if the handle is a UDP socket. If the
 * handle is a directory, DkStreamRead fills the buffer with the names (NULL-ended) of the files or
 * subdirectories inside of this directory.
 */
PAL_NUM
DkStreamRead(PAL_HANDLE handle, PAL_NUM offset, PAL_NUM count, PAL_PTR buffer, PAL_PTR source,
             PAL_NUM size);

/*!
 * \brief Write data to an opened stream.
 *
 * If the handle is a file, `offset` must be specified at each call of DkStreamWrite. `dest` can be
 * used to specify the remote socket address if the handle is a UDP socket.
 */
PAL_NUM
DkStreamWrite(PAL_HANDLE handle, PAL_NUM offset, PAL_NUM count, PAL_PTR buffer, PAL_STR dest);

enum PAL_DELETE {
    PAL_DELETE_RD = 01, /*!< shut down the read side only */
    PAL_DELETE_WR = 02, /*!< shut down the write side only */
};

/*!
 * \brief Delete files or directories on the host or shut down the connection of TCP/UDP sockets.
 *
 * \param access which side to shut down (#PAL_DELETE), or both if 0 is given.
 */
void
DkStreamDelete(PAL_HANDLE handle, PAL_FLG access);

/*!
 * \brief Map a file to a virtual memory address in the current process.
 *
 * \param address can be NULL or a valid address that is aligned at the allocation alignment.
 * \param prot see #DkVirtualMemoryAlloc()
 *
 * `offset` and `size` have to be non-zero and aligned at the allocation alignment
 */
PAL_PTR
DkStreamMap(PAL_HANDLE handle, PAL_PTR address, PAL_FLG prot,
            PAL_NUM offset, PAL_NUM size);

/*!
 * \brief Unmap virtual memory that is backed by a file stream.
 *
 * `addr` and `size` must be aligned at the allocation alignment
 */
void
DkStreamUnmap(PAL_PTR addr, PAL_NUM size);

/*!
 * \brief Set the length of the file referenced by handle to `length`.
 *
 * \return Returns the 0 on success, a _positive_ errno on failure.
 */
PAL_NUM
DkStreamSetLength(PAL_HANDLE handle, PAL_NUM length);

/*!
 * \brief Flush the buffer of a file stream.
 */
PAL_BOL
DkStreamFlush(PAL_HANDLE handle);

/*!
 * \brief Send a PAL handle over another handle.
 *
 * Currently, the handle that is used to send cargo must be a process handle.
 *
 * \param cargo the handle being sent
 */
PAL_BOL
DkSendHandle(PAL_HANDLE handle, PAL_HANDLE cargo);

/*!
 * \brief This API receives a handle over another handle.
 */
PAL_HANDLE
DkReceiveHandle(PAL_HANDLE handle);

/* stream attribute structure */
typedef struct _PAL_STREAM_ATTR {
    PAL_IDX handle_type;
    PAL_BOL disconnected;
    PAL_BOL nonblocking;
    PAL_BOL readable, writable, runnable;
    PAL_BOL secure;
    PAL_FLG share_flags;
    PAL_NUM pending_size;
    PAL_IDX no_of_fds;
    PAL_IDX fds[MAX_FDS];
    union {
        struct {
            PAL_NUM linger;
            PAL_NUM receivebuf, sendbuf;
            PAL_NUM receivetimeout, sendtimeout;
            PAL_BOL tcp_cork;
            PAL_BOL tcp_keepalive;
            PAL_BOL tcp_nodelay;
        } socket;
    };
} PAL_STREAM_ATTR;

/*!
 * \brief Query the attributes of a named stream.
 *
 * This API only applies for URIs such as `%file:...`, `dir:...`, and `dev:...`.
 */
PAL_BOL
DkStreamAttributesQuery(PAL_STR uri, PAL_STREAM_ATTR* attr);

/*!
 * \brief Query the attributes of an opened stream.
 *
 * This API applies to any stream handle.
 */
PAL_BOL
DkStreamAttributesQueryByHandle(PAL_HANDLE handle, PAL_STREAM_ATTR* attr);

/*!
 * \brief Set the attributes of an opened stream.
 */
PAL_BOL
DkStreamAttributesSetByHandle(PAL_HANDLE handle, PAL_STREAM_ATTR* attr);

/*!
 * \brief Query the name of an opened stream.
 */
PAL_NUM
DkStreamGetName(PAL_HANDLE handle, PAL_PTR buffer, PAL_NUM size);

/*!
 * \brief This API changes the name of an opened stream.
 */
PAL_BOL
DkStreamChangeName(PAL_HANDLE handle, PAL_STR uri);


/*
 * Thread creation
 */

#define PAL_THREAD_MASK         0

/*!
 * \brief Create a thread in the current process.
 *
 * \param addr is the address of an entry point of execution for the new thread
 * \param param is the pointer argument that is passed to the new thread
 */
PAL_HANDLE
DkThreadCreate(PAL_PTR addr, PAL_PTR param);

/*!
 * \brief Suspend the current thread for a certain duration
 *
 * \param duration the duration in microseconds
 */
PAL_NUM
DkThreadDelayExecution(PAL_NUM duration);

/*!
 * \brief Yield the current thread such that the host scheduler can reschedule it.
 */
void
DkThreadYieldExecution(void);

/*!
 * \brief Terminate the current thread.
 *
 * \param clear_child_tid is the pointer to memory that is erased on thread exit
 *  to notify LibOS (which in turn notifies the parent thread if any); if
 *  `clear_child_tid` is NULL, then PAL doesn't do the clearing.
 */
noreturn void DkThreadExit(PAL_PTR clear_child_tid);

/*!
 * \brief Resume a thread.
 */
PAL_BOL
DkThreadResume(PAL_HANDLE thread);

/*
 * Exception Handling
 */

enum PAL_EVENT {
    /*! arithmetic error (div-by-zero, floating point exception, etc.) */
    PAL_EVENT_ARITHMETIC_ERROR = 1,
    /*! segmentation fault, protection fault, bus fault */
    PAL_EVENT_MEMFAULT         = 2,
    /*! illegal instructions */
    PAL_EVENT_ILLEGAL          = 3,
    /*! terminated by external program */
    PAL_EVENT_QUIT             = 4,
    /*! suspended by external program */
    PAL_EVENT_SUSPEND          = 5,
    /*! continued by external program */
    PAL_EVENT_RESUME           = 6,
    /*! failure within PAL calls */
    PAL_EVENT_FAILURE          = 7,

    PAL_EVENT_NUM_BOUND        = 8,
};

typedef void (*PAL_EVENT_HANDLER) (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT*);

/*!
 * \brief Set the handler for the specific exception event.
 *
 * \param event can be one of #PAL_EVENT values
 */
PAL_BOL
DkSetExceptionHandler(PAL_EVENT_HANDLER handler, PAL_NUM event);

/*!
 * \brief Exit an exception handler and restore the context.
 */
void DkExceptionReturn(PAL_PTR event);

/* parameter: keeping int threadHandle for now (to be in sync with the paper).
 * We may want to replace it with a PAL_HANDLE. Ideally, either use PAL_HANDLE
 * or threadHandle.
 */


/*
 * Synchronization
 */

/*!
 * \brief Create a mutex with the given `initialCount`.
 *
 * Destroy a mutex using DkObjectClose.
 *
 * \param initialCount 0 is unlocked, 1 is locked
 */
PAL_HANDLE
DkMutexCreate(PAL_NUM initialCount);

/*!
 * \brief Unlock the given mutex.
 */
void
DkMutexRelease(PAL_HANDLE mutexHandle);


/*!
 * \brief Creates a notification event with the given `initialState`.
 *
 * The definition of notification events is the same as the WIN32 API. When
 * a notification event is set to the signaled state it remains in that state
 * until it is explicitly cleared.
 */
PAL_HANDLE
DkNotificationEventCreate(PAL_BOL initialState);

/*!
 * \brief Creates a synchronization event with the given `initialState`.
 *
 * The definition of synchronization events is the same as the WIN32 API. When
 * a synchronization event is set to the signaled state, a single thread of
 * execution that was waiting for the event is released, and the event is
 * automatically reset to the not-signaled state.
 */
PAL_HANDLE
DkSynchronizationEventCreate(PAL_BOL initialState);

/*!
 * \brief Set (signal) a notification event or a synchronization event.
 */
void
DkEventSet(PAL_HANDLE eventHandle);

/*!
 * \brief Clear a notification event or a synchronization event.
 */
void
DkEventClear(PAL_HANDLE eventHandle);

/*! block until the handle's event is triggered */
#define NO_TIMEOUT ((PAL_NUM)-1)

/*!
 * \brief Wait on a synchronization handle.
 *
 * \param timeout_us is the maximum time that the API should wait (in
 *  microseconds), or #NO_TIMEOUT to indicate it is to be blocked until the
 *  handle's event is triggered.
 * \return true if this handle's event was triggered, false otherwise
 */
PAL_BOL DkSynchronizationObjectWait(PAL_HANDLE handle, PAL_NUM timeout_us);

enum PAL_WAIT {
    PAL_WAIT_SIGNAL = 1, /*!< ignored in events */
    PAL_WAIT_READ   = 2,
    PAL_WAIT_WRITE  = 4,
    PAL_WAIT_ERROR  = 8, /*!< ignored in events */
};

/*!
 * \brief Poll
 *
 * \param count the number of items in the array
 * \param handle_array
 * \param events user-defined events
 * \param[out] ret_events polled-handles' events in `ret_events`
 * \param timeout_us is the maximum time that the API should wait (in
 *  microseconds), or `NO_TIMEOUT` to indicate it is to be blocked until at
 *  least one handle is ready.
 * \return true if there was an event on at least one handle, false otherwise
 */
PAL_BOL DkStreamsWaitEvents(PAL_NUM count, PAL_HANDLE* handle_array, PAL_FLG* events,
                            PAL_FLG* ret_events, PAL_NUM timeout_us);

/*!
 * \brief Close (deallocate) a PAL handle.
 */
void DkObjectClose(PAL_HANDLE objectHandle);

/*
 * MISC
 */

/*!
 * \brief Get the current time
 * \return the current time in microseconds
 */
PAL_NUM
DkSystemTimeQuery(void);

/*!
 * \brief Cryptographically secure random.
 *
 * \param[out] buffer is filled with cryptographically-secure random values
 * \param[in] size buffer size
 * \return 0 on success, negative on failure
 */
PAL_NUM
DkRandomBitsRead(PAL_PTR buffer, PAL_NUM size);

/*!
 * \todo document DkInstructionCacheFlush
 */
PAL_BOL
DkInstructionCacheFlush(PAL_PTR addr, PAL_NUM size);

enum PAL_SEGMENT {
    PAL_SEGMENT_FS = 0x1,
    PAL_SEGMENT_GS = 0x2,
};

/*!
 * \brief Set segment register
 *
 * \param reg the register to be set (#PAL_SEGMENT)
 * \param addr the address to be set; if `NULL`, return the current value of the
 *  segment register.
 *
 * \todo what is being returned if not `NULL`?
 */
PAL_PTR DkSegmentRegister(PAL_FLG reg, PAL_PTR addr);

/*!
 * \brief Return the amount of currently available memory for LibOS/application
 * usage.
 */
PAL_NUM DkMemoryAvailableQuota(void);

enum PAL_CPUID_WORD {
    PAL_CPUID_WORD_EAX = 0,
    PAL_CPUID_WORD_EBX = 1,
    PAL_CPUID_WORD_ECX = 2,
    PAL_CPUID_WORD_EDX = 3,
    PAL_CPUID_WORD_NUM = 4,
};

/*!
 * \brief Return CPUID information, based on the leaf/subleaf.
 *
 * \param[out] values the array of the results
 */
PAL_BOL
DkCpuIdRetrieve(PAL_IDX leaf, PAL_IDX subleaf, PAL_IDX values[PAL_CPUID_WORD_NUM]);

/*!
 * \brief Obtain the attestation quote with `report_data` embedded into it.
 *
 * Currently, works only for Linux-SGX PAL, where `report_data` is a 64B blob and `quote` is an
 * SGX quote obtained from the Quoting Enclave via AESM service.
 *
 * \param[in]     report_data       Report data with arbitrary contents (typically uniquely
 *                                  identifies this Graphene instance). Must be a 64B buffer
 *                                  in case of SGX PAL.
 * \param[in]     report_data_size  Size in bytes of report data. Must be 64 in case of SGX PAL.
 * \param[out]    quote             Attestation quote with report data embedded.
 * \param[in,out] quote_size        Caller specifies maximum size allocated for `quote`; on return,
 *                                  contains actual size of `quote`.
 */
PAL_BOL DkAttestationQuote(PAL_PTR report_data, PAL_NUM report_data_size, PAL_PTR quote,
                           PAL_NUM* quote_size);

#ifdef __GNUC__
# define symbol_version_default(real, name, version) \
    __asm__ (".symver " #real "," #name "@@" #version "\n")
#else
# define symbol_version_default(real, name, version)
#endif

#endif /* PAL_H */
