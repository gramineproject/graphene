/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 OSCAR lab, Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * pal_internal.h
 *
 * This file contains definition of functions, variables and data structures
 * for internal uses.
 */

#ifndef PAL_INTERNAL_H
#define PAL_INTERNAL_H

#include "pal_defs.h"
#include "pal.h"
#include "atomic.h"

#ifndef IN_PAL
# error "pal_internal.h can only be included in PAL"
#endif

/* handle_ops is the operators provided for each handler type. They are
   mostly used by Stream-related PAL calls, but can also be used by
   some others in special ways. */
struct handle_ops {
    /* 'getrealpath' return the real path that represent the handle */
    const char * (*getrealpath) (PAL_HANDLE handle);

    /* 'getname' is used by DkStreamGetName. It's different from
       'getrealpath' */
    int (*getname) (PAL_HANDLE handle, char * buffer, int count);

    /* 'open' is used by DkStreamOpen. 'handle' is a preallocated handle,
       'type' will be a normalized prefix, 'uri' is the remaining string
       of uri */
    int (*open) (PAL_HANDLE * handle, const char * type, const char * uri,
                 int access, int share, int create, int options);

    /* 'read' and 'write' is used by DkStreamRead and DkStreamWrite, so
       they have exactly same prototype as them.  */
    int (*read) (PAL_HANDLE handle, int offset, int count, void * buffer);
    int (*write) (PAL_HANDLE handle, int offset, int count,
                  const void * buffer);

    /* 'readbyaddr' and 'writebyaddr' are the same as read and write,
       but with extra field to specify address */
    int (*readbyaddr) (PAL_HANDLE handle, int offset, int count, void * buffer,
                       char * addr, int addrlen);
    int (*writebyaddr) (PAL_HANDLE handle, int offset, int count,
                        const void * buffer, const char * addr, int addrlen);

    /* 'close' and 'delete' is used by DkObjectClose and DkStreamDelete,
       'close' will close the stream, while 'delete' actually destroy
       the stream, such as deleting a file or shutting down a socket */
    int (*close) (PAL_HANDLE handle);
    int (*delete) (PAL_HANDLE handle, int access);

    /* 'map' and 'unmap' will map or unmap the handle into memory space,
       it's not necessary mapped by mmap, so unmap also needs 'handle'
       to deal with special cases */
    int (*map) (PAL_HANDLE handle, void ** address, int prot, int offset,
                int size);

    /* 'setlength' is used by DkStreamFlush. It truncate the stream
       to certain size. */
    int (*setlength) (PAL_HANDLE handle, int length);

    /* 'flush' is used by DkStreamFlush. It syncs the stream to the device */
    int (*flush) (PAL_HANDLE handle);

    /* 'waitforclient' is used by DkStreamWaitforClient. It accepts an
       connection */
    int (*waitforclient) (PAL_HANDLE server, PAL_HANDLE *client);

    /* 'attrquery' is used by DkStreamAttributesQuery. It queries the
        attributes of a stream */
    int (*attrquery) (const char * type, const char * uri,
                      PAL_STREAM_ATTR * attr);

    /* 'attrquerybyhdl' is used by DkStreamAttributesQuerybyHandle. It queries
       the attributes of a stream handle */
    int (*attrquerybyhdl) (PAL_HANDLE handle, PAL_STREAM_ATTR * attr);

    /* 'attrsetbyhdl' is used by DkStreamAttributesSetbyHandle. It queries
       the attributes of a stream handle */
    int (*attrsetbyhdl) (PAL_HANDLE handle, PAL_STREAM_ATTR * attr);

    /* 'wait' is used for synchronous wait */
    int (*wait) (PAL_HANDLE handle, int time);

    /* 'rename' is used to change name of a stream, or reset its share
       option */
    int (*rename) (PAL_HANDLE handle, const char * type, const char * uri);
};

extern const struct handle_ops * pal_handle_ops [];

#define HANDLE_OPS(handle)                              \
    ({ int _type = HANDLE_TYPE(handle);                 \
       (_type <= 0 || _type >= PAL_HANDLE_TYPE_BOUND) ? \
       NULL : pal_handle_ops[_type];                    \
    })

int parse_stream_uri (const char ** uri, const char ** prefix,
                      struct handle_ops ** ops);

/* interger hash functions defined inline. The algorithm we used here
  is based on Robert Jenkins developed in 96', the algorithm has two
  version, 32-bit one and 64-bit one. */
static inline uint32_t hash32 (uint32_t key)
{
    key = ~key + (key << 15);
    key = key ^ (key >> 12);
    key = key + (key << 2);
    key = key ^ (key >> 4);
    key = (key + (key << 3)) + (key << 11);
    key = key ^ (key >> 16);
    return key;
}

static inline uint64_t hash64 (uint64_t key)
{
    key = (~key) + (key << 21);
    key = key ^ (key >> 24);
    key = (key + (key << 3)) + (key << 8);
    key = key ^ (key >> 14);
    key = (key + (key << 2)) + (key << 4);
    key = key ^ (key >> 28);
    key = key + (key << 31);
    return key;
}

/* We allow dynamic size handle allocation. Here is some macro to help
   deciding the actual size of the handle */
#define HANDLE_SIZE(type)  ({ PAL_HANDLE _h; sizeof(_h->type); })

#define UNKNOWN_HANDLE(handle)     \
    (HANDLE_TYPE(handle) == 0 || HANDLE_TYPE(handle) >= PAL_HANDLE_TYPE_BOUND)

static inline int handle_size (PAL_HANDLE handle)
{
    static int handle_sizes[PAL_HANDLE_TYPE_BOUND]
            = { 0,
                sizeof(handle->file),
                sizeof(handle->pipe),
                sizeof(handle->pipe),
                sizeof(handle->pipe),
                sizeof(handle->pipeprv),
                sizeof(handle->dev),
                sizeof(handle->dir),
                sizeof(handle->sock),
                sizeof(handle->sock),
                sizeof(handle->sock),
                sizeof(handle->sock),
                sizeof(handle->process),
                sizeof(handle->mcast),
                sizeof(handle->thread),
                sizeof(handle->semaphore),
                sizeof(handle->event),
                sizeof(handle->gipc),
            };

    if (UNKNOWN_HANDLE(handle))
        return 0;
    else
        return handle_sizes[HANDLE_TYPE(handle)];
}

#ifdef __x86_64__

# ifdef OMIT_FRAME_POINTER
#  define store_stack(rsp)                                      \
    void * rsp;                                                 \
    do {                                                        \
        asm volatile ("movq %%rsp, %0\r\n"                      \
                      : "=g"(rsp) :: "memory");                 \
    } while(0)
# else
#  define store_stack(rsp, rbp)                                 \
    void * rsp, * rbp;                                          \
    do {                                                        \
        asm volatile ("movq %%rsp, %0\r\n"                      \
                      "movq %%rbp, %1\r\n"                      \
                      : "=g"(rsp), "=g"(rbp) :: "memory");      \
    } while(0)
# endif

struct arch_frame {
    unsigned long rsp, rbp, rbx, rsi, rdi, r12, r13, r14, r15;
};

# define store_register(reg, var)     \
    asm volatile ("movq %%" #reg ", %0" : "=g" (var) :: "memory");

# define store_register_in_frame(reg, f)     store_register(reg, (f)->reg)

# define arch_store_frame(f)                     \
    store_register_in_frame(rsp, f)              \
    store_register_in_frame(rbp, f)              \
    store_register_in_frame(rbx, f)              \
    store_register_in_frame(rsi, f)              \
    store_register_in_frame(rdi, f)              \
    store_register_in_frame(r12, f)              \
    store_register_in_frame(r13, f)              \
    store_register_in_frame(r14, f)              \
    store_register_in_frame(r15, f)

# define restore_register(reg, var, clobber...)  \
    asm volatile ("movq %0, %%" #reg :: "g" (var) : "memory", ##clobber);

# define restore_register_in_frame(reg, f)       \
    restore_register(reg, (f)->reg,              \
                     "r15", "r14", "r13", "r12", "rdi", "rsi", "rbx")

# define arch_restore_frame(f)                   \
    restore_register_in_frame(r15, f)            \
    restore_register_in_frame(r14, f)            \
    restore_register_in_frame(r13, f)            \
    restore_register_in_frame(r12, f)            \
    restore_register_in_frame(rdi, f)            \
    restore_register_in_frame(rsi, f)            \
    restore_register_in_frame(rbx, f)            \
    restore_register_in_frame(rbp, f)            \
    restore_register_in_frame(rsp, f)

#endif /* __x86_64__ */

struct pal_frame {
    volatile struct pal_frame * self;
    void *                      func;
    const char *                funcname;
    struct arch_frame           arch;
    PAL_CONTEXT *               context;
    unsigned long *             retval;
};

static inline
void __store_frame (struct pal_frame * frame,
                    void * func, const char * funcname)
{
    frame->self = frame;
    frame->func = func;
    frame->funcname = funcname;
    frame->context = NULL;
    frame->retval = NULL;
    arch_store_frame(&frame->arch)
}

#define store_frame(f)                     \
    struct pal_frame frame;                \
    __store_frame(&frame, &Dk##f, "Dk" #f)

/* failure notify. The rountine is called whenever a PAL call return
   error code. As the current design of PAL does not return error
   code directly, we rely on DkAsynchronousEventUpcall to handle
   PAL call error. If the user does not set up a upcall, the error
   code will be ignored. Ignoring PAL error code can be a possible
   optimization for SHIM. */
void notify_failure (unsigned long error);

#include <sigset.h>

/* all pal config value */
extern struct pal_config {
    const char *    manifest;
    const char *    exec;
    PAL_HANDLE      manifest_handle;
    PAL_HANDLE      exec_handle;
    struct config_store * root_config;
    const char **   environments;
    unsigned long   pagesize;
    unsigned long   alloc_align;
    bool            daemonize;
    void *          heap_base;
    void *          lib_text_start, * lib_text_end;
    void *          lib_data_start, * lib_data_end;
    PAL_HANDLE      console_output;
    const char *    syscall_sym_name;
    void *          syscall_sym_addr;
} pal_config;

#define BREAK()                         \
    do {                                \
        asm volatile ("int $3");        \
    } while (0)

extern PAL_CONTROL __pal_control;

extern void * text_start, * text_end;
extern void * data_start, * data_end;

/* constants and macros to help rounding addresses to page
   boundaries */
extern unsigned long allocsize, allocshift, allocmask;

#define ALLOC_ALIGNDOWN(addr) \
    (allocsize ? ((unsigned long) (addr)) & allocmask : (unsigned long) (addr))
#define ALLOC_ALIGNUP(addr) \
    (allocsize ? (((unsigned long) (addr)) + allocshift) & allocmask : (unsigned long) (addr))
#define ALLOC_ALIGNED(addr) \
    (allocsize && ((unsigned long) (addr)) == (((unsigned long) (addr)) & allocmask))

/* For initialization */
void pal_main (int argc, const char ** argv, const char ** envp);
unsigned long _DkGetPagesize (void);
unsigned long _DkGetAllocationAlignment (void);
int _DkInitHost (int * pargc, const char *** pargv);

#include <atomic.h>

int _DkInternalLock (PAL_LOCK * mut);
int _DkInternalUnlock (PAL_LOCK * mut);

/* Internal DK calls, in case any of the internal routines needs to use them */
/* DkStream calls */
int _DkStreamOpen (PAL_HANDLE * handle, const char * uri,
                   int access, int share, int create, int options);
int _DkStreamDelete (PAL_HANDLE handle, int access);
int _DkStreamRead (PAL_HANDLE handle, int offset, int count, void * buf,
                   char * addr, int addrlen);
int _DkStreamWrite (PAL_HANDLE handle, int offset, int count,
                    const void * buf, const char * addr, int addrlen);
int _DkStreamAttributesQuery (PAL_STR uri, PAL_STREAM_ATTR * attr);
int _DkStreamAttributesQuerybyHandle (PAL_HANDLE hdl, PAL_STREAM_ATTR * attr);
int _DkStreamMap (PAL_HANDLE handle, void ** addr, int prot, int offset,
                  size_t size);
int _DkStreamUnmap (void * addr, size_t size);
int _DkStreamSetLength (PAL_HANDLE handle, size_t length);
int _DkStreamFlush (PAL_HANDLE handle);
const char * _DkStreamRealpath (PAL_HANDLE hdl);
int _DkSendHandle(PAL_HANDLE hdl, PAL_HANDLE cargo);
int _DkReceiveHandle(PAL_HANDLE hdl, PAL_HANDLE cargo);
PAL_HANDLE _DkBroadcastStreamOpen (int port);

/* DkProcess and DkThread calls */
int _DkThreadCreate (PAL_HANDLE * handle, int (*callback) (void *),
                     const void * parem, int flags);
void * _DkThreadPrivate (void * addr);
void _DkThreadExit (int exitcode);
int _DkThreadDelayExecution (unsigned long * duration);
void _DkThreadYieldExecution (void);
int _DkThreadResume (PAL_HANDLE threadHandle);
int _DkProcessCreate (PAL_HANDLE * handle, const char * uri,
                      int flags, const char ** args);
void _DkProcessExit (int exitCode);
int _DkProcessSandboxCreate (const char * manifest, int flags);

/* DkSemaphore calls */
int _DkSemaphoreCreate (PAL_HANDLE handle, int initialCount, int maxCount);
void _DkSemaphoreDestroy (PAL_HANDLE semaphoreHandle);
int _DkSemaphoreAcquire (PAL_HANDLE sem, int count);
int _DkSemaphoreAcquireTimeout (PAL_HANDLE sem, int count, int timeout);
void _DkSemaphoreRelease (PAL_HANDLE sem, int count);
int _DkSemaphoreGetCurrentCount (PAL_HANDLE sem);

/* DkEvent calls */
int _DkEventCreate (PAL_HANDLE * event, bool initialState,
                    bool isnotification);
void _DkEventDestroy (PAL_HANDLE handle);
int _DkEventSet (PAL_HANDLE event);
int _DkEventWaitTimeout (PAL_HANDLE event, int timeout);
int _DkEventWait (PAL_HANDLE event);
int _DkEventClear (PAL_HANDLE event);

/* DkVirtualMemory calls */
int _DkVirtualMemoryAlloc (void ** paddr, size_t size, int alloc_type,
                           int prot);
int _DkVirtualMemoryFree (void * addr, size_t size);
int _DkVirtualMemoryProtect (void * addr, size_t size, int prot);

/* DkObject calls */
int _DkObjectReference (PAL_HANDLE objectHandle);
int _DkObjectClose (PAL_HANDLE objectHandle);
int _DkObjectsWaitAny (int count, PAL_HANDLE * handleArray, int timeout,
                       PAL_HANDLE * polled);

/* DkException calls & structures */
typedef void (*PAL_UPCALL) (PAL_PTR, PAL_NUM, PAL_CONTEXT *);
int (*_DkExceptionHandlers[PAL_EVENT_NUM_BOUND + 1]) (int, PAL_UPCALL, int);
void _DkExceptionReturn (const void * event);

/* other DK calls */
unsigned long _DkSystemTimeQuery (void);
int _DkRandomBitsRead (void * buffer, int size);
int _DkInstructionCacheFlush (const void * addr, size_t size);
int _DkCreatePhysicalMemoryChannel (PAL_HANDLE * handle, unsigned long * key);
int _DkPhysicalMemoryCommit (PAL_HANDLE channel, int entries, void ** addrs,
                             unsigned long * sizes, int flags);
int _DkPhysicalMemoryMap (PAL_HANDLE channel, int entries, void ** addrs,
                          unsigned long * sizes, unsigned int * prots);

/* To setup the system-wise signal handlers, including SIGKILL, SIGTERM,
 * SIGINT, SIGUSR1, etc */
int signal_setup (void);

/* random number generator: initialization and fetching */
int getrand (void * buffer, int size);

/* blocking and unblocking signals */
int block_signals (int * sigs, int nsig);
int unblock_signals (int * sigs, int nsig);

void * find_address (void * addr);

/* function and definition for loading binaries */
enum object_type { OBJECT_RTLD, OBJECT_EXEC, OBJECT_PRELOAD, OBJECT_EXTERNAL };

int check_elf_object (PAL_HANDLE handle);
int load_elf_object (const char * uri, enum object_type type);
int load_elf_object_by_handle (PAL_HANDLE handle, enum object_type type);

void init_slab_mgr (void);
void * malloc (int size);
void * remalloc (const void * mem, int size);
void * calloc (int nmem, int size);
void free (void * mem);

#define attribute_hidden __attribute__ ((visibility ("hidden")))

#define alias_str(name) #name

#define extern_alias(name) \
    extern __typeof(name) pal_##name __attribute ((alias (alias_str(name))))

void _DkPrintConsole (const void * buf, int size);
int printf  (const char  *fmt, ...);
int snprintf (char * buf, size_t n, const char * fmt, ...);

#endif
