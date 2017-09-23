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

#ifndef IN_PAL
# error "pal_internal.h can only be included in PAL"
#endif

#define PAL_FILE(name) XSTRINGIFY(PAL_DIR) "/" name
#define RUNTIME_FILE(name) XSTRINGIFY(RUNTIME_DIR) "/" name

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
    int (*map) (PAL_HANDLE handle, void ** address, int prot, uint64_t offset,
                uint64_t size);

    /* 'setlength' is used by DkStreamFlush. It truncate the stream
       to certain size. */
    int64_t (*setlength) (PAL_HANDLE handle, uint64_t length);

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

    /* 'wait' is used for synchronous wait.
     * Time is in microseconds, NO_TIMEOUT means no timeout.
     * Returns 0 on success, a negative value on failure.
     * Timeout: -PAL_ERROR_TRYAGAIN
     * Positive return values are undefined.
     */
    int (*wait) (PAL_HANDLE handle, uint64_t time);

    /* 'rename' is used to change name of a stream, or reset its share
       option */
    int (*rename) (PAL_HANDLE handle, const char * type, const char * uri);
};

extern const struct handle_ops * pal_handle_ops [];

static inline const struct handle_ops * HANDLE_OPS (PAL_HANDLE handle)
{
    int _type = PAL_GET_TYPE(handle);
    if (_type <= 0 || _type >= PAL_HANDLE_TYPE_BOUND)
        return NULL;
    return pal_handle_ops[_type];
}

/* interger hash functions defined inline. The algorithm we used here
  is based on Robert Jenkins developed in 96', the algorithm has two
  version, 32-bit one and 64-bit one. */
static inline unsigned int hash32 (unsigned int key)
{
    key = ~key + (key << 15);
    key = key ^ (key >> 12);
    key = key + (key << 2);
    key = key ^ (key >> 4);
    key = (key + (key << 3)) + (key << 11);
    key = key ^ (key >> 16);
    return key;
}

static inline unsigned int hash64 (unsigned long key)
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
extern PAL_HANDLE _h;
#define HANDLE_SIZE(type)  (sizeof(_h->type))

#define UNKNOWN_HANDLE(handle)     \
    (PAL_GET_TYPE(handle) == 0 || PAL_GET_TYPE(handle) >= PAL_HANDLE_TYPE_BOUND)

static inline int handle_size (PAL_HANDLE handle)
{
    static int handle_sizes[PAL_HANDLE_TYPE_BOUND]
            = { 0,
                [pal_type_file]      = sizeof(handle->file),
                [pal_type_pipe]      = sizeof(handle->pipe),
                [pal_type_pipesrv]   = sizeof(handle->pipe),
                [pal_type_pipecli]   = sizeof(handle->pipe),
                [pal_type_pipeprv]   = sizeof(handle->pipeprv),
                [pal_type_dev]       = sizeof(handle->dev),
                [pal_type_dir]       = sizeof(handle->dir),
                [pal_type_tcp]       = sizeof(handle->sock),
                [pal_type_tcpsrv]    = sizeof(handle->sock),
                [pal_type_udp]       = sizeof(handle->sock),
                [pal_type_udpsrv]    = sizeof(handle->sock),
                [pal_type_process]   = sizeof(handle->process),
                [pal_type_mcast]     = sizeof(handle->mcast),
                [pal_type_thread]    = sizeof(handle->thread),
                [pal_type_semaphore] = sizeof(handle->semaphore),
                [pal_type_event]     = sizeof(handle->event),
                [pal_type_gipc]      = sizeof(handle->gipc),
            };

    if (UNKNOWN_HANDLE(handle))
        return 0;
    else
        return handle_sizes[PAL_GET_TYPE(handle)];
}

#ifndef ENTER_PAL_CALL
# define ENTER_PAL_CALL(name)
#endif

#ifndef LEAVE_PAL_CALL
# define LEAVE_PAL_CALL()
#endif

#ifndef LEAVE_PAL_CALL_RETURN
# define LEAVE_PAL_CALL_RETURN(retval)     do { return (retval); } while (0)
#endif

/* failure notify. The rountine is called whenever a PAL call return
   error code. As the current design of PAL does not return error
   code directly, we rely on DkAsynchronousEventUpcall to handle
   PAL call error. If the user does not set up a upcall, the error
   code will be ignored. Ignoring PAL error code can be a possible
   optimization for SHIM. */
void notify_failure (unsigned long error);

/* all pal config value */
extern struct pal_internal_state {
    PAL_NUM         instance_id;

    PAL_HANDLE      parent_process;

    const char *    manifest;
    PAL_HANDLE      manifest_handle;

    const char *    exec;
    PAL_HANDLE      exec_handle;

    PAL_HANDLE      log_stream;
    enum {
        LOG_FILE    = 0x01,
        LOG_PIPE    = 0x02,
        LOG_SOCKET  = 0x04,
        LOG_GENERIC_TYPES = 0x08,
    } log_types;

    struct config_store * root_config;

    unsigned long   pagesize;
    unsigned long   alloc_align, alloc_shift, alloc_mask;

    PAL_HANDLE      console;

    unsigned long   start_time;
#if PROFILING == 1
    unsigned long   relocation_time;
    unsigned long   linking_time;
    unsigned long   manifest_loading_time;
    unsigned long   slab_time;
    unsigned long   tail_startup_time;
    unsigned long   process_create_time;
#endif
} pal_state;

#ifdef __GNUC__
#define BREAK()                         \
    do {                                \
        asm volatile ("int $3");        \
    } while (0)
#else
#define BREAK()
#endif

extern PAL_CONTROL __pal_control;

#define ALLOC_ALIGNDOWN(addr)                               \
        (((unsigned long) (addr)) & pal_state.alloc_mask)
#define ALLOC_ALIGNUP(addr)                                 \
        ((((unsigned long) (addr)) + pal_state.alloc_shift) & pal_state.alloc_mask)
#define ALLOC_ALIGNED(addr)                                 \
        ((unsigned long) (addr) ==                          \
            (((unsigned long) (addr)) & pal_state.alloc_mask))

/* Main initialization function */
void pal_main (
        PAL_NUM    instance_id,      /* current instance id */
        PAL_HANDLE manifest_handle,  /* manifest handle if opened */
        PAL_HANDLE exec_handle,      /* executable handle if opened */
        PAL_PTR    exec_loaded_addr, /* executable addr if loaded */
        PAL_HANDLE parent_process,   /* parent process if it's a child */
        PAL_HANDLE first_thread,     /* first thread handle */
        PAL_STR *  arguments,        /* application arguments */
        PAL_STR *  environments      /* environment variables */
    );

/* For initialization */
unsigned long _DkGetPagesize (void);
unsigned long _DkGetAllocationAlignment (void);
void _DkGetAvailableUserAddressRange (PAL_PTR * start, PAL_PTR * end);
bool _DkCheckMemoryMappable (const void * addr, int size);
PAL_NUM _DkGetProcessId (void);
PAL_NUM _DkGetHostId (void);
unsigned long _DkMemoryQuota (void);
unsigned long _DkMemoryAvailableQuota (void);
void _DkGetCPUInfo (PAL_CPU_INFO * info);

/* Internal DK calls, in case any of the internal routines needs to use them */
/* DkStream calls */
int _DkStreamOpen (PAL_HANDLE * handle, const char * uri,
                   int access, int share, int create, int options);
int _DkStreamDelete (PAL_HANDLE handle, int access);
int _DkStreamRead (PAL_HANDLE handle, int offset, int count, void * buf,
                   char * addr, int addrlen);
int _DkStreamWrite (PAL_HANDLE handle, int offset, int count,
                    const void * buf, const char * addr, int addrlen);
int _DkStreamAttributesQuery (const char * uri, PAL_STREAM_ATTR * attr);
int _DkStreamAttributesQuerybyHandle (PAL_HANDLE hdl, PAL_STREAM_ATTR * attr);
int _DkStreamMap (PAL_HANDLE handle, void ** addr, int prot, uint64_t offset,
                  uint64_t size);
int _DkStreamUnmap (void * addr, uint64_t size);
int64_t _DkStreamSetLength (PAL_HANDLE handle, uint64_t length);
int _DkStreamFlush (PAL_HANDLE handle);
int _DkStreamGetName (PAL_HANDLE handle, char * buf, int size);
const char * _DkStreamRealpath (PAL_HANDLE hdl);
int _DkStreamFile (PAL_HANDLE hdl, PAL_HANDLE * file);
int _DkSendHandle(PAL_HANDLE hdl, PAL_HANDLE cargo);
int _DkReceiveHandle(PAL_HANDLE hdl, PAL_HANDLE * cargo);
PAL_HANDLE _DkBroadcastStreamOpen (void);

/* DkProcess and DkThread calls */
int _DkThreadCreate (PAL_HANDLE * handle, int (*callback) (void *),
                     const void * parem, int flags);
void _DkThreadExit (void);
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
int _DkSemaphoreAcquireTimeout (PAL_HANDLE sem, int count, uint64_t timeout);
void _DkSemaphoreRelease (PAL_HANDLE sem, int count);
int _DkSemaphoreGetCurrentCount (PAL_HANDLE sem);

/* DkEvent calls */
int _DkEventCreate (PAL_HANDLE * event, bool initialState,
                    bool isnotification);
void _DkEventDestroy (PAL_HANDLE handle);
int _DkEventSet (PAL_HANDLE event, int wakeup);
int _DkEventWaitTimeout (PAL_HANDLE event, uint64_t timeout);
int _DkEventWait (PAL_HANDLE event);
int _DkEventClear (PAL_HANDLE event);

/* DkVirtualMemory calls */
int _DkVirtualMemoryAlloc (void ** paddr, uint64_t size, int alloc_type, int prot);
int _DkVirtualMemoryFree (void * addr, uint64_t size);
int _DkVirtualMemoryProtect (void * addr, uint64_t size, int prot);

/* DkObject calls */
int _DkObjectReference (PAL_HANDLE objectHandle);
int _DkObjectClose (PAL_HANDLE objectHandle);
int _DkObjectsWaitAny (int count, PAL_HANDLE * handleArray, uint64_t timeout,
                       PAL_HANDLE * polled);

/* DkException calls & structures */
PAL_EVENT_HANDLER _DkGetExceptionHandler (PAL_NUM event_num);
void _DkRaiseFailure (int error);
void _DkExceptionReturn (void * event);

/* other DK calls */
int _DkInternalLock (PAL_LOCK * mut);
int _DkInternalUnlock (PAL_LOCK * mut);
unsigned long _DkSystemTimeQuery (void);
int _DkFastRandomBitsRead (void * buffer, int size);
int _DkRandomBitsRead (void * buffer, int size);
int _DkSegmentRegisterSet (int reg, const void * addr);
int _DkSegmentRegisterGet (int reg, void ** addr);
int _DkInstructionCacheFlush (const void * addr, int size);
int _DkCreatePhysicalMemoryChannel (PAL_HANDLE * handle, unsigned long * key);
int _DkPhysicalMemoryCommit (PAL_HANDLE channel, int entries,
                             PAL_PTR * addrs, PAL_NUM * sizes, int flags);
int _DkPhysicalMemoryMap (PAL_HANDLE channel, int entries,
                          PAL_PTR * addrs, PAL_NUM * sizes, PAL_FLG * prots);
int _DkCpuIdRetrieve (unsigned int leaf, unsigned int subleaf, unsigned int values[4]);

#define init_fail(exitcode, reason)                                     \
    do {                                                                \
        printf("PAL failed at " __FILE__  ":%s:%u (exitcode = %u, reason=%s)\n", \
               __FUNCTION__, (unsigned int)__LINE__,                    \
               (unsigned int) (exitcode), (const char *) (reason));     \
        _DkProcessExit(exitcode);                                       \
    } while (0)

/* function and definition for loading binaries */
enum object_type { OBJECT_RTLD, OBJECT_EXEC, OBJECT_PRELOAD, OBJECT_EXTERNAL };

int check_elf_object (PAL_HANDLE handle);
int load_elf_object (const char * uri, enum object_type type);
int load_elf_object_by_handle (PAL_HANDLE handle, enum object_type type);
int add_elf_object(void * addr, PAL_HANDLE handle, int type);

#ifndef NO_INTERNAL_ALLOC
void init_slab_mgr (int alignment);
void * malloc (size_t size);
void * remalloc (const void * mem, size_t size);
void * calloc (size_t nmem, size_t size);
char * strdup(const char *source);
void free (void * mem);
#endif

#ifdef __GNUC__
# define __attribute_hidden __attribute__ ((visibility ("hidden")))
# define __attribute_always_inline __attribute__((always_inline))
# define __attribute_unused __attribute__((unused))
# define __attribute_noinline __attribute__((noinline))
#else
# define __attribute_hidden
# define __attribute_always_inline
# define __attribute_unused
# define __attribute_noinline
#endif

#define alias_str(name) #name
#ifdef __GNUC__
# define extern_alias(name) \
    extern __typeof(name) pal_##name __attribute ((alias (alias_str(name))))
#else
# define extern_alias(name)
#endif

void _DkPrintConsole (const void * buf, int size);
int printf  (const char  *fmt, ...);
void write_log (int nstrs, ...);

static inline void log_stream (const char * uri)
{
    if (!uri || !pal_state.log_stream)
        return;

    bool logging = false;

    if ((pal_state.log_types & LOG_FILE) &&
        uri[0] == 'f' && uri[1] == 'i' && uri[2] == 'l' && uri[3] == 'e')
        logging = true;

    if ((pal_state.log_types & LOG_PIPE) &&
        uri[0] == 'p' && uri[1] == 'i' && uri[2] == 'p' && uri[3] == 'e')
        logging = true;

    if ((pal_state.log_types & LOG_SOCKET) &&
        uri[0] == 't' && uri[1] == 'c' && uri[2] == 'p')
        logging = true;

    if ((pal_state.log_types & LOG_SOCKET) &&
        uri[0] == 'u' && uri[1] == 'd' && uri[2] == 'p')
        logging = true;

    if (logging)
        write_log(2, uri, "\n");
}

#endif
