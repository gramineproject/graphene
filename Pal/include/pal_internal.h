/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains definitions of functions, variables and data structures for internal uses.
 */

#ifndef PAL_INTERNAL_H
#define PAL_INTERNAL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#include "api.h"
#include "log.h"
#include "pal.h"
#include "pal_defs.h"
#include "pal_error.h"
#include "toml.h"

#ifndef IN_PAL
#error "pal_internal.h can only be included in PAL"
#endif

/* handle_ops is the operators provided for each handler type. They are mostly used by
 * stream-related PAL calls, but can also be used by some others in special ways. */
struct handle_ops {
    /* 'getrealpath' return the real path that represent the handle */
    const char* (*getrealpath)(PAL_HANDLE handle);

    /* 'getname' is used by DkStreamGetName. It's different from 'getrealpath' */
    int (*getname)(PAL_HANDLE handle, char* buffer, size_t count);

    /* 'open' is used by DkStreamOpen. 'handle' is a preallocated handle, 'type' will be a
     * normalized prefix, 'uri' is the remaining string of uri. access, share, create, and options
     * follow the same flags defined for DkStreamOpen in pal.h. */
    int (*open)(PAL_HANDLE* handle, const char* type, const char* uri, int access, int share,
                int create, int options);

    /* 'read' and 'write' is used by DkStreamRead and DkStreamWrite, so they have exactly same
     * prototype as them. */
    int64_t (*read)(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buffer);
    int64_t (*write)(PAL_HANDLE handle, uint64_t offset, uint64_t count, const void* buffer);

    /* 'readbyaddr' and 'writebyaddr' are the same as read and write, but with extra field to
     * specify address */
    int64_t (*readbyaddr)(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buffer,
                          char* addr, size_t addrlen);
    int64_t (*writebyaddr)(PAL_HANDLE handle, uint64_t offset, uint64_t count, const void* buffer,
                           const char* addr, size_t addrlen);

    /* 'close' and 'delete' is used by DkObjectClose and DkStreamDelete, 'close' will close the
     * stream, while 'delete' actually destroy the stream, such as deleting a file or shutting
     * down a socket */
    int (*close)(PAL_HANDLE handle);
    int (*delete)(PAL_HANDLE handle, int access);

    /*
     * 'map' and 'unmap' will map or unmap the handle into memory space, it's not necessary mapped
     * by mmap, so unmap also needs 'handle' to deal with special cases.
     *
     * Common PAL code will ensure that *address, offset, and size are page-aligned. 'address'
     * should not be NULL.
     */
    int (*map)(PAL_HANDLE handle, void** address, int prot, uint64_t offset, uint64_t size);

    /* 'setlength' is used by DkStreamFlush. It truncate the stream to certain size. */
    int64_t (*setlength)(PAL_HANDLE handle, uint64_t length);

    /* 'flush' is used by DkStreamFlush. It syncs the stream to the device */
    int (*flush)(PAL_HANDLE handle);

    /* 'waitforclient' is used by DkStreamWaitforClient. It accepts an connection */
    int (*waitforclient)(PAL_HANDLE server, PAL_HANDLE* client);

    /* 'attrquery' is used by DkStreamAttributesQuery. It queries the attributes of a stream */
    int (*attrquery)(const char* type, const char* uri, PAL_STREAM_ATTR* attr);

    /* 'attrquerybyhdl' is used by DkStreamAttributesQueryByHandle. It queries the attributes of
     * a stream handle */
    int (*attrquerybyhdl)(PAL_HANDLE handle, PAL_STREAM_ATTR* attr);

    /* 'attrsetbyhdl' is used by DkStreamAttributesSetByHandle. It queries the attributes of
     * a stream handle */
    int (*attrsetbyhdl)(PAL_HANDLE handle, PAL_STREAM_ATTR* attr);

    /* 'rename' is used to change name of a stream, or reset its share option */
    int (*rename)(PAL_HANDLE handle, const char* type, const char* uri);
};

extern const struct handle_ops* g_pal_handle_ops[];

static inline const struct handle_ops* HANDLE_OPS(PAL_HANDLE handle) {
    int _type = PAL_GET_TYPE(handle);
    if (_type < 0 || _type >= PAL_HANDLE_TYPE_BOUND)
        return NULL;
    return g_pal_handle_ops[_type];
}

/* We allow dynamic size handle allocation. Here is some macro to help deciding the actual size of
 * the handle */
extern PAL_HANDLE _h;
#define HANDLE_SIZE(type) (sizeof(*_h))

static inline size_t handle_size(PAL_HANDLE handle) {
    return sizeof(*handle);
}

/*
 * failure notify. The rountine is called whenever a PAL call return error code. As the current
 * design of PAL does not return error code directly, we rely on DkAsynchronousEventUpcall to handle
 * PAL call error. If the user does not set up a upcall, the error code will be ignored. Ignoring
 * PAL error code can be a possible optimization for SHIM.
 */
void notify_failure(unsigned long error);

/* all pal config value */
struct pal_internal_state {
    uint64_t        instance_id;

    PAL_HANDLE      parent_process;

    const char*     raw_manifest_data;
    toml_table_t*   manifest_root;

    /* May not be the same as page size, e.g. SYSTEM_INFO::dwAllocationGranularity on Windows */
    size_t          alloc_align;
};
extern struct pal_internal_state g_pal_state;

extern PAL_CONTROL g_pal_control;

int add_preloaded_range(uintptr_t start, uintptr_t end, const char* comment);

#define IS_ALLOC_ALIGNED(addr)     IS_ALIGNED_POW2(addr, g_pal_state.alloc_align)
#define IS_ALLOC_ALIGNED_PTR(addr) IS_ALIGNED_PTR_POW2(addr, g_pal_state.alloc_align)
#define ALLOC_ALIGN_UP(addr)       ALIGN_UP_POW2(addr, g_pal_state.alloc_align)
#define ALLOC_ALIGN_UP_PTR(addr)   ALIGN_UP_PTR_POW2(addr, g_pal_state.alloc_align)
#define ALLOC_ALIGN_DOWN(addr)     ALIGN_DOWN_POW2(addr, g_pal_state.alloc_align)
#define ALLOC_ALIGN_DOWN_PTR(addr) ALIGN_DOWN_PTR_POW2(addr, g_pal_state.alloc_align)

/*!
 * \brief Main initialization function
 *
 * This function must be called by the host-specific loader.
 *
 * \param instance_id       current instance id
 * \param exec_uri          executable URI
 * \param parent_process    parent process if it's a child
 * \param first_thread      first thread handle
 * \param arguments         application arguments
 * \param environments      environment variables
 */
noreturn void pal_main(uint64_t instance_id, PAL_HANDLE parent_process, PAL_HANDLE first_thread,
                       PAL_STR* arguments, PAL_STR* environments);

/* For initialization */

void _DkGetAvailableUserAddressRange(PAL_PTR* start, PAL_PTR* end);
bool _DkCheckMemoryMappable(const void* addr, size_t size);
unsigned long _DkMemoryQuota(void);
unsigned long _DkMemoryAvailableQuota(void);
// Returns 0 on success, negative PAL code on failure
int _DkGetCPUInfo(PAL_CPU_INFO* info);
int _DkGetTopologyInfo(PAL_TOPO_INFO* topo_info);

/* Internal DK calls, in case any of the internal routines needs to use them */
/* DkStream calls */
int _DkStreamOpen(PAL_HANDLE* handle, const char* uri, int access, int share, int create,
                  int options);
int _DkStreamDelete(PAL_HANDLE handle, int access);
int64_t _DkStreamRead(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buf, char* addr,
                      int addrlen);
int64_t _DkStreamWrite(PAL_HANDLE handle, uint64_t offset, uint64_t count, const void* buf,
                       const char* addr, int addrlen);
int _DkStreamAttributesQuery(const char* uri, PAL_STREAM_ATTR* attr);
int _DkStreamAttributesQueryByHandle(PAL_HANDLE hdl, PAL_STREAM_ATTR* attr);
int _DkStreamMap(PAL_HANDLE handle, void** addr, int prot, uint64_t offset, uint64_t size);
int _DkStreamUnmap(void* addr, uint64_t size);
int64_t _DkStreamSetLength(PAL_HANDLE handle, uint64_t length);
int _DkStreamFlush(PAL_HANDLE handle);
int _DkStreamGetName(PAL_HANDLE handle, char* buf, size_t size);
const char* _DkStreamRealpath(PAL_HANDLE hdl);
int _DkSendHandle(PAL_HANDLE hdl, PAL_HANDLE cargo);
int _DkReceiveHandle(PAL_HANDLE hdl, PAL_HANDLE* cargo);

/* DkProcess and DkThread calls */
int _DkThreadCreate(PAL_HANDLE* handle, int (*callback)(void*), const void* param);
noreturn void _DkThreadExit(int* clear_child_tid);
void _DkThreadYieldExecution(void);
int _DkThreadResume(PAL_HANDLE threadHandle);
int _DkProcessCreate(PAL_HANDLE* handle, const char** args);
noreturn void _DkProcessExit(int exitCode);
int _DkThreadSetCpuAffinity(PAL_HANDLE thread, PAL_NUM cpumask_size, PAL_PTR cpu_mask);
int _DkThreadGetCpuAffinity(PAL_HANDLE thread, PAL_NUM cpumask_size, PAL_PTR cpu_mask);

/* DkEvent calls */
int _DkEventCreate(PAL_HANDLE* handle_ptr, bool init_signaled, bool auto_clear);
void _DkEventSet(PAL_HANDLE handle);
void _DkEventClear(PAL_HANDLE handle);
int _DkEventWait(PAL_HANDLE handle, uint64_t* timeout_us);

/* DkVirtualMemory calls */
int _DkVirtualMemoryAlloc(void** paddr, uint64_t size, int alloc_type, int prot);
int _DkVirtualMemoryFree(void* addr, uint64_t size);
int _DkVirtualMemoryProtect(void* addr, uint64_t size, int prot);

/* DkObject calls */
int _DkObjectClose(PAL_HANDLE objectHandle);
int _DkStreamsWaitEvents(size_t count, PAL_HANDLE* handle_array, PAL_FLG* events,
                         PAL_FLG* ret_events, int64_t timeout_us);

/* DkException calls & structures */
PAL_EVENT_HANDLER _DkGetExceptionHandler(PAL_NUM event_num);

/* other DK calls */
int _DkSystemTimeQuery(uint64_t* out_usec);

/*
 * Cryptographically secure random.
 * 0 on success, negative on failure.
 */
int _DkRandomBitsRead(void* buffer, size_t size);
int _DkSegmentRegisterGet(int reg, void** addr);
int _DkSegmentRegisterSet(int reg, void* addr);
int _DkCpuIdRetrieve(unsigned int leaf, unsigned int subleaf, unsigned int values[4]);
int _DkAttestationReport(PAL_PTR user_report_data, PAL_NUM* user_report_data_size,
                         PAL_PTR target_info, PAL_NUM* target_info_size, PAL_PTR report,
                         PAL_NUM* report_size);
int _DkAttestationQuote(PAL_PTR user_report_data, PAL_NUM user_report_data_size, PAL_PTR quote,
                        PAL_NUM* quote_size);
int _DkSetProtectedFilesKey(PAL_PTR pf_key_hex);

#define INIT_FAIL(exitcode, reason)                                                              \
    do {                                                                                         \
        log_error("PAL failed at " __FILE__ ":%s:%u (exitcode = %u, reason=%s)", __FUNCTION__,   \
                  (unsigned int)__LINE__, (unsigned int)(exitcode), reason);                     \
        _DkProcessExit(exitcode);                                                                \
    } while (0)

#define INIT_FAIL_MANIFEST(exitcode, reason)                           \
    do {                                                               \
        log_error("PAL failed at parsing the manifest: %s", reason);   \
        _DkProcessExit(exitcode);                                      \
    } while (0)

/* Loading ELF binaries */
enum object_type { OBJECT_RTLD, OBJECT_EXEC, OBJECT_PRELOAD, OBJECT_EXTERNAL };

bool has_elf_magic(const void* header, size_t len);
bool is_elf_object(PAL_HANDLE handle);
int load_elf_object(const char* uri, enum object_type type);
int load_elf_object_by_handle(PAL_HANDLE handle, enum object_type type, void** out_loading_base);

void init_slab_mgr(size_t alignment);
void* malloc(size_t size);
void* malloc_copy(const void* mem, size_t size);
void* calloc(size_t nmem, size_t size);
void free(void* mem);

#ifdef __GNUC__
#define __attribute_hidden        __attribute__((visibility("hidden")))
#define __attribute_always_inline __attribute__((always_inline))
#define __attribute_unused        __attribute__((unused))
#define __attribute_noinline      __attribute__((noinline))
#else
#error Unsupported compiler
#endif

int _DkInitDebugStream(const char* path);
int _DkDebugLog(const void* buf, size_t size);

// TODO(mkow): We should make it cross-object-inlinable, ideally by enabling LTO, less ideally by
// pasting it here and making `inline`, but our current linker scripts prevent both.
void pal_log(int level, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

#define PAL_LOG_DEFAULT_LEVEL  LOG_LEVEL_ERROR
#define PAL_LOG_DEFAULT_FD     2

#define uthash_fatal(msg)                      \
    do {                                       \
        log_error("uthash error: %s", msg);    \
        _DkProcessExit(PAL_ERROR_NOMEM);       \
    } while (0)
#include "uthash.h"

#endif
