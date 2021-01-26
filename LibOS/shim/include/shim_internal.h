/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#ifndef _SHIM_INTERNAL_H_
#define _SHIM_INTERNAL_H_

#include <stdbool.h>

#include "api.h"
#include "assert.h"
#include "atomic.h"
#include "shim_defs.h"
#include "shim_internal-arch.h"
#include "shim_tcb.h"
#include "shim_types.h"

void* shim_init(int argc, void* args);

/* important macros and static inline functions */

#define PAL_NATIVE_ERRNO() SHIM_TCB_GET(pal_errno)

#define INTERNAL_TID_BASE ((IDTYPE)1 << (sizeof(IDTYPE) * 8 - 1))

static inline bool is_internal_tid(unsigned int tid) {
    return tid >= INTERNAL_TID_BASE;
}

struct debug_buf {
    int start;
    int end;
    char buf[DEBUGBUF_SIZE];
};

#include "pal.h"
#include "pal_debug.h"
#include "pal_error.h"

extern int g_log_level;

#include <stdarg.h>

void debug_printf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void debug_puts(const char* str);
void debug_putch(int ch);
void debug_vprintf(const char* fmt, va_list ap) __attribute__((format(printf, 1, 0)));

#define _log(level, fmt...)                          \
    do {                                             \
        if ((level) <= g_log_level)                  \
            debug_printf(fmt);                       \
    } while (0)

#define log_error(fmt...)    _log(PAL_LOG_ERROR, fmt)
#define log_warning(fmt...)  _log(PAL_LOG_WARNING, fmt)
#define log_debug(fmt...)    _log(PAL_LOG_DEBUG, fmt)
#define log_trace(fmt...)    _log(PAL_LOG_TRACE, fmt)

/* TODO: Replace debug() calls with log_*() at the appropriate levels, and remove this macro. */
#define debug(fmt...)        _log(PAL_LOG_WARNING, fmt)

#if 0
#define DEBUG_BREAK_ON_FAILURE() DEBUG_BREAK()
#else
#define DEBUG_BREAK_ON_FAILURE() do {} while (0)
#endif

#define BUG()                                       \
    do {                                            \
        warn("BUG() " __FILE__ ":%d\n", __LINE__);  \
        DEBUG_BREAK_ON_FAILURE();                   \
        die_or_inf_loop();                          \
    } while (0)

#define DEBUG_HERE()                                         \
    do {                                                     \
        debug("%s (" __FILE__ ":%d)\n", __func__, __LINE__); \
    } while (0)

/* definition for syscall table */
void handle_signals(void);
long convert_pal_errno(long err);
void syscall_wrapper(void);
void syscall_wrapper_after_syscalldb(void);

#define PAL_ERRNO() convert_pal_errno(PAL_NATIVE_ERRNO())

#define SHIM_ARG_TYPE long

static inline int64_t get_cur_preempt(void) {
    shim_tcb_t* tcb = shim_get_tcb();
    assert(tcb);
    return __atomic_load_n(&tcb->context.preempt.counter, __ATOMIC_SEQ_CST);
}

#define BEGIN_SHIM(name, args...)              \
    SHIM_ARG_TYPE __shim_##name(args) {        \
        SHIM_ARG_TYPE ret = 0;                 \
        int64_t preempt = get_cur_preempt();   \
        __UNUSED(preempt);

#define END_SHIM(name)                        \
        handle_signals();                     \
        assert(preempt == get_cur_preempt()); \
        return ret;                           \
    }

#define DEFINE_SHIM_SYSCALL(name, n, func, ...) \
    SHIM_SYSCALL_##n(name, func, __VA_ARGS__)

#define PROTO_ARGS_0()              void
#define PROTO_ARGS_1(t, a)          t a
#define PROTO_ARGS_2(t, a, rest...) t a, PROTO_ARGS_1(rest)
#define PROTO_ARGS_3(t, a, rest...) t a, PROTO_ARGS_2(rest)
#define PROTO_ARGS_4(t, a, rest...) t a, PROTO_ARGS_3(rest)
#define PROTO_ARGS_5(t, a, rest...) t a, PROTO_ARGS_4(rest)
#define PROTO_ARGS_6(t, a, rest...) t a, PROTO_ARGS_5(rest)

#define CAST_ARGS_0()
#define CAST_ARGS_1(t, a)          (SHIM_ARG_TYPE)a
#define CAST_ARGS_2(t, a, rest...) (SHIM_ARG_TYPE)a, CAST_ARGS_1(rest)
#define CAST_ARGS_3(t, a, rest...) (SHIM_ARG_TYPE)a, CAST_ARGS_2(rest)
#define CAST_ARGS_4(t, a, rest...) (SHIM_ARG_TYPE)a, CAST_ARGS_3(rest)
#define CAST_ARGS_5(t, a, rest...) (SHIM_ARG_TYPE)a, CAST_ARGS_4(rest)
#define CAST_ARGS_6(t, a, rest...) (SHIM_ARG_TYPE)a, CAST_ARGS_5(rest)

#define DEFINE_SHIM_FUNC(func, n, r, args...) \
    r func(PROTO_ARGS_##n(args));

#define PARSE_SYSCALL1(name, ...) \
    debug_print_syscall_before(__NR_##name, ##__VA_ARGS__);

#define PARSE_SYSCALL2(name, ret_val, ...) \
    debug_print_syscall_after(__NR_##name, ret_val, ##__VA_ARGS__);

void debug_print_syscall_before(int sysno, ...);
void debug_print_syscall_after(int sysno, ...);

#define SHIM_SYSCALL_0(name, func, r)       \
    BEGIN_SHIM(name, void)                  \
        PARSE_SYSCALL1(name);               \
        r __ret = (func)();                 \
        PARSE_SYSCALL2(name, __ret);        \
        ret = (SHIM_ARG_TYPE)__ret;         \
    END_SHIM(name)

#define SHIM_SYSCALL_1(name, func, r, t1, a1)        \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1)           \
        t1 a1 = (t1)__arg1;                          \
        PARSE_SYSCALL1(name, a1);                    \
        r __ret = (func)(a1);                        \
        PARSE_SYSCALL2(name, __ret, a1);             \
        ret = (SHIM_ARG_TYPE)__ret;                  \
    END_SHIM(name)

#define SHIM_SYSCALL_2(name, func, r, t1, a1, t2, a2)                \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2)     \
        t1 a1 = (t1)__arg1;                                          \
        t2 a2 = (t2)__arg2;                                          \
        PARSE_SYSCALL1(name, a1, a2);                                \
        r __ret = (func)(a1, a2);                                    \
        PARSE_SYSCALL2(name, __ret, a1, a2);                         \
        ret = (SHIM_ARG_TYPE)__ret;                                  \
    END_SHIM(name)

#define SHIM_SYSCALL_3(name, func, r, t1, a1, t2, a2, t3, a3)                              \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2, SHIM_ARG_TYPE __arg3)     \
        t1 a1 = (t1)__arg1;                                                                \
        t2 a2 = (t2)__arg2;                                                                \
        t3 a3 = (t3)__arg3;                                                                \
        PARSE_SYSCALL1(name, a1, a2, a3);                                                  \
        r __ret = (func)(a1, a2, a3);                                                      \
        PARSE_SYSCALL2(name, __ret, a1, a2, a3);                                           \
        ret = (SHIM_ARG_TYPE)__ret;                                                        \
    END_SHIM(name)

#define SHIM_SYSCALL_4(name, func, r, t1, a1, t2, a2, t3, a3, t4, a4)                      \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2, SHIM_ARG_TYPE __arg3,     \
               SHIM_ARG_TYPE __arg4)                                                       \
        t1 a1 = (t1)__arg1;                                                                \
        t2 a2 = (t2)__arg2;                                                                \
        t3 a3 = (t3)__arg3;                                                                \
        t4 a4 = (t4)__arg4;                                                                \
        PARSE_SYSCALL1(name, a1, a2, a3, a4);                                              \
        r __ret = (func)(a1, a2, a3, a4);                                                  \
        PARSE_SYSCALL2(name, __ret, a1, a2, a3, a4);                                       \
        ret = (SHIM_ARG_TYPE)__ret;                                                        \
    END_SHIM(name)

#define SHIM_SYSCALL_5(name, func, r, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5)              \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2, SHIM_ARG_TYPE __arg3,     \
               SHIM_ARG_TYPE __arg4, SHIM_ARG_TYPE __arg5)                                 \
        t1 a1 = (t1)__arg1;                                                                \
        t2 a2 = (t2)__arg2;                                                                \
        t3 a3 = (t3)__arg3;                                                                \
        t4 a4 = (t4)__arg4;                                                                \
        t5 a5 = (t5)__arg5;                                                                \
        PARSE_SYSCALL1(name, a1, a2, a3, a4, a5);                                          \
        r __ret = (func)(a1, a2, a3, a4, a5);                                              \
        PARSE_SYSCALL2(name, __ret, a1, a2, a3, a4, a5);                                   \
        ret = (SHIM_ARG_TYPE)__ret;                                                        \
    END_SHIM(name)

#define SHIM_SYSCALL_6(name, func, r, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6)             \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2, SHIM_ARG_TYPE __arg3,            \
               SHIM_ARG_TYPE __arg4, SHIM_ARG_TYPE __arg5, SHIM_ARG_TYPE __arg6)                  \
        t1 a1 = (t1)__arg1;                                                                       \
        t2 a2 = (t2)__arg2;                                                                       \
        t3 a3 = (t3)__arg3;                                                                       \
        t4 a4 = (t4)__arg4;                                                                       \
        t5 a5 = (t5)__arg5;                                                                       \
        t6 a6 = (t6)__arg6;                                                                       \
        PARSE_SYSCALL1(name, a1, a2, a3, a4, a5, a6);                                             \
        r __ret = (func)(a1, a2, a3, a4, a5, a6);                                                 \
        PARSE_SYSCALL2(name, __ret, a1, a2, a3, a4, a5, a6);                                      \
        ret = (SHIM_ARG_TYPE)__ret;                                                               \
    END_SHIM(name)

#define SHIM_PROTO_ARGS_0 void
#define SHIM_PROTO_ARGS_1 SHIM_ARG_TYPE __arg1
#define SHIM_PROTO_ARGS_2 SHIM_PROTO_ARGS_1, SHIM_ARG_TYPE __arg2
#define SHIM_PROTO_ARGS_3 SHIM_PROTO_ARGS_2, SHIM_ARG_TYPE __arg3
#define SHIM_PROTO_ARGS_4 SHIM_PROTO_ARGS_3, SHIM_ARG_TYPE __arg4
#define SHIM_PROTO_ARGS_5 SHIM_PROTO_ARGS_4, SHIM_ARG_TYPE __arg5
#define SHIM_PROTO_ARGS_6 SHIM_PROTO_ARGS_5, SHIM_ARG_TYPE __arg6

#define SHIM_UNUSED_ARGS_0()

#define SHIM_UNUSED_ARGS_1() \
    do {                     \
        __UNUSED(__arg1);    \
    } while (0)
#define SHIM_UNUSED_ARGS_2()  \
    do {                      \
        SHIM_UNUSED_ARGS_1(); \
        __UNUSED(__arg2);     \
    } while (0)
#define SHIM_UNUSED_ARGS_3()  \
    do {                      \
        SHIM_UNUSED_ARGS_2(); \
        __UNUSED(__arg3);     \
    } while (0)
#define SHIM_UNUSED_ARGS_4()  \
    do {                      \
        SHIM_UNUSED_ARGS_3(); \
        __UNUSED(__arg4);     \
    } while (0)

#define SHIM_UNUSED_ARGS_5()  \
    do {                      \
        SHIM_UNUSED_ARGS_4(); \
        __UNUSED(__arg5);     \
    } while (0)

#define SHIM_UNUSED_ARGS_6()  \
    do {                      \
        SHIM_UNUSED_ARGS_5(); \
        __UNUSED(__arg6);     \
    } while (0)

#define SHIM_SYSCALL_RETURN_ENOSYS(name, n, ...)                                   \
    BEGIN_SHIM(name, SHIM_PROTO_ARGS_##n)                                          \
        debug("WARNING: syscall " #name " not implemented. Returning -ENOSYS.\n"); \
        SHIM_UNUSED_ARGS_##n();                                                    \
        ret = -ENOSYS;                                                             \
    END_SHIM(name)

#define PAL_CB(member) (pal_control.member)

static inline int64_t __disable_preempt(shim_tcb_t* tcb) {
    // tcb->context.syscall_nr += SYSCALL_NR_PREEMPT_INC;
    int64_t preempt = __atomic_add_fetch(&tcb->context.preempt.counter, 1, __ATOMIC_SEQ_CST);
    /* Assert if this counter overflows */
    assert(preempt != 0);
    // debug("disable preempt: %d\n", preempt);
    return preempt;
}

static inline void disable_preempt(shim_tcb_t* tcb) {
    if (!tcb && !(tcb = shim_get_tcb()))
        return;

    __disable_preempt(tcb);
}

static inline void __enable_preempt(shim_tcb_t* tcb) {
    int64_t preempt = __atomic_sub_fetch(&tcb->context.preempt.counter, 1, __ATOMIC_SEQ_CST);
    /* Assert if this counter underflows */
    __UNUSED(preempt);
    assert(preempt >= 0);
    // debug("enable preempt: %d\n", preempt);
}

void __handle_signals(shim_tcb_t* tcb);

static inline void enable_preempt(shim_tcb_t* tcb) {
    if (!tcb && !(tcb = shim_get_tcb()))
        return;

    int64_t preempt = __atomic_load_n(&tcb->context.preempt.counter, __ATOMIC_SEQ_CST);
    if (!preempt)
        return;

    if (preempt == 1)
        __handle_signals(tcb);

    __enable_preempt(tcb);
}

/*
 * These events have counting semaphore semantics:
 * - `set_event(e, n)` increases value of the semaphore by `n`,
 * - `wait_event(e)` decreases value by 1 (blocking if it's 0),
 * - `clear_event(e)` decreases value to 0, without blocking - this operation is not atomic.
 * Note that using `clear_event` probably requires external locking to avoid races.
 */
static inline int create_event(AEVENTTYPE* e) {
    e->event = DkStreamOpen(URI_PREFIX_PIPE, PAL_ACCESS_RDWR, 0, 0, 0);
    if (!e->event) {
        return -PAL_ERRNO();
    }
    return 0;
}

static inline PAL_HANDLE event_handle(AEVENTTYPE* e) {
    return e->event;
}

static inline void destroy_event(AEVENTTYPE* e) {
    if (e->event) {
        DkObjectClose(e->event);
        e->event = NULL;
    }
}

static inline int set_event(AEVENTTYPE* e, size_t n) {
    /* TODO: this should be changed into an assert, once we make sure it does not happen (old
     * version handled it). */
    if (!e->event) {
        return -EINVAL;
    }

    char bytes[n];
    memset(bytes, '\0', n);
    while (n > 0) {
        PAL_NUM ret = DkStreamWrite(e->event, 0, n, bytes, NULL);
        if (ret == PAL_STREAM_ERROR) {
            int err = PAL_ERRNO();
            if (err == EINTR || err == EAGAIN || err == EWOULDBLOCK) {
                continue;
            }
            return -err;
        }
        n -= ret;
    }

    return 0;
}

static inline int wait_event(AEVENTTYPE* e) {
    /* TODO: this should be changed into an assert, once we make sure it does not happen (old
     * version handled it). */
    if (!e->event) {
        return -EINVAL;
    }

    int err = 0;
    do {
        char byte;
        PAL_NUM ret = DkStreamRead(e->event, 0, 1, &byte, NULL, 0);
        err = ret == PAL_STREAM_ERROR ? PAL_ERRNO() : 0;
    } while (err == EINTR || err == EAGAIN || err == EWOULDBLOCK);

    return -err;
}

static inline int clear_event(AEVENTTYPE* e) {
    /* TODO: this should be changed into an assert, once we make sure it does not happen (old
     * version handled it). */
    if (!e->event) {
        return -EINVAL;
    }

    while (1) {
        PAL_HANDLE handle = e->event;
        PAL_FLG ievent = PAL_WAIT_READ;
        PAL_FLG revent = 0;

        shim_get_tcb()->pal_errno = PAL_ERROR_SUCCESS;
        PAL_BOL ret = DkStreamsWaitEvents(1, &handle, &ievent, &revent, /*timeout=*/0);
        if (!ret) {
            int err = PAL_ERRNO();
            if (err == EINTR) {
                continue;
            } else if (!err || err == EAGAIN || err == EWOULDBLOCK) {
                break;
            }
            return -err;
        }

        /* Even if `revent` has `PAL_WAIT_ERROR` marked, let `DkSitreamRead()` report the error
         * below. */
        assert(revent);

        char bytes[100];
        PAL_NUM n = DkStreamRead(e->event, 0, sizeof(bytes), bytes, NULL, 0);
        if (n == PAL_STREAM_ERROR) {
            int err = PAL_ERRNO();
            if (err == EINTR) {
                continue;
            } else if (err == EAGAIN || err == EWOULDBLOCK) {
                /* This should not happen, since we polled above  ... */
                break;
            }
            return -err;
        }
    }

    return 0;
}

/* reference counter APIs */
#define REF_GET(ref)        __atomic_load_n(&(ref).counter, __ATOMIC_SEQ_CST)
#define REF_SET(ref, count) __atomic_store_n(&(ref).counter, count, __ATOMIC_SEQ_CST);

static inline int __ref_inc(REFTYPE* ref) {
    int64_t _c;
    do {
        _c = __atomic_load_n(&ref->counter, __ATOMIC_SEQ_CST);
        assert(_c >= 0);
    } while (!__atomic_compare_exchange_n(&ref->counter, &_c, _c + 1, /*weak=*/false,
                                          __ATOMIC_SEQ_CST, __ATOMIC_RELAXED));
    return _c + 1;
}

#define REF_INC(ref) __ref_inc(&(ref))

static inline int __ref_dec(REFTYPE* ref) {
    int64_t _c;
    do {
        _c = __atomic_load_n(&ref->counter, __ATOMIC_SEQ_CST);
        if (!_c) {
            debug("Fail: Trying to drop reference count below 0\n");
            BUG();
            return 0;
        }
    } while (!__atomic_compare_exchange_n(&ref->counter, &_c, _c - 1, /*weak=*/false,
                                          __ATOMIC_SEQ_CST, __ATOMIC_RELAXED));
    return _c - 1;
}

#define REF_DEC(ref) __ref_dec(&(ref))

#ifndef __alloca
#define __alloca __builtin_alloca
#endif

extern size_t g_pal_alloc_align;
#define ALLOC_ALIGNMENT         g_pal_alloc_align
#define IS_ALLOC_ALIGNED(x)     IS_ALIGNED_POW2(x, g_pal_alloc_align)
#define IS_ALLOC_ALIGNED_PTR(x) IS_ALIGNED_PTR_POW2(x, g_pal_alloc_align)
#define ALLOC_ALIGN_DOWN(x)     ALIGN_DOWN_POW2(x, g_pal_alloc_align)
#define ALLOC_ALIGN_UP(x)       ALIGN_UP_POW2(x, g_pal_alloc_align)
#define ALLOC_ALIGN_DOWN_PTR(x) ALIGN_DOWN_PTR_POW2(x, g_pal_alloc_align)
#define ALLOC_ALIGN_UP_PTR(x)   ALIGN_UP_PTR_POW2(x, g_pal_alloc_align)

void* __system_malloc(size_t size);
void __system_free(void* addr, size_t size);

#define system_malloc __system_malloc
#define system_free   __system_free

extern void* migrated_memory_start;
extern void* migrated_memory_end;

static inline bool memory_migrated(void* mem) {
    return mem >= migrated_memory_start && mem < migrated_memory_end;
}

extern void* __load_address;
extern void* __load_address_end;
extern void* __code_address;
extern void* __code_address_end;

extern const char** migrated_envp;

struct shim_handle;
int init_brk_from_executable(struct shim_handle* exec);
int init_brk_region(void* brk_region, size_t data_segment_size);
void reset_brk(void);
int init_internal_map(void);
int init_loader(void);
int init_rlimit(void);

bool test_user_memory(void* addr, size_t size, bool write);
bool test_user_string(const char* addr);

uint64_t get_rlimit_cur(int resource);
void set_rlimit_cur(int resource, uint64_t rlim);

int object_wait_with_retry(PAL_HANDLE handle);

void _update_epolls(struct shim_handle* handle);
void delete_from_epoll_handles(struct shim_handle* handle);

void* allocate_stack(size_t size, size_t protect_size, bool user);
int init_stack(const char** argv, const char** envp, const char*** out_argp, elf_auxv_t** out_auxv);

#endif /* _SHIM_INTERNAL_H_ */
