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
 * shim_internal.h
 */

#ifndef _SHIM_INTERNAL_H_
#define _SHIM_INTERNAL_H_

#ifndef IN_SHIM
#error "this header file can only be used inside SHIM"
#endif

#define attribute_hidden __attribute__ ((visibility ("hidden")))

#define ALIAS_STR(name) #name

#define EXTERN_ALIAS(name) \
    extern __typeof__(name) shim_##name __attribute ((alias (ALIAS_STR(name))))

#define static_always_inline static inline __attribute__((always_inline))

#include <api.h>
#include <assert.h>
#include <shim_types.h>
#include <shim_defs.h>
#include <atomic.h>
#include <shim_tcb.h>

noreturn void shim_clean_and_exit(int exit_code);

/* important macros and static inline functions */
static inline unsigned int get_cur_tid(void) {
    return SHIM_TCB_GET(tid);
}

#define PAL_NATIVE_ERRNO        (SHIM_TCB_GET(pal_errno))

#define INTERNAL_TID_BASE       ((IDTYPE) 1 << (sizeof(IDTYPE) * 8 - 1))

static inline bool is_internal_tid(unsigned int tid)
{
    return tid >= INTERNAL_TID_BASE;
}

struct debug_buf {
    int start;
    int end;
    char buf[DEBUGBUF_SIZE];
};

#include <pal.h>
#include <pal_debug.h>
#include <pal_error.h>

extern PAL_HANDLE debug_handle;

#include <stdarg.h>

void debug_printf (const char * fmt, ...) __attribute__((format (printf, 1, 2)));
void debug_puts (const char * str);
void debug_putch (int ch);
void debug_vprintf (const char * fmt, va_list ap) __attribute__((format (printf, 1, 0)));

#define VMID_PREFIX     "[P%05u] "
#define TID_PREFIX      "[%-6u] "
#define NOID_PREFIX     "[      ] "
#define debug(fmt, ...)                                                     \
    do {                                                                    \
        if (debug_handle)                                                   \
            debug_printf(fmt, ##__VA_ARGS__);                               \
    } while (0)

/* print system messages */
#define SYSPRINT_BUFFER_SIZE    256

void handle_printf (PAL_HANDLE hdl, const char * fmt, ...) __attribute__((format (printf, 2, 3)));
void handle_vprintf (PAL_HANDLE hdl, const char * fmt, va_list ap) __attribute__((format (printf, 2, 0)));

#define __SYS_PRINTF(fmt, ...)                                              \
    do {                                                                    \
        PAL_HANDLE _hdl = __open_shim_stdio();                              \
        if (_hdl)                                                           \
           handle_printf(_hdl, fmt, ##__VA_ARGS__);                         \
    } while (0)

#define __SYS_VPRINTF(fmt, va)                                              \
    do {                                                                    \
        PAL_HANDLE _hdl = __open_shim_stdio();                              \
        if (_hdl)                                                           \
            handle_vprintf(_hdl, fmt, va);                                  \
    } while (0)


#define __SYS_FPRINTF(hdl, fmt, ...)                                        \
    do {                                                                    \
        handle_printf(hdl, fmt, ##__VA_ARGS__);                             \
    } while (0)

#define SYS_PRINTF(fmt, ...)                                                \
    do {                                                                    \
        MASTER_LOCK();                                                      \
        __SYS_PRINTF(fmt, ##__VA_ARGS__);                                   \
        MASTER_UNLOCK();                                                    \
    } while (0)

#define SYS_FPRINTF(hdl, fmt, ...)                                          \
    do {                                                                    \
        MASTER_LOCK();                                                      \
        __SYS_FPRINTF(hdl, fmt, ##__VA_ARGS__);                             \
        MASTER_UNLOCK();                                                    \
    } while (0)

extern PAL_HANDLE shim_stdio;

static inline PAL_HANDLE __open_shim_stdio (void)
{
    if (shim_stdio == (PAL_HANDLE) -1)
        return NULL;

    if (shim_stdio)
        return shim_stdio;

    shim_stdio = DkStreamOpen(URI_PREFIX_DEV "tty", PAL_ACCESS_RDWR, 0, 0, 0);

    if (!shim_stdio) {
        shim_stdio = (PAL_HANDLE) -1;
        return NULL;
    }

    return shim_stdio;
}

#define USE_PAUSE       0

static inline void do_pause (void);

#if USE_PAUSE == 1
# define PAUSE() do { do_pause(); } while (0)
#else
# define PAUSE() do { __asm__ volatile ("int $3"); } while (0)
#endif

#define BUG()                                                               \
    do {                                                                    \
        __SYS_PRINTF("BUG() " __FILE__ ":%d\n", __LINE__);                  \
        PAUSE();                                                            \
        shim_clean_and_exit(-ENOTRECOVERABLE);                              \
    } while (0)

#define DEBUG_HERE() \
    do { debug("%s (" __FILE__ ":%d)\n", __func__, __LINE__); } while (0)

/* definition for syscall table */
void handle_signal (void);
long convert_pal_errno (long err);
void syscall_wrapper(void);
void syscall_wrapper_after_syscalldb(void);

#define PAL_ERRNO  convert_pal_errno(PAL_NATIVE_ERRNO)

#define SHIM_ARG_TYPE long

#ifdef PROFILE
# define ENTER_TIME     shim_get_tcb()->context.enter_time
# define BEGIN_SYSCALL_PROFILE()        \
    do { ENTER_TIME = GET_PROFILE_INTERVAL(); } while (0)
# define END_SYSCALL_PROFILE(name)      \
    do { unsigned long _interval = GET_PROFILE_INTERVAL();          \
         if (_interval - ENTER_TIME > 1000)                         \
             SAVE_PROFILE_INTERVAL_SET(syscall_##name##_slow, ENTER_TIME, _interval); \
         else                                                       \
             SAVE_PROFILE_INTERVAL_SET(syscall_##name, ENTER_TIME, _interval); \
         ENTER_TIME = 0; } while (0)
#else
# define BEGIN_SYSCALL_PROFILE()        do {} while (0)
# define END_SYSCALL_PROFILE(name)      do {} while (0)
#endif

void check_stack_hook (void);

static inline int64_t get_cur_preempt (void) {
    shim_tcb_t* tcb = shim_get_tcb();
    assert(tcb);
    return atomic_read(&tcb->context.preempt);
}

#define BEGIN_SHIM(name, args ...)                          \
    SHIM_ARG_TYPE __shim_##name(args) {                     \
        SHIM_ARG_TYPE ret = 0;                              \
        int64_t preempt = get_cur_preempt();                \
        __UNUSED(preempt);                                  \
        /* handle_signal(); */                              \
        /* check_stack_hook(); */                           \
        BEGIN_SYSCALL_PROFILE();

#define END_SHIM(name)                                      \
        END_SYSCALL_PROFILE(name);                          \
        handle_signal();                                    \
        assert(preempt == get_cur_preempt());               \
        return ret;                                         \
    }

#define DEFINE_SHIM_SYSCALL(name, n, func, ...)             \
    DEFINE_PROFILE_INTERVAL(syscall_##name##_slow, syscall); \
    DEFINE_PROFILE_INTERVAL(syscall_##name, syscall);       \
    SHIM_SYSCALL_##n (name, func, __VA_ARGS__)              \
    EXPORT_SHIM_SYSCALL (name, n, __VA_ARGS__)

#define PROTO_ARGS_0() void
#define PROTO_ARGS_1(t, a) t a
#define PROTO_ARGS_2(t, a, rest ...) t a, PROTO_ARGS_1(rest)
#define PROTO_ARGS_3(t, a, rest ...) t a, PROTO_ARGS_2(rest)
#define PROTO_ARGS_4(t, a, rest ...) t a, PROTO_ARGS_3(rest)
#define PROTO_ARGS_5(t, a, rest ...) t a, PROTO_ARGS_4(rest)
#define PROTO_ARGS_6(t, a, rest ...) t a, PROTO_ARGS_5(rest)

#define CAST_ARGS_0()
#define CAST_ARGS_1(t, a) (SHIM_ARG_TYPE) a
#define CAST_ARGS_2(t, a, rest ...) (SHIM_ARG_TYPE) a, CAST_ARGS_1(rest)
#define CAST_ARGS_3(t, a, rest ...) (SHIM_ARG_TYPE) a, CAST_ARGS_2(rest)
#define CAST_ARGS_4(t, a, rest ...) (SHIM_ARG_TYPE) a, CAST_ARGS_3(rest)
#define CAST_ARGS_5(t, a, rest ...) (SHIM_ARG_TYPE) a, CAST_ARGS_4(rest)
#define CAST_ARGS_6(t, a, rest ...) (SHIM_ARG_TYPE) a, CAST_ARGS_5(rest)

#define DEFINE_SHIM_FUNC(func, n, r, args ...)             \
    r func (PROTO_ARGS_##n (args));

#define TYPE_HASH(t) ({ const char * _s = #t;              \
       ((uint16_t) _s[0] << 8) +  _s[1]; })

#define POINTER_TYPE(t) ({ int _h = TYPE_HASH(t);                   \
       _h == TYPE_HASH(void *) || _h == TYPE_HASH(char *) ||        \
       _h == TYPE_HASH(const); })

#define EXPORT_SHIM_SYSCALL(name, n, r, args ...)                   \
    r shim_##name (PROTO_ARGS_##n (args)) {                         \
        SHIM_ARG_TYPE ret =  __shim_##name (CAST_ARGS_##n (args));  \
        if (POINTER_TYPE(r)) {                                      \
            if ((uint64_t) ret >= (uint64_t) -4095L) return (r) 0;  \
        } else {                                                    \
            if ((int) ret < 0) return (r) -1;                       \
        }                                                           \
        return (r) ret;                                             \
    }

#define PARSE_SYSCALL1(name, ...)                                   \
    if (debug_handle)                                               \
        parse_syscall_before(__NR_##name, #name, ##__VA_ARGS__);

#define PARSE_SYSCALL2(name, ...)                                   \
    if (debug_handle)                                               \
        parse_syscall_after(__NR_##name, #name, ##__VA_ARGS__);

void parse_syscall_before (int sysno, const char * name, int nr, ...);
void parse_syscall_after (int sysno, const char * name, int nr, ...);

#define SHIM_SYSCALL_0(name, func, r)                           \
    BEGIN_SHIM(name, void)                                      \
        PARSE_SYSCALL1(name, 0);                                \
        r __ret = (func)();                                     \
        PARSE_SYSCALL2(name, 0, #r, __ret);                     \
        ret = (SHIM_ARG_TYPE) __ret;                            \
    END_SHIM(name)

#define SHIM_SYSCALL_1(name, func, r, t1, a1)                               \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1)                                  \
        t1 a1 = (t1) __arg1;                                                \
        PARSE_SYSCALL1(name, 1, #t1, a1);                                   \
        r __ret = (func)(a1);                                               \
        PARSE_SYSCALL2(name, 1, #r, __ret, #t1, a1);                        \
        ret = (SHIM_ARG_TYPE) __ret;                                        \
    END_SHIM(name)

#define SHIM_SYSCALL_2(name, func, r, t1, a1, t2, a2)                       \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2)            \
        t1 a1 = (t1) __arg1;                                                \
        t2 a2 = (t2) __arg2;                                                \
        PARSE_SYSCALL1(name, 2, #t1, a1, #t2, a2);                          \
        r __ret = (func)(a1, a2);                                           \
        PARSE_SYSCALL2(name, 2, #r, __ret, #t1, a1, #t2, a2);               \
        ret = (SHIM_ARG_TYPE) __ret;                                        \
    END_SHIM(name)

#define SHIM_SYSCALL_3(name, func, r, t1, a1, t2, a2, t3, a3)               \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2,            \
                     SHIM_ARG_TYPE __arg3)                                  \
        t1 a1 = (t1) __arg1;                                                \
        t2 a2 = (t2) __arg2;                                                \
        t3 a3 = (t3) __arg3;                                                \
        PARSE_SYSCALL1(name, 3, #t1, a1, #t2, a2, #t3, a3);                 \
        r __ret = (func)(a1, a2, a3);                                       \
        PARSE_SYSCALL2(name, 3, #r, __ret, #t1, a1, #t2, a2, #t3, a3);      \
        ret = (SHIM_ARG_TYPE) __ret;                                        \
    END_SHIM(name)

#define SHIM_SYSCALL_4(name, func, r, t1, a1, t2, a2, t3, a3, t4, a4)       \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2,            \
                     SHIM_ARG_TYPE __arg3, SHIM_ARG_TYPE __arg4)            \
        t1 a1 = (t1) __arg1;                                                \
        t2 a2 = (t2) __arg2;                                                \
        t3 a3 = (t3) __arg3;                                                \
        t4 a4 = (t4) __arg4;                                                \
        PARSE_SYSCALL1(name, 4, #t1, a1, #t2, a2, #t3, a3, #t4, a4);        \
        r __ret = (func)(a1, a2, a3, a4);                                   \
        PARSE_SYSCALL2(name, 4, #r, __ret, #t1, a1, #t2, a2, #t3, a3,       \
                       #t4, a4);                                            \
        ret = (SHIM_ARG_TYPE) __ret;                                        \
    END_SHIM(name)

#define SHIM_SYSCALL_5(name, func, r, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5) \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2,            \
                     SHIM_ARG_TYPE __arg3, SHIM_ARG_TYPE __arg4,            \
                     SHIM_ARG_TYPE __arg5)                                  \
        t1 a1 = (t1) __arg1;                                                \
        t2 a2 = (t2) __arg2;                                                \
        t3 a3 = (t3) __arg3;                                                \
        t4 a4 = (t4) __arg4;                                                \
        t5 a5 = (t5) __arg5;                                                \
        PARSE_SYSCALL1(name, 5, #t1, a1, #t2, a2, #t3, a3, #t4, a4,         \
                       #t5, a5);                                            \
        r __ret = (func)(a1, a2, a3, a4, a5);                               \
        PARSE_SYSCALL2(name, 5, #r, __ret, #t1, a1, #t2, a2, #t3, a3,       \
                       #t4, a4, #t5, a5);                                   \
        ret = (SHIM_ARG_TYPE) __ret;                                        \
    END_SHIM(name)

#define SHIM_SYSCALL_6(name, func, r, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6) \
    BEGIN_SHIM(name, SHIM_ARG_TYPE __arg1, SHIM_ARG_TYPE __arg2,            \
                     SHIM_ARG_TYPE __arg3, SHIM_ARG_TYPE __arg4,            \
                     SHIM_ARG_TYPE __arg5, SHIM_ARG_TYPE __arg6)            \
        t1 a1 = (t1) __arg1;                                                \
        t2 a2 = (t2) __arg2;                                                \
        t3 a3 = (t3) __arg3;                                                \
        t4 a4 = (t4) __arg4;                                                \
        t5 a5 = (t5) __arg5;                                                \
        t6 a6 = (t6) __arg6;                                                \
        PARSE_SYSCALL1(name, 6, #t1, a1, #t2, a2, #t3, a3, #t4, a4,         \
                       #t5, a5, #t6, a6);                                   \
        r __ret = (func)(a1, a2, a3, a4, a5, a6);                           \
        PARSE_SYSCALL2(name, 6, #r, __ret, #t1, a1, #t2, a2, #t3, a3,       \
                       #t4, a4, #t5, a5, #t6, a6);  \
        ret = (SHIM_ARG_TYPE) __ret;                                        \
    END_SHIM(name)

#define SHIM_PROTO_ARGS_0 void
#define SHIM_PROTO_ARGS_1 SHIM_ARG_TYPE __arg1
#define SHIM_PROTO_ARGS_2 SHIM_PROTO_ARGS_1, SHIM_ARG_TYPE __arg2
#define SHIM_PROTO_ARGS_3 SHIM_PROTO_ARGS_2, SHIM_ARG_TYPE __arg3
#define SHIM_PROTO_ARGS_4 SHIM_PROTO_ARGS_3, SHIM_ARG_TYPE __arg4
#define SHIM_PROTO_ARGS_5 SHIM_PROTO_ARGS_4, SHIM_ARG_TYPE __arg5
#define SHIM_PROTO_ARGS_6 SHIM_PROTO_ARGS_5, SHIM_ARG_TYPE __arg6

#define SHIM_PASS_ARGS_1 __arg1
#define SHIM_PASS_ARGS_2 SHIM_PASS_ARGS_1, __arg2
#define SHIM_PASS_ARGS_3 SHIM_PASS_ARGS_2, __arg3
#define SHIM_PASS_ARGS_4 SHIM_PASS_ARGS_3, __arg4
#define SHIM_PASS_ARGS_5 SHIM_PASS_ARGS_4, __arg5
#define SHIM_PASS_ARGS_6 SHIM_PASS_ARGS_5, __arg6

#define SHIM_UNUSED_ARGS_0()

#define SHIM_UNUSED_ARGS_1() do {               \
        __UNUSED(__arg1);                       \
    } while (0)
#define SHIM_UNUSED_ARGS_2() do {               \
        __UNUSED(__arg1);                       \
        __UNUSED(__arg2);                       \
    } while (0)
#define SHIM_UNUSED_ARGS_3() do {               \
        __UNUSED(__arg1);                       \
        __UNUSED(__arg2);                       \
        __UNUSED(__arg3);                       \
    } while (0)
#define SHIM_UNUSED_ARGS_4() do {               \
        __UNUSED(__arg1);                       \
        __UNUSED(__arg2);                       \
        __UNUSED(__arg3);                       \
        __UNUSED(__arg4);                       \
    } while (0)

#define SHIM_UNUSED_ARGS_5() do {               \
        __UNUSED(__arg1);                       \
        __UNUSED(__arg2);                       \
        __UNUSED(__arg3);                       \
        __UNUSED(__arg4);                       \
        __UNUSED(__arg5);                       \
    } while (0)

#define SHIM_UNUSED_ARGS_6() do {               \
        __UNUSED(__arg1);                       \
        __UNUSED(__arg2);                       \
        __UNUSED(__arg3);                       \
        __UNUSED(__arg4);                       \
        __UNUSED(__arg5);                       \
        __UNUSED(__arg6);                       \
    } while (0)

#define DO_SYSCALL(...) DO_SYSCALL2(__VA_ARGS__)
#define DO_SYSCALL2(n, ...) -ENOSYS

#define DO_SYSCALL_0(sysno) -ENOSYS
#define DO_SYSCALL_1(sysno, ...) DO_SYSCALL(1, sysno, SHIM_PASS_ARGS_1)
#define DO_SYSCALL_2(sysno, ...) DO_SYSCALL(2, sysno, SHIM_PASS_ARGS_2)
#define DO_SYSCALL_3(sysno, ...) DO_SYSCALL(3, sysno, SHIM_PASS_ARGS_3)
#define DO_SYSCALL_4(sysno, ...) DO_SYSCALL(4, sysno, SHIM_PASS_ARGS_4)
#define DO_SYSCALL_5(sysno, ...) DO_SYSCALL(5, sysno, SHIM_PASS_ARGS_5)
#define DO_SYSCALL_6(sysno, ...) DO_SYSCALL(6, sysno, SHIM_PASS_ARGS_6)

#define SHIM_SYSCALL_PASSTHROUGH(name, n, ...)                      \
    DEFINE_PROFILE_INTERVAL(syscall_##name##_slow, syscall);        \
    DEFINE_PROFILE_INTERVAL(syscall_##name, syscall);               \
    BEGIN_SHIM(name, SHIM_PROTO_ARGS_##n)                           \
        debug("WARNING: shim_" #name " not implemented\n");         \
        SHIM_UNUSED_ARGS_##n();                                     \
        ret = DO_SYSCALL_##n(__NR_##name);                          \
    END_SHIM(name)                                                  \
    EXPORT_SHIM_SYSCALL(name, n, __VA_ARGS__)

#define CONCAT2(t1, t2) __CONCAT2(t1, t2)
#define __CONCAT2(t1, t2) t1##_##t2

#define CONCAT3(t1, t2, t3) __CONCAT3(t1, t2, t3)
#define __CONCAT3(t1, t2, t3) t1##_##t2##_##t3

/* Some SHIM internal errno */
#define EISLINK          141    /* the path is a link */
#define ECONTAINLINK     142    /* part of path contains a link */
#define ENOTLINK         143    /* the path is not a link */
#define ESKIPPED         144    /* skip looking up current path */

#define PAL_CB(member)     (pal_control.member)

#define LOCK_FREE ((IDTYPE) -1)

extern bool lock_enabled;

static inline void enable_locking (void)
{
    if (!lock_enabled)
        lock_enabled = true;
}

static inline PAL_HANDLE thread_create (void * func, void * arg)
{
    assert(lock_enabled);
    return DkThreadCreate(func, arg);
}

static inline int64_t __disable_preempt (shim_tcb_t * tcb)
{
    //tcb->context.syscall_nr += SYSCALL_NR_PREEMPT_INC;
    int64_t preempt = atomic_inc_return(&tcb->context.preempt);
    /* Assert if this counter overflows */
    assert(preempt != 0);
    //debug("disable preempt: %d\n", preempt);
    return preempt;
}

static inline void disable_preempt (shim_tcb_t * tcb)
{
    if (!tcb && !(tcb = shim_get_tcb()))
        return;

    __disable_preempt(tcb);
}

static inline void __enable_preempt (shim_tcb_t * tcb)
{
    int64_t preempt = atomic_add_return(-1, &tcb->context.preempt);
    /* Assert if this counter underflows */
    __UNUSED(preempt);
    assert(preempt >= 0);
    //debug("enable preempt: %d\n", preempt);
}

void __handle_signal (shim_tcb_t * tcb, int sig);

static inline void enable_preempt (shim_tcb_t * tcb)
{
    if (!tcb && !(tcb = shim_get_tcb()))
        return;

    int64_t preempt = atomic_read(&tcb->context.preempt);
    if (!preempt)
        return;

    if (preempt == 1)
        __handle_signal(tcb, 0);

    __enable_preempt(tcb);
}

static inline bool lock_created(struct shim_lock* l)
{
    return l->lock != NULL;
}

static inline void clear_lock(struct shim_lock* l)
{
    l->lock = NULL;
    l->owner = 0;
}

static inline bool create_lock(struct shim_lock* l) {
    l->owner = 0;
    l->lock = DkMutexCreate(0);
    return l->lock != NULL;
}

static inline void destroy_lock(struct shim_lock* l) {
    DkObjectClose(l->lock);
    l->lock = NULL;
    l->owner = 0;
}

#ifdef DEBUG
#define lock(l) __lock(l, __FILE__, __LINE__)
static void __lock(struct shim_lock* l, const char* file, int line) {
#else
static void lock(struct shim_lock* l) {
#endif
    if (!lock_enabled) {
        return;
    }
    /* TODO: This whole if should be just an assert. Change it once we are sure that it does not
     * trigger (previous code allowed for this case). Same in unlock below. */
    if (!l->lock) {
#ifdef DEBUG
        debug("Trying to lock an uninitialized lock at %s:%d!\n", file, line);
#endif // DEBUG
        __abort();
    }

    shim_tcb_t * tcb = shim_get_tcb();
    disable_preempt(tcb);

    while (!DkSynchronizationObjectWait(l->lock, NO_TIMEOUT))
        /* nop */;

    l->owner = tcb->tid;
}

#ifdef DEBUG
#define unlock(l) __unlock(l, __FILE__, __LINE__)
static inline void __unlock(struct shim_lock* l, const char* file, int line) {
#else
static inline void unlock(struct shim_lock* l) {
#endif
    if (!lock_enabled) {
        return;
    }
    if (!l->lock) {
#ifdef DEBUG
        debug("Trying to unlock an uninitialized lock at %s:%d!\n", file, line);
#endif // DEBUG
        __abort();
    }

    shim_tcb_t* tcb = shim_get_tcb();

    l->owner = 0;
    DkMutexRelease(l->lock);
    enable_preempt(tcb);
}

static inline bool locked(struct shim_lock* l) {
    if (!lock_enabled) {
        return true;
    }
    if (!l->lock) {
        return false;
    }
    return get_cur_tid() == l->owner;
}

#define DEBUG_MASTER_LOCK 0

extern struct shim_lock __master_lock;

#if DEBUG_MASTER_LOCK == 1
# define MASTER_LOCK()                                              \
    do {                                                            \
        lock(&__master_lock);                                       \
        pal_printf("master lock " __FILE__ ":%d\n", __LINE__);      \
    } while (0)
# define MASTER_UNLOCK()                                            \
    do {                                                            \
        pal_printf("master unlock " __FILE__ ":%d\n", __LINE__);    \
        unlock(&__master_lock);                                     \
    } while (0)
#else
# define MASTER_LOCK() do { lock(&__master_lock); } while (0)
# define MASTER_UNLOCK() do { unlock(&__master_lock); } while (0)
#endif

static inline bool create_lock_runtime(struct shim_lock* l) {
    bool ret = true;

    if (!lock_created(l)) {
        MASTER_LOCK();
        if (!lock_created(l))
            ret = create_lock(l);
        MASTER_UNLOCK();
    }

    return ret;
}

static inline void create_event (AEVENTTYPE * e)
{
    if (!e->event)
        e->event = DkStreamOpen(URI_PREFIX_PIPE, PAL_ACCESS_RDWR, 0, 0,
                                PAL_OPTION_NONBLOCK);
}

static inline bool event_created (AEVENTTYPE * e)
{
    return e->event != NULL;
}

static inline PAL_HANDLE event_handle (AEVENTTYPE * e)
{
    return e->event;
}

static inline void destroy_event (AEVENTTYPE * e)
{
    if (e->event) {
        DkObjectClose(e->event);
        e->event = NULL;
    }
}

static inline void set_event (AEVENTTYPE * e, int n)
{
    if (e->event) {
        char bytes[n];
        DkStreamWrite(e->event, 0, n, bytes, NULL);
    }
}

static inline void wait_event (AEVENTTYPE * e)
{
    if (e->event) {
        char byte;
        int n = 0;
        do {
            if (!DkSynchronizationObjectWait(e->event, NO_TIMEOUT))
                continue;

            n = DkStreamRead(e->event, 0, 1, &byte, NULL, 0);
        } while (!n);
    }
}

static inline void clear_event (AEVENTTYPE * e)
{
    if (e->event) {
        char bytes[100];
        int n;
        do {
            n = DkStreamRead(e->event, 0, 100, bytes, NULL, 0);
        } while (n == 100);
    }
}

static inline void do_pause (void)
{
    bool go = false;
    while (!go)
        DkThreadDelayExecution(60 * 60 * 1000000ULL);
}

/* reference counter APIs */
#define REF_GET(ref)            atomic_read(&(ref))
#define REF_SET(ref, count)     atomic_set(&(ref), count)

static inline int __ref_inc (REFTYPE * ref)
{
    register int _c;
    do {
        _c = atomic_read(ref);
        assert(_c >= 0);
    } while (atomic_cmpxchg(ref, _c, _c + 1) != _c);
    return _c + 1;
}

#define REF_INC(ref)  __ref_inc(&(ref))

static inline int __ref_dec (REFTYPE * ref)
{
    register int _c;
    do {
        _c = atomic_read(ref);
        if (!_c) {
            debug("Fail: Trying to drop reference count below 0\n");
            BUG();
            return 0;
        }
    } while (atomic_cmpxchg(ref, _c, _c - 1) != _c);
    return _c - 1;
}

#define REF_DEC(ref) __ref_dec(&(ref))

/* integer hash functions */
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

#ifndef __alloca
# define __alloca __builtin_alloca
#endif

extern size_t g_pal_alloc_align;
#define ALLOC_ALIGNMENT         g_pal_alloc_align
#define IS_ALLOC_ALIGNED(x)     IS_ALIGNED_POW2(x, g_pal_alloc_align)
#define IS_ALLOC_ALIGNED_PTR(x) IS_ALIGNED_PTR_POW2(x, g_pal_alloc_align)
#define ALLOC_ALIGN_DOWN(x)     ALIGN_DOWN_POW2(x, g_pal_alloc_align)
#define ALLOC_ALIGN_UP(x)       ALIGN_UP_POW2(x, g_pal_alloc_align)
#define ALLOC_ALIGN_DOWN_PTR(x) ALIGN_DOWN_PTR_POW2(x, g_pal_alloc_align)
#define ALLOC_ALIGN_UP_PTR(x)   ALIGN_UP_PTR_POW2(x, g_pal_alloc_align)

void * __system_malloc (size_t size);
void __system_free (void * addr, size_t size);

#define system_malloc __system_malloc
#define system_free __system_free

extern void * migrated_memory_start;
extern void * migrated_memory_end;

static inline bool memory_migrated(void * mem)
{
    return mem >= migrated_memory_start && mem < migrated_memory_end;
}


extern void * __load_address, * __load_address_end;
extern void * __code_address, * __code_address_end;

unsigned long parse_int (const char * str);

extern void * initial_stack;
extern const char ** initial_envp;

void get_brk_region (void ** start, void ** end, void ** current);

int reset_brk (void);
struct shim_handle;
int init_brk_from_executable (struct shim_handle * exec);
int init_brk_region(void* brk_region, size_t data_segment_size);
int init_heap (void);
int init_internal_map (void);
int init_loader (void);
int init_manifest (PAL_HANDLE manifest_handle);
int init_rlimit(void);

bool test_user_memory (void * addr, size_t size, bool write);
bool test_user_string (const char * addr);

uint64_t get_rlimit_cur(int resource);
void set_rlimit_cur(int resource, uint64_t rlim);

int object_wait_with_retry(PAL_HANDLE handle);

void release_clear_child_tid(int* clear_child_tid);

void delete_from_epoll_handles(struct shim_handle* handle);

#ifdef __x86_64__
#define __SWITCH_STACK(stack_top, func, arg)                    \
    do {                                                        \
        /* 16 Bytes align of stack */                           \
        uintptr_t __stack_top = (uintptr_t)(stack_top);         \
        __stack_top &= ~0xf;                                    \
        __stack_top -= 8;                                       \
        __asm__ volatile (                                      \
            "movq %0, %%rbp\n"                                  \
            "movq %0, %%rsp\n"                                  \
            "jmpq *%1\n"                                        \
            ::"r"(__stack_top), "r"(func), "D"(arg): "memory"); \
    } while (0)

static_always_inline void * current_stack(void)
{
    void * _rsp;
    __asm__ volatile ("movq %%rsp, %0" : "=r"(_rsp) :: "memory");
    return _rsp;
}

#else
# error "Unsupported architecture"
#endif /* __x86_64__ */

static inline IDTYPE hashtype_to_idtype(HASHTYPE hash) {
    static_assert(sizeof(HASHTYPE) == 8, "Unsupported HASHTYPE size");
    static_assert(sizeof(IDTYPE) == 4, "Unsupported IDTYPE size");
    return ((IDTYPE)hash) ^ ((IDTYPE)(hash >> 32));
}

#endif /* _PAL_INTERNAL_H_ */
