#ifndef _SHIM_TLS_H_
#define _SHIM_TLS_H_

#ifndef __ASSEMBLER__

#define SHIM_TLS_CANARY 0xdeadbeef

struct lock_record {
    enum { NO_LOCK, SEM_LOCK, READ_LOCK, WRITE_LOCK } type;
    void * lock;
    const char * filename;
    int lineno;
};

#define NUM_LOCK_RECORD      32
#define NUM_LOCK_RECORD_MASK (NUM_LOCK_RECORD - 1)

struct shim_regs {
    unsigned long           orig_rax;
    unsigned long           rsp;
    unsigned long           r15;
    unsigned long           r14;
    unsigned long           r13;
    unsigned long           r12;
    unsigned long           r11;
    unsigned long           r10;
    unsigned long           r9;
    unsigned long           r8;
    unsigned long           rcx;
    unsigned long           rdx;
    unsigned long           rsi;
    unsigned long           rdi;
    unsigned long           rbx;
    unsigned long           rbp;
    unsigned long           rflags;
    unsigned long           rip;
};

struct shim_context {
    struct shim_regs *      regs;
    struct shim_context *   next;
    uint64_t                enter_time;
    uint64_t                preempt;
};

#ifdef IN_SHIM

#include <shim_defs.h>

#endif /* IN_SHIM */

struct debug_buf;

typedef struct shim_tcb shim_tcb_t;
struct shim_tcb {
    uint64_t                canary;
#ifdef ENABLE_STACK_PROTECTOR
#define STACK_PROTECTOR_CANARY_DEFAULT  0xbadbadbadbadUL
    uint64_t                stack_protector_canary;
#endif
    shim_tcb_t *            self;
    struct shim_thread *    tp;
    struct shim_context     context;
    unsigned int            tid;
    int                     pal_errno;
    struct debug_buf *      debug_buf;

    /* This record is for testing the memory of user inputs.
     * If a segfault occurs with the range [start, end],
     * the code addr is set to cont_addr to alert the caller. */
    struct {
        void * start, * end;
        void * cont_addr;
    } test_range;
};

#ifdef IN_SHIM

/*
 * This struct must match the one defined in glibc/nptl/sysdeps/x86_64/tls.h
 * The first 10 members(from tcb to __unused1) are used by Glibc-internal,
 * they are NOT used by Graphene.
 * But Graphene needs to preserve the correct offset of shim_tcb so we have to
 * duplicate these 10 fields from the original Glibc struct.
 */
struct __libc_tcb_t;
typedef struct __libc_tcb_t __libc_tcb_t;
struct __libc_tcb_t
{
    __libc_tcb_t *          tcb;
    void *                  dtv, * self;
    int                     mthreads, gscope;
    uintptr_t               sysinfo, sg, pg;
    unsigned long int       vgetcpu_cache[2];
    int                     __unused1;
    shim_tcb_t              shim_tcb;
};

#include <stddef.h>

void __init_tcb (shim_tcb_t * tcb);
#ifdef ENABLE_STACK_PROTECTOR
void init_tcb (shim_tcb_t * tcb);
#else
static inline void init_tcb (shim_tcb_t * tcb)
{
    __init_tcb(tcb);
}
#endif

static inline bool shim_tls_check_canary(void)
{
    uint64_t __canary;
    __asm__ ("movq %%fs:%c1,%q0" : "=r" (__canary)
             : "i" (offsetof(__libc_tcb_t, shim_tcb.canary)));
    return __canary == SHIM_TLS_CANARY;
}

static inline shim_tcb_t * shim_get_tls(void)
{
    shim_tcb_t *__self;
    __asm__ ("movq %%fs:%c1,%q0" : "=r" (__self)
             : "i" (offsetof(__libc_tcb_t, shim_tcb.self)));
    return __self;
}

static inline __libc_tcb_t * shim_libc_tcb(void)
{
    __libc_tcb_t *__self;
    __asm__ ("movq %%fs:%c1,%q0" : "=r" (__self)
             : "i" (offsetof(__libc_tcb_t, tcb)));
    return __self;
}

#endif /* IN_SHIM */

#endif /* !__ASSEMBLER__ */

#endif /* _SHIM_H_ */
