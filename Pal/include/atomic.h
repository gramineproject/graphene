/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#ifndef _SHIM_ATOMIC_H_
#define _SHIM_ATOMIC_H_

#define LOCK_PREFIX     "\n\tlock; "

#define ATOMIC_INIT(i)      { (i) }

static inline volatile int atomic_read (const struct atomic_int * v)
{
    return v->counter;
}

static inline void atomic_set (struct atomic_int * v, int i)
{
    v->counter = i;
}

static inline void atomic_add (int i, struct atomic_int * v)
{
    asm volatile(LOCK_PREFIX "addl %1,%0"
                 : "+m" (v->counter)
                 : "ir" (i));
}

static inline void atomic_sub (int i, struct atomic_int * v)
{
    asm volatile(LOCK_PREFIX "subl %1,%0"
                 : "+m" (v->counter)
                 : "ir" (i));
}

static inline int atomic_sub_and_test (int i, struct atomic_int * v)
{
    unsigned char c;
    asm volatile(LOCK_PREFIX "subl %2,%0; sete %1"
                 : "+m" (v->counter), "=qm" (c)
                 : "ir" (i) : "memory");
    return c;
}

/* Return 0 if the value drops below zero, 1 if >= 0 */
static inline int atomic_sub_and_test_nonnegative (int i, struct atomic_int * v)
{
    unsigned char c;
    asm volatile(LOCK_PREFIX "subl %2,%0; setns %1"
                 : "+m" (v->counter), "=qm" (c)
                 : "ir" (i) : "memory");
    return c;
}


static inline void atomic_inc (struct atomic_int * v)
{
    asm volatile(LOCK_PREFIX "incl %0"
                 : "+m" (v->counter));
}

static inline int atomic_inc_and_test (struct atomic_int * v)
{
    unsigned char c;
    asm volatile(LOCK_PREFIX "incl %0; sete %1"
                 : "+m" (v->counter), "=qm" (c)
                 : : "memory");
    return c != 0;
}

static inline void atomic_dec (struct atomic_int * v)
{
    asm volatile(LOCK_PREFIX "decl %0"
                 : "+m" (v->counter));
}

static inline int atomic_dec_and_test (struct atomic_int * v)
{
    unsigned char c;
    asm volatile(LOCK_PREFIX "decl %0; sete %1"
                 : "+m" (v->counter), "=qm" (c)
                 : : "memory");
    return c != 0;
}

/* Return 0 if the value drops below zero, 1 if >= 0 */
static inline int atomic_dec_and_test_nonnegative (struct atomic_int * v)
{
    unsigned char c;
    asm volatile(LOCK_PREFIX "decl %0; setns %1"
                 : "+m" (v->counter), "=qm" (c)
                 : : "memory");
    return c;
}

#ifndef __i386__
# include "cmpxchg_64.h"
#else
# include "cmpxchg_32.h"
#endif

static inline int atomic_cmpxchg (struct atomic_int * v, int old, int new)
{
    return cmpxchg((&v->counter), old, new);
}

static inline int atomic_xchg (struct atomic_int * v, int new)
{
    return xchg((&v->counter), new);
}

#endif /* _ATOMIC_INT_H_ */
