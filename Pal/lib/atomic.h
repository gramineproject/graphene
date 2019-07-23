#ifndef _SHIM_ATOMIC_H_
#define _SHIM_ATOMIC_H_

/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2017 Fortanix Inc, and University of North Carolina
 * at Chapel Hill.
 *
 * This file defines atomic operations (And barriers) for use in
 * Graphene.
 *
 * The atomic operation assembly code is taken from musl libc, which
 * is subject to the MIT license.
 *
 * At this point, we primarily focus on x86_64; there are some vestigial
 * 32-bit definitions here, but a more portable version would need to
 * move and reimplement portions of this for 32-bit x86 (or other architectures).
 */

/*
/----------------------------------------------------------------------
Copyright (C) 2005-2014 Rich Felker, et al.

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    ----------------------------------------------------------------------
*/

#include <stdint.h>

/* Optimization barrier */
#define COMPILER_BARRIER() __asm__ __volatile__("": : :"memory")
#define CPU_RELAX() __asm__ __volatile__("rep; nop" ::: "memory")

#ifdef __i386__
# define RMB()      __asm__ __volatile__("lock; addl $0,0(%%esp)" ::: "memory")

struct atomic_int {
    volatile int32_t counter;
};
#endif


/* The return types below effectively assume we are dealing with a 64-bit
 * signed value.
 */
#ifdef __x86_64__
/*
 * Some non-Intel clones support out of order store. WMB() ceases to be a
 * nop for these.
 */
# define MB()    __asm__ __volatile__ ("mfence" ::: "memory")
# define RMB()   __asm__ __volatile__ ("lfence" ::: "memory")
# define WMB()   __asm__ __volatile__ ("sfence" ::: "memory")

struct atomic_int {
    volatile int64_t counter;
};
#endif

#define LOCK_PREFIX     "\n\tlock; "

#define ATOMIC_INIT(i)      { (i) }

/* Read the value currently stored in the atomic_int */
static inline int64_t atomic_read (const struct atomic_int * v)
{
    //  Effectively:
    //      return v->counter;
    int64_t i;
    /* Use inline assembly to ensure this is one instruction */
    __asm__ __volatile__("mov %1, %0"
                         : "=r"(i) :
                           "m"(v->counter));
    return i;
}

/* Does a blind write to the atomic variable */
static inline void atomic_set (struct atomic_int * v, int64_t i)
{
    //  Effectively:
    //      v->counter = i;
    /* Use inline assembly to ensure this is one instruction */
    __asm__ __volatile__("mov %2, %0"
                         : "=m"(v->counter) :
                           "m"(v->counter), "r"(i));
}

/* Helper function that atomically adds a value to an atomic_int,
 * and returns the _new_ value. */
static inline int64_t _atomic_add (int64_t i, struct atomic_int * v)
{
    int64_t increment = i;
    __asm__ __volatile__(
        "lock ; xadd %0, %1"
        : "=r"(i), "=m"(v->counter) : "0"(i) : "cc");
    return i + increment;
}

/* Atomically adds i to v.  Does not return a value. */
static inline void atomic_add (int64_t i, struct atomic_int * v)
{
    _atomic_add(i, v);
}

/* Atomically substracts i from v.  Does not return a value. */
static inline void atomic_sub (int64_t i, struct atomic_int * v)
{
    _atomic_add(-i, v);
}

/* Atomically adds 1 to v.  Does not return a value. */
static inline void atomic_inc (struct atomic_int * v)
{
    __asm__ __volatile__(
        "lock ; incl %0"
        : "=m"(v->counter) : "m"(v->counter) : "cc");
}

/* Atomically substracts 1 from v.  Does not return a value. */
static inline void atomic_dec (struct atomic_int * v)
{
    __asm__ __volatile__(
        "lock ; decl %0"
        : "=m"(v->counter) : "m"(v->counter) : "cc");
}

/* Atomically substracts 1 from v.  Returns 1 if this causes the
   value to reach 0; returns 0 otherwise. */
static inline int64_t atomic_dec_and_test (struct atomic_int * v)
{
    int64_t i = _atomic_add(-1, v);
    return i == 0;
}

/* Helper function to atomically compare-and-swap the value pointed to by p.
 * t is the old value, s is the new value.  Returns
 * the value originally in p. */
static inline int64_t cmpxchg(volatile int64_t *p, int64_t t, int64_t s)
{
    __asm__ __volatile__ (
        "lock ; cmpxchg %3, %1"
        : "=a"(t), "=m"(*p) : "a"(t), "r"(s) : "cc");
    return t;
}

#define atomic_add_return(i, v)  _atomic_add(i, v)
#define atomic_inc_return(v)     _atomic_add(1, v)

/* Helper function to atomically compare-and-swap the value in v.
 * If v == old, it sets v = new.
 * Returns the value originally in v. */
static inline int64_t atomic_cmpxchg (struct atomic_int * v, int64_t old, int64_t new)
{
    return cmpxchg(&v->counter, old, new);
}

#endif /* _ATOMIC_INT_H_ */
