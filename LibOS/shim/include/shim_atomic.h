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
 * shim_atomic.h
 *
 * This file contains functions and macros for atomic operations.
 */

#ifndef _SHIM_ATOMIC_H_
#define _SHIM_ATOMIC_H_

#include "shim_types.h"

/* Optimization barrier */
/* The "volatile" is due to gcc bugs */
#define barrier() __asm__ __volatile__("": : :"memory")

#ifdef __x86_64__
/*
 * Some non-Intel clones support  of order store. wmb() ceases to be a
 * nop for these.
 */
# define cpu_relax()    asm volatile ("rep; nop" ::: "memory")
# define mb()    asm volatile ("mfence" ::: "memory")
# define rmb()   asm volatile ("lfence" ::: "memory")
# define wmb()   asm volatile ("sfence" ::: "memory")
#endif

#define LOCK_PREFIX     "\n\tlock; "

#define ATOMIC_INIT(i)      { (i) }

//static inline int atomic_read (const struct shim_atomic * v)
static inline uint64_t atomic_read (const struct shim_atomic * v) 	// Adil
{
    return (*(volatile long *)&(v)->counter);
}

static inline void atomic_set (struct shim_atomic * v, int i)
{
    v->counter = i;
}

static inline void atomic_add (int i, struct shim_atomic * v)
{
    asm volatile(LOCK_PREFIX "addl %1,%0"
                 : "+m" (v->counter)
                 : "ir" (i));
}

static inline void atomic_sub (int i, struct shim_atomic * v)
{
    asm volatile(LOCK_PREFIX "subl %1,%0"
                 : "+m" (v->counter)
                 : "ir" (i));
}

static inline int atomic_sub_and_test (int i, struct shim_atomic * v)
{
    unsigned char c;
    asm volatile(LOCK_PREFIX "subl %2,%0; sete %1"
                 : "+m" (v->counter), "=qm" (c)
                 : "ir" (i) : "memory");
    return c;
}

static inline void atomic_inc (struct shim_atomic * v)
{
    asm volatile(LOCK_PREFIX "incl %0"
                 : "+m" (v->counter));
}

static inline int atomic_inc_and_test (struct shim_atomic * v)
{
    unsigned char c;
    asm volatile(LOCK_PREFIX "incl %0; sete %1"
                 : "+m" (v->counter), "=qm" (c)
                 : : "memory");
    return c != 0;
}

static inline void atomic_dec (struct shim_atomic * v)
{
    asm volatile(LOCK_PREFIX "decl %0"
                 : "+m" (v->counter));
}

static inline int atomic_dec_and_test (struct shim_atomic * v)
{
    unsigned char c;
    asm volatile(LOCK_PREFIX "decl %0; sete %1"
                 : "+m" (v->counter), "=qm" (c)
                 : : "memory");
    return c != 0;
}

#undef LOCK_PREFIX

#ifndef __i386__
# include "cmpxchg_64.h"
#else
# include "cmpxchg_32.h"
#endif

static inline uint64_t atomic_cmpxchg (struct shim_atomic * v, uint64_t old, uint64_t new)
{
    return cmpxchg(&v->counter, old, new);
}

static inline int atomic_xchg (struct shim_atomic * v, int new)
{
    return xchg(&v->counter, new);
}

#endif /* _SHIM_ATOMIC_H_ */
