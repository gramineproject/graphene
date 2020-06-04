#ifndef _ATOMIC_H_
#define _ATOMIC_H_

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

#include <stdbool.h>
#include <stdint.h>

struct atomic_int {
    volatile int64_t counter;
};

#define ATOMIC_INIT(i)      { (i) }

/* Read the value currently stored in the atomic_int */
static inline int64_t atomic_read(const struct atomic_int* v) {
    return __atomic_load_n(&v->counter, __ATOMIC_SEQ_CST);
}

/* Does a blind write to the atomic variable */
static inline void atomic_set(struct atomic_int* v, int64_t i) {
    __atomic_store_n(&v->counter, i, __ATOMIC_SEQ_CST);
}

/* Helper function that atomically adds a value to an atomic_int,
 * and returns the _new_ value. */
static inline int64_t _atomic_add(int64_t i, struct atomic_int* v) {
    return __atomic_add_fetch(&v->counter, i, __ATOMIC_SEQ_CST);
}

/* Atomically adds i to v.  Does not return a value. */
static inline void atomic_add(int64_t i, struct atomic_int* v) {
    __atomic_add_fetch(&v->counter, i, __ATOMIC_SEQ_CST);
}

/* Atomically substracts i from v.  Does not return a value. */
static inline void atomic_sub(int64_t i, struct atomic_int* v) {
    __atomic_sub_fetch(&v->counter, i, __ATOMIC_SEQ_CST);
}

/* Atomically adds 1 to v.  Does not return a value. */
static inline void atomic_inc(struct atomic_int* v) {
    __atomic_add_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

/* Atomically substracts 1 from v.  Does not return a value. */
static inline void atomic_dec(struct atomic_int* v) {
    __atomic_sub_fetch(&v->counter, 1, __ATOMIC_SEQ_CST);
}

/* Atomically substracts 1 from v.  Returns true if this causes the
   value to reach 0; returns false otherwise. */
static inline bool atomic_dec_and_test(struct atomic_int* v) {
    return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_SEQ_CST) == 0;
}

#define atomic_add_return(i, v)  _atomic_add(i, v)
#define atomic_inc_return(v)     _atomic_add(1, v)

/* Helper function to atomically compare-and-swap the value pointed to by p.
 * t is the old value, s is the new value.
 * Returns true if s was written to *p, false otherwise. */
static inline bool cmpxchg(volatile int64_t* p, int64_t t, int64_t s) {
    return __atomic_compare_exchange_n(p, &t, s, false, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
}

/* Helper function to atomically compare-and-swap the value in v.
 * If v == old, it sets v = new.
 * Returns true if `new` was written to v, false otherwise. */
static inline bool atomic_cmpxchg(struct atomic_int* v, int64_t old, int64_t new) {
    return cmpxchg(&v->counter, old, new);
}

#endif /* _ATOMIC_H_ */
