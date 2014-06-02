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
 * cmpxchg_64.h
 */

#ifndef _ASM_X86_CMPXCHG_64_H
#define _ASM_X86_CMPXCHG_64_H

//#include <asm/alternative.h> /* Provides LOCK_PREFIX */

/*
  Including the definition of LOCK_PREFIX directly here
*/
#define LOCK_PREFIX "\n\tlock; "

#define __xg(x) ((volatile long *)(x))

/*static inline void set_64bit(volatile u64 *ptr, u64 val)
{
	*ptr = val;
}*/

extern void __xchg_wrong_size(void);
extern void __cmpxchg_wrong_size(void);

/*
 * Note: no "lock" prefix even on SMP: xchg always implies lock anyway
 * Note 2: xchg has side effect, so that attribute volatile is necessary,
 *	  but generally the primitive is invalid, *ptr is output argument. --ANK
 */
#define __xchg(x, ptr, size)						\
({									\
	__typeof(*(ptr)) __x = (x);					\
	switch (size) {							\
	case 1:								\
	  asm volatile("lock; xchgb %b0,%1"				\
			     : "=q" (__x), "+m" (*__xg(ptr))		\
			     : "0" (__x)				\
			     : "memory");				\
		break;							\
	case 2:								\
	  asm volatile("lock; xchgw %w0,%1"				\
			     : "=r" (__x), "+m" (*__xg(ptr))		\
			     : "0" (__x)				\
			     : "memory");				\
		break;							\
	case 4:								\
	  asm volatile("lock; xchgl %k0,%1"				\
			     : "=r" (__x), "+m" (*__xg(ptr))		\
			     : "0" (__x)				\
			     : "memory");				\
		break;							\
	case 8:								\
	  asm volatile("lock; xchgq %0,%1"				\
			     : "=r" (__x), "+m" (*__xg(ptr))		\
			     : "0" (__x)				\
			     : "memory");				\
		break;							\
	default:							\
		__xchg_wrong_size();					\
	}								\
	__x;								\
})

#define xchg(ptr, v)							\
	__xchg((v), (ptr), sizeof(*ptr))

#define __HAVE_ARCH_CMPXCHG 1

/*
 * Atomic compare and exchange.  Compare OLD with MEM, if identical,
 * store NEW in MEM.  Return the initial value in MEM.  Success is
 * indicated by comparing RETURN with OLD.
 */
#define __raw_cmpxchg(ptr, old, new, size, lock)			\
({									\
	__typeof__(*(ptr)) __ret;					\
	__typeof__(*(ptr)) __old = (old);				\
	__typeof__(*(ptr)) __new = (new);				\
	switch (size) {							\
	case 1:								\
		asm volatile(lock "cmpxchgb %b2,%1"			\
			     : "=a" (__ret), "+m" (*__xg(ptr))		\
			     : "q" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	case 2:								\
		asm volatile(lock "cmpxchgw %w2,%1"			\
			     : "=a" (__ret), "+m" (*__xg(ptr))		\
			     : "r" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	case 4:								\
		asm volatile(lock "cmpxchgl %k2,%1"			\
			     : "=a" (__ret), "+m" (*__xg(ptr))		\
			     : "r" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	case 8:								\
		asm volatile(lock "cmpxchgq %2,%1"			\
			     : "=a" (__ret), "+m" (*__xg(ptr))		\
			     : "r" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	default:							\
		__cmpxchg_wrong_size();					\
	}								\
	__ret;								\
})

#define __cmpxchg(ptr, old, new, size)					\
	__raw_cmpxchg((ptr), (old), (new), (size), LOCK_PREFIX)

#define __sync_cmpxchg(ptr, old, new, size)				\
	__raw_cmpxchg((ptr), (old), (new), (size), "lock; ")

#define __cmpxchg_local(ptr, old, new, size)				\
	__raw_cmpxchg((ptr), (old), (new), (size), "")

#define cmpxchg(ptr, old, new)						\
	__cmpxchg((ptr), (old), (new), sizeof(*ptr))

#define sync_cmpxchg(ptr, old, new)					\
	__sync_cmpxchg((ptr), (old), (new), sizeof(*ptr))

#define cmpxchg_local(ptr, old, new)					\
	__cmpxchg_local((ptr), (old), (new), sizeof(*ptr))

#define cmpxchg64(ptr, o, n)						\
({									\
	BUILD_BUG_ON(sizeof(*(ptr)) != 8);				\
	cmpxchg((ptr), (o), (n));					\
})

#define cmpxchg64_local(ptr, o, n)					\
({									\
	BUILD_BUG_ON(sizeof(*(ptr)) != 8);				\
	cmpxchg_local((ptr), (o), (n));					\
})

#endif /* _ASM_X86_CMPXCHG_64_H */
