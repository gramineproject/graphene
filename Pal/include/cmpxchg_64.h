#ifndef _ASM_X86_CMPXCHG_64_H
#define _ASM_X86_CMPXCHG_64_H

//#include <asm/alternative.h> /* Provides LOCK_PREFIX */

/*
  Including the definition of LOCK_PREFIX directly here
*/
#define LOCK_PREFIX "\n\tlock; "

#define __xg(x) ((volatile char *)(x))

/*static inline void set_64bit(volatile u64 *ptr, u64 val)
{
	*ptr = val;
}*/

extern void __xchg_wrong_size(void);
extern void __cmpxchg_wrong_size(void);

/*
 * Note: xchg always implies lock prefix.
 * Note 2: xchg has side effect, so that attribute volatile is necessary,
 *	  but generally the primitive is invalid, *ptr is output argument. --ANK
 */
#define __xchg(x, ptr, size)						\
({									\
	__typeof(*(ptr)) __x = (x);					\
	switch (size) {							\
	case 1:								\
	  asm volatile("xchgb %b0,%1"					\
			     : "=q" (__x), "+m" (*__xg(ptr))		\
			     : "0" (__x)				\
			     : "memory");				\
		break;							\
	case 2:								\
	  asm volatile("xchgw %w0,%1"					\
			     : "=r" (__x), "+m" (*__xg(ptr))		\
			     : "0" (__x)				\
			     : "memory");				\
		break;							\
	case 4:								\
	  asm volatile("xchgl %k0,%1"					\
			     : "=r" (__x), "+m" (*__xg(ptr))		\
			     : "0" (__x)				\
			     : "memory");				\
		break;							\
	case 8:								\
	  asm volatile("xchgq %0,%1"					\
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
#define __raw_cmpxchg(ptr, old, new, size)				\
({									\
	__typeof__(*(ptr)) __ret;					\
	__typeof__(*(ptr)) __old = (old);				\
	__typeof__(*(ptr)) __new = (new);				\
	switch (size) {							\
	case 1:								\
	  asm volatile(LOCK_PREFIX "cmpxchgb %b2,%1"			\
			     : "=a" (__ret), "+m" (*__xg(ptr))		\
			     : "q" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	case 2:								\
	  asm volatile(LOCK_PREFIX "cmpxchgw %w2,%1"			\
			     : "=a" (__ret), "+m" (*__xg(ptr))		\
			     : "r" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	case 4:								\
	  asm volatile(LOCK_PREFIX "cmpxchgl %k2,%1"			\
			     : "=a" (__ret), "+m" (*__xg(ptr))		\
			     : "r" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	case 8:								\
	  asm volatile(LOCK_PREFIX "cmpxchgq %2,%1"			\
			     : "=a" (__ret), "+m" (*__xg(ptr))		\
			     : "r" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	default:							\
		__cmpxchg_wrong_size();					\
	}								\
	__ret;								\
})

#define cmpxchg(ptr, old, new)						\
	__raw_cmpxchg((ptr), (old), (new), sizeof(*ptr))

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
