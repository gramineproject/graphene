/* ===-- udivmodti4.c - Implement __udivmodti4 -----------------------------===
 *
 *                    The LLVM Compiler Infrastructure
 *
 * This file is dual licensed under the MIT and the University of Illinois Open
 * Source Licenses. See LICENSE.TXT for details.
 *
 * ===----------------------------------------------------------------------===
 *
 * This file implements __udivmodti4 for the compiler_rt library.
 *
 * ===----------------------------------------------------------------------===
 */

#ifndef _UDIVMODTI4_
#define _UDIVMODTI4_

typedef          long long di_int;
typedef unsigned long long du_int;

typedef          int si_int;
typedef unsigned int su_int;

typedef          int ti_int __attribute__((mode (TI)));
typedef unsigned int tu_int __attribute__((mode (TI)));

tu_int __udivti3(tu_int a, tu_int b);

#endif /* _UDIVMODTI4_ */
