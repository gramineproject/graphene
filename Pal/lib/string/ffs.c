/* ffs -- find first set bit in a word, counted from least significant end.
   For AMD x86-64.
   This file is part of the GNU C Library.
   Copyright (C) 1991-2014 Free Software Foundation, Inc.
   Contributed by Ulrich Drepper <drepper@cygnus.com>.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#include "api.h"

int ffs (int x)
{
  int cnt;
  int tmp;

  __asm__ ("bsfl %2,%0\n"           /* Count low bits in X and store in %1.  */
           "cmovel %1,%0\n"         /* If number was zero, use -1 as result.  */
           : "=&r" (cnt), "=r" (tmp) : "rm" (x), "1" (-1));

  return cnt + 1;
}

int
ffsl (long int x)
{
  long int cnt;
  long int tmp;

  __asm__ ("bsfq %2,%0\n"           /* Count low bits in X and store in %1.  */
           "cmoveq %1,%0\n"         /* If number was zero, use -1 as result.  */
           : "=&r" (cnt), "=r" (tmp) : "rm" (x), "1" (-1));

  return cnt + 1;
}
