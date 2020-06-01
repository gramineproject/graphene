/*
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

#ifndef CPU_H
#define CPU_H

static inline void cpu_pause(void) {
    __asm__ volatile("pause");
}

#define CPU_RELAX() __asm__ __volatile__("rep; nop" ::: "memory")

/*
 * Some non-Intel clones support out of order store. WMB() ceases to be a
 * nop for these.
 */
# define MB()    __asm__ __volatile__ ("mfence" ::: "memory")
# define RMB()   __asm__ __volatile__ ("lfence" ::: "memory")
# define WMB()   __asm__ __volatile__ ("sfence" ::: "memory")

#endif /* CPU_H */
