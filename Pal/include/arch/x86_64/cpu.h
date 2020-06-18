/* SPDX-License-Identifier: LGPL-3.0-or-later */

#ifndef CPU_H
#define CPU_H

static inline void cpu_pause(void) {
    __asm__ volatile("pause");
}

/* this function is used to get TSC cycle */
static inline unsigned long get_tsc(void) {
    unsigned long lo, hi;
    __asm__ volatile("rdtsc" : "=a" (lo), "=d" (hi));
    return lo | (hi << 32);
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
