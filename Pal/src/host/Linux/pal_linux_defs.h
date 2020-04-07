#ifndef PAL_LINUX_DEFS_H
#define PAL_LINUX_DEFS_H

#define USER_ADDRESS_LOWEST 0x10000

#define THREAD_STACK_SIZE (PRESET_PAGESIZE * 2)   /* 8KB initial stack (grows automatically) */
#define ALT_STACK_SIZE    (PRESET_PAGESIZE * 16)  /* 64KB signal stack */

#define USE_VSYSCALL_GETTIME 0
#define USE_VDSO_GETTIME     1
#define USE_CLOCK_GETTIME    1

#define USE_ARCH_RDRAND 0

#define BLOCK_SIGFAULT 0

#ifndef FIONREAD
#define FIONREAD 0x541B
#endif

#endif /* PAL_LINUX_DEFS_H */
