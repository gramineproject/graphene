#ifndef _SHIM_UNISTD_DEFS_H_
#define _SHIM_UNISTD_DEFS_H_

#if defined(__i386__) || defined(__x86_64__)
#define LIBOS_SYSCALL_BASE  340
#endif

#define LIBOS_SYSCALL_BOUND (LIBOS_SYSCALL_BASE + 1 + 4) /* 4 custom syscalls */

#endif
