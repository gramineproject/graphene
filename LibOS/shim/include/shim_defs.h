#ifndef _SHIM_DEFS_H_
#define _SHIM_DEFS_H_

#include "shim_syscalls.h"

/* Names and values are taken from the Linux kernel. */
#define ERESTARTSYS     512 /* Usual case - restart if SA_RESTART is set. */
#define ERESTARTNOINTR  513 /* Always restart. */
#define ERESTARTNOHAND  514 /* Restart if no signal handler. */

/* Internal LibOS stack size: 7 pages + one guard page. */
#define SHIM_THREAD_LIBOS_STACK_SIZE (7 * PAGE_SIZE + PAGE_SIZE)

#define DEFAULT_BRK_MAX_SIZE   (256 * 1024)        /* 256KB */
#define DEFAULT_SYS_STACK_SIZE (256 * 1024)        /* 256KB */

#define CP_INIT_VMA_SIZE (64 * 1024 * 1024) /* 64MB */

#define DEFAULT_VMA_COUNT 64

/* ELF aux vectors  */
#define REQUIRED_ELF_AUXV       8  /* number of LibOS-supported vectors */
#define REQUIRED_ELF_AUXV_SPACE 16 /* extra memory space (in bytes) */
#define LIBOS_SYSCALL_BOUND __NR_syscalls

#endif /* _SHIM_DEFS_H_ */
