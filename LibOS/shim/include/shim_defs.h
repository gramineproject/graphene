#ifndef _SHIM_DEFS_H_
#define _SHIM_DEFS_H_

#define DEFAULT_HEAP_MIN_SIZE       (256 * 1024 * 1024) /* 256MB */
#define DEFAULT_MEM_MAX_NPAGES      (1024 * 1024)       /* 4GB */
#define DEFAULT_BRK_MAX_SIZE        (256 * 1024)        /* 256KB */
#define DEFAULT_SYS_STACK_SIZE      (256 * 1024)        /* 256KB */

#define CP_INIT_VMA_SIZE            (64 * 1024 * 1024)  /* 64MB */

/* debug message printout */
#define DEBUGBUF_SIZE               256
#define DEBUGBUF_BREAK              0

#define DEFAULT_VMA_COUNT           64

/* ELF aux vectors  */
#define REQUIRED_ELF_AUXV           8   /* number of LibOS-supported vectors */
#define REQUIRED_ELF_AUXV_SPACE     16  /* extra memory space (in bytes) */

#if defined(__i386__) || defined(__x86_64__)
#define LIBOS_SYSCALL_BOUND         (340 + 1)
#endif

#endif /* _SHIM_DEFS_H_ */
