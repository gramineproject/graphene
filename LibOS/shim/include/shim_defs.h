#ifndef _SHIM_DEFS_H_
#define _SHIM_DEFS_H_

#define MIGRATE_MORE_GIPC           0

#define HASH_GIPC                   0

/*
 * If enable CPSTORE_DERANDOMIZATION, the library OS will try to
 * load the checkpoint (either from the parent or a file) at the
 * exact address it was created. Currently this option is disabled
 * to prevent internal fragmentation of virtual memory space.
 */
#define CPSTORE_DERANDOMIZATION     0

#define DEFAULT_HEAP_MIN_SIZE       (256 * 1024 * 1024) /* 256MB */
#define DEFAULT_MEM_MAX_NPAGES      (1024 * 1024)       /* 4GB */
#define DEFAULT_BRK_MAX_SIZE        (256 * 1024)        /* 256KB */
#define DEFAULT_SYS_STACK_SIZE      (256 * 1024)        /* 256KB */

#define CP_INIT_VMA_SIZE            (64 * 1024 * 1024)  /* 64MB */

#define EXECVE_RTLD                 1

#define ENABLE_ASLR                 1

/* debug message printout */
#define DEBUGBUF_SIZE               256
#define DEBUGBUF_BREAK              0

#define DEFAULT_VMA_COUNT           64

/* System V IPC semaphore / message queue migration */
#define MIGRATE_SYSV_SEM            0
#define MIGRATE_SYSV_MSG            1

/* ELF aux vectors  */
#define REQUIRED_ELF_AUXV           8   /* number of LibOS-supported vectors */
#define REQUIRED_ELF_AUXV_SPACE     16  /* extra memory space (in bytes) */

#endif /* _SHIM_DEFS_H_ */
