#ifndef _SHIM_DEFS_H_
#define _SHIM_DEFS_H_

/*
 * If enable CPSTORE_DERANDOMIZATION, the library OS will try to
 * load the checkpoint (either from the parent or a file) at the
 * exact address it was created. Currently this option is disabled
 * to prevent internal fragmentation of virtual memory space.
 */
#define CPSTORE_DERANDOMIZATION     1

/* This macro disables current vfork implementation and aliases it to fork.
 *
 * Rationale:
 * Current vfork() implementation is broken and works only in simple cases.
 * The implementation creates a new thread in the same process and runs it
 * in place of the previous (parent) thread which called vfork(). When the
 * "pseudo-process" new thread reaches execve(), it silently dies and
 * switches execution back to the suspended parent thread (as per vfork
 * semantics). Because execve() emulation creates a new host-OS process,
 * this vfork implementation works in simple benign cases.
 *
 * However, this co-existence of the "pseudo-process" thread with threads
 * of the parent process leads to bugs elsewhere in Graphene. In general,
 * the rest of Graphene is not aware of such situation when two processes
 * co-exist in the same Graphene instance and share memory. If the new
 * "pseudo-process" thread makes syscalls in-between vfork() and execve()
 * or abnormally dies or receives a signal, Graphene may hang or segfault
 * or end up with inconsistent internal state.
 *
 * Therefore, instead of trying to support Linux semantics for vfork() --
 * which requires adding corner-cases in signal handling and syscalls --
 * we simply redirect vfork() as fork(). We assume that performance hit is
 * negligible (Graphene has to migrate internal state anyway which is slow)
 * and apps do not rely on insane Linux-specific semantics of vfork().
 * */
#define ALIAS_VFORK_AS_FORK 1

#define DEFAULT_HEAP_MIN_SIZE       (256 * 1024 * 1024) /* 256MB */
#define DEFAULT_MEM_MAX_NPAGES      (1024 * 1024)       /* 4GB */
#define DEFAULT_BRK_MAX_SIZE        (256 * 1024)        /* 256KB */
#define DEFAULT_SYS_STACK_SIZE      (256 * 1024)        /* 256KB */

#define CP_INIT_VMA_SIZE            (64 * 1024 * 1024)  /* 64MB */

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
