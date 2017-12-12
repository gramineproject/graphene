/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#ifndef _SHIM_DEFS_H_
#define _SHIM_DEFS_H_

#define MIGRATE_MORE_GIPC           0

#define HASH_GIPC                   0

#define DEFAULT_HEAP_MIN_SIZE       (256 * 1024 * 1024) /* 256MB */
#define DEFAULT_MEM_MAX_NPAGES      (1024 * 1024)       /* 4GB */
#define DEFAULT_BRK_MAX_SIZE        (256 * 1024)        /* 256KB */
#define DEFAULT_SYS_STACK_SIZE      (256 * 1024)        /* 256KB */

/*
 * Default size on stack reserved for auxilary vectors:
 * (1) AT_PHDR (2) AT_PHNUM (3) AT_PAGESZ (4) AT_ENTRY (5) AT_BASE
 * (6) AT_RANDOM (7) AT_NULL (8) reserved
 */
#define DEFAULT_AUXV_NUM        (8)

/* By default, AT_RANDOM_SIZE is 16, unless specified otherwise. */
#define AUXV_RANDOM_SIZE        (16)

/* Default reserved size on application stack */
#define DEFAULT_STACK_RESERVE_SIZE  \
    (sizeof(elf_auxv_t) * DEFAULT_AUXV_NUM + AUXV_RANDOM_SIZE)

#define CP_INIT_VMA_SIZE            (64 * 1024 * 1024)  /* 64MB */

#define EXECVE_RTLD                 1

/* debug message printout */
#define DEBUGBUF_SIZE               256
#define DEBUGBUF_BREAK              0

#endif /* _SHIM_DEFS_H_ */
