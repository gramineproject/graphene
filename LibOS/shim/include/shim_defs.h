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

#define CP_INIT_VMA_SIZE            (64 * 1024 * 1024)  /* 64MB */

#define EXECVE_RTLD                 1

#define ENABLE_ASLR                 1

/* debug message printout */
#define DEBUGBUF_SIZE               256
#define DEBUGBUF_BREAK              0

#define DEFAULT_VMA_COUNT           64

#endif /* _SHIM_DEFS_H_ */
