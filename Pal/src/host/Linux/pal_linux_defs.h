#ifndef PAL_LINUX_DEFS_H
#define PAL_LINUX_DEFS_H

/* default heap base cannot start at zero (modern OSes do not allow this) */
#define DEFAULT_HEAP_MIN 0x10000

#define THREAD_STACK_SIZE (PRESET_PAGESIZE * 16) /* 64KB user stack */
#define ALT_STACK_SIZE    (PRESET_PAGESIZE * 16) /* 64KB signal stack */

#endif /* PAL_LINUX_DEFS_H */
