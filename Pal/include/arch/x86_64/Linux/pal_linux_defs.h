#ifndef PAL_LINUX_DEFS_H
#define PAL_LINUX_DEFS_H

/* Macro to call pal_linux_main */
#define CALL_PAL_LINUX_MAIN(PAL_START) \
__asm__ (                              \
    ".global "#PAL_START"\n"            \
    "   .type "#PAL_START",@function\n" \
    #PAL_START":\n"                     \
    "   movq %rsp, %rdi\n" /* 1st arg for pal_linux_main: initial RSP */ \
    "   movq %rdx, %rsi\n" /* 2nd arg: fini callback */                  \
    "   xorq %rbp, %rbp\n" /* mark the last stack frame with RBP == 0 (for debuggers) */ \
    "   andq $~15, %rsp\n"             \
    "   call pal_linux_main\n"         \
)

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
