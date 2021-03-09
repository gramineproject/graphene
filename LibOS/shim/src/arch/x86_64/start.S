/* This is the canonical entry point, usually the first thing in the text
   segment.  The SVR4/i386 ABI (pages 3-31, 3-32) says that when the entry
   point runs, most registers' values are unspecified, except for:

   %rdx        Contains a function pointer to be registered with `atexit'.
   This is how the dynamic linker arranges to have DT_FINI
   functions called for shared libraries that have been loaded
   before this code runs.

   %rsp        The stack contains the arguments and environment:
   0(%rsp)            argc
   8(%rsp)            argv[0]
   ...
   (8*argc)(%rsp)        NULL
   (8*(argc+1))(%rsp)    envp[0]
   ...
   NULL
 */
    .text
    .globl shim_start
    .type shim_start,@function

shim_start:
    .cfi_startproc

    # Clear the frame pointer.  The ABI suggests this be done, to mark
    # the outermost frame obviously.
    xorq %rbp, %rbp

    # Arguments for shim_init:
    movq 0(%rsp), %rdi  # argc
    leaq 8(%rsp), %rsi  # args

    # Required by System V AMD64 ABI.
    andq  $~0xF, %rsp

    callq *shim_init@GOTPCREL(%rip)

    # TODO: Call initial %rdi to execute atexit callbacks.
    .cfi_endproc
