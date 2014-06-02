/* -*- mode:c; c-basic-offset:4; tab-width:4; indent-tabs-mode:t; mode:auto-fill; fill-column:78; -*- */ 
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */


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

/* Clear the frame pointer.  The ABI suggests this be done, to mark
   the outermost frame obviously.  */
    xorq %rbp, %rbp
    movq %rsp, %rbp

/* Extract the arguments as encoded on the stack and set up
   the arguments for shim_init (int, void *, void **),
   The arguments are passed via registers and on the stack:
   argc:         %rdi
   argv:         %rsi
   stack:        %rdx
*/

    /* Align the stack to a 16 byte boundary to follow the ABI.  */
    andq  $~15, %rsp

    movq %rdi, %rcx         /* Possibly the stack has to be switched */
    movq 0(%rbp), %rdi      /* Pop the argument count.  */
    leaq 8(%rbp), %rsi      /* argv starts just at the current stack top.  */

/* Provide the highest stack address to the user code (for stacks
   which grow downwards).  */

    pushq %rbp
    movq %rsp, %rdx

    movq shim_init@GOTPCREL(%rip), %r11
    call *%r11

    popq %rbp
    leaveq
    retq
    .cfi_endproc
