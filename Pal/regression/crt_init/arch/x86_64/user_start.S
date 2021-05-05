/* This is the canonical entry point, usually the first thing in the text
   segment.  The SVR4/i386 ABI (pages 3-31, 3-32) says that when the entry
   point runs, most registers' values are unspecified, except for:

   %rdx		Contains a function pointer to be registered with `atexit'.
		This is how the dynamic linker arranges to have DT_FINI
		functions called for shared libraries that have been loaded
		before this code runs.

   %rsp		The stack contains the arguments and environment:
		0(%rsp)				argc
		LP_SIZE(%rsp)			argv[0]
		...
		(LP_SIZE*argc)(%rsp)		NULL
		(LP_SIZE*(argc+1))(%rsp)	envp[0]
		...
						NULL
*/

	.text
	.globl _start
	.type _start,@function
_start:
	popq %rdi		/* Pop the argument count.  */

	/* argv starts just at the current stack top.  */
	mov %rsp, %rsi

	/* Align the stack to a 16 byte boundary to follow the ABI.  */
	and  $~0xF, %rsp

	/* push the exit address on the stack and preserve %rsp alignment */
	pushq %rdx
	/* Clear the frame pointer.  The ABI suggests this be done, to mark
	   the outermost frame obviously.  */
	pushq %rbp		/* %rbp is callee save. */
	xorl %ebp, %ebp


	/* find the environs */
	lea (%rsi,%rdi,8), %rdx
	add $8, %rdx

#ifdef SHARED
	call main@PLT
#else
	call main
#endif

	/* return to the exit function */
	popq %rbp
	retq
