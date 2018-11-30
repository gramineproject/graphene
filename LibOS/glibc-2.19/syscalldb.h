#ifndef _SYSCALLDB_H_
#define _SYSCALLDB_H_

#ifdef __ASSEMBLER__
.weak syscalldb
.type syscalldb, @function

# if defined(PSEUDO) && defined(SYSCALL_NAME) && defined(SYSCALL_SYMBOL)
#  define SYSCALLDB				\
    subq $128, %rsp;            \
    movq syscalldb@GOTPCREL(%rip), %rcx;	\
    call *%rcx;					\
    addq $128, %rsp
# else
#  define SYSCALLDB				\
    movq syscalldb@GOTPCREL(%rip), %rcx;	\
    call *%rcx
# endif

#else /* !__ASSEMBLER__ */
asm (
".weak syscalldb\r\n"
".type syscalldb, @function\r\n");

#define SYSCALLDB							      \
	"subq $128, %%rsp\n\t"						      \
	"pushq %%rbx\n\t"						      \
	"movq syscalldb@GOTPCREL(%%rip), %%rbx\n\t"			      \
	"callq *%%rbx\n\t"						      \
	"popq %%rbx\n\t"						      \
	"addq $128, %%rsp\n\t"

#define SYSCALLDB_ASM							      \
	"movq syscalldb@GOTPCREL(%rip), %rbx\n\t"			      \
	"callq *%rbx\n\t"

long int glibc_option (const char * opt);

asm (
".weak glibc_option\r\n"
".type glibc_option, @function\r\n");

#endif /* Assembler */

#endif /* _SYSCALLDB_H */
