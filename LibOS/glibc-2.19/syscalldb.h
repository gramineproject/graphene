#ifndef _SYSCALLDB_H_
#define _SYSCALLDB_H_

#ifdef __ASSEMBLER__
.weak syscalldb
.type syscalldb, @function

# define SYSCALLDB				\
    pushq %rbx;					\
    movq syscalldb@GOTPCREL(%rip), %rbx;	\
    call *%rbx;					\
    popq %rbx;


#else /* !__ASSEMBLER__ */
asm (
".weak syscalldb\r\n"
".type syscalldb, @function\r\n");

#define SYSCALLDB							      \
	"subq $128, %%rsp\n\t"						      \
	"movq syscalldb@GOTPCREL(%%rip), %%rcx\n\t"			      \
	"callq *%%rcx\n\t"						      \
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
