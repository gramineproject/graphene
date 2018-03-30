#ifndef _SYSCALLDB_H_
#define _SYSCALLDB_H_

#include <tcb-offsets.h>

#define XSTRINGIFY(x) STRINGIFY(x)
#define STRINGIFY(x) #x

#ifdef __ASSEMBLER__
.weak syscalldb
.type syscalldb, @function

# define SYSCALLDB				\
    pushq %rbx;					\
    movq %fs:SYSCALLDB_OFFSET, %rbx;		\
    call *%rbx;					\
    popq %rbx;


#else /* !__ASSEMBLER__ */
asm (
".weak syscalldb\r\n"
".type syscalldb, @function\r\n");

#define SYSCALLDB							      \
	"subq $128, %%rsp\n\t"						      \
	"pushq %%rbx\n\t"						      \
	"movq %%fs:" XSTRINGIFY(SYSCALLDB_OFFSET) ", %%rbx\n\t"		      \
	"callq *%%rbx\n\t"						      \
	"popq %%rbx\n\t"						      \
	"addq $128, %%rsp\n\t"

#define SYSCALLDB_ASM							      \
	"movq %fs:" XSTRINGIFY(SYSCALLDB_OFFSET) ", %rbx\n\t"		      \
	"callq *%rbx\n\t"

long int glibc_option (const char * opt);

asm (
".weak glibc_option\r\n"
".type glibc_option, @function\r\n");

#endif /* Assembler */

#endif /* _SYSCALLDB_H */
