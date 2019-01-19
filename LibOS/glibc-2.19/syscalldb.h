#ifndef _SYSCALLDB_H_
#define _SYSCALLDB_H_

#ifdef __ASSEMBLER__
.weak syscalldb
.type syscalldb, @function

# if defined(PSEUDO) && defined(SYSCALL_NAME) && defined(SYSCALL_SYMBOL)
#  define SYSCALLDB                 \
    subq $128, %rsp;                \
    call syscalldb@GOTPCREL(%rip);  \
    addq $128, %rsp
# else
# define SYSCALLDB                  \
    callq *syscalldb@GOTPCREL(%rip)
# endif

#else /* !__ASSEMBLER__ */
asm (
".weak syscalldb\r\n"
".type syscalldb, @function\r\n");

#define SYSCALLDB                               \
    "subq $128, %%rsp\n\t"                      \
    "callq *syscalldb@GOTPCREL(%%rip)\n\t"      \
    "addq $128, %%rsp\n\t"

#define SYSCALLDB_ASM                           \
    "callq *syscalldb@GOTPCREL(%rip)\n\t"

long int glibc_option (const char * opt);

asm (
".weak glibc_option\r\n"
".type glibc_option, @function\r\n");

#endif /* Assembler */

#endif /* _SYSCALLDB_H */
