#ifndef _SYSCALLDB_H_
#define _SYSCALLDB_H_

#ifdef __ASSEMBLER__
.weak syscalldb
.type syscalldb, @function

#else /* !__ASSEMBLER__ */
asm (
".weak syscalldb\r\n"
".type syscalldb, @function\r\n");

long int glibc_option (const char * opt);

asm (
".weak glibc_option\r\n"
".type glibc_option, @function\r\n");

#endif /* Assembler */

#endif /* _SYSCALLDB_H */
