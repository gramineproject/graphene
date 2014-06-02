#ifndef _SYSCALLDB_H_
#define _SYSCALLDB_H_

#define WEAK_SYSCALLDB 1

#ifdef __ASSEMBLER__
# ifdef WEAK_SYSCALLDB
.weak syscalldb
# else
.global syscalldb
# endif
.type syscalldb, @function

#else /* !__ASSEMBLER__ */
asm (
# ifdef WEAK_SYSCALLDB
".weak syscalldb\r\n"
# else
".global syscalldb\r\n"
# endif
".type syscalldb, @function\r\n");

#endif /* Assembler */

#endif /* _SYSCALLDB_H */
