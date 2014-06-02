#include <syscalldb.h>

#ifdef WEAK_SYSCALLDB
.weak syscalldb
#else
.global syscalldb
#endif
.type syscalldb,@function

syscalldb:
	.cfi_startproc
	syscall
	ret
.cfi_endproc
.size syscalldb,.-syscalldb
