#include <syscalldb.h>

.weak syscalldb
.type syscalldb,@function

syscalldb:
	.cfi_startproc
	syscall
	retq
	.cfi_endproc
	.size syscalldb,.-syscalldb
