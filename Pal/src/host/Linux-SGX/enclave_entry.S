#include "sgx_arch.h"
#include "sgx_tls.h"

	.extern ecall_table
	.extern enclave_ecall_pal_main

	.global enclave_entry
	.type enclave_entry, @function

enclave_entry:
	# current SSA is in RAX
	cmp $0, %rax
	jne .Lhandle_resume

	# AEP address in RCX
	mov %rcx, %gs:SGX_AEP

	cmp $RETURN_FROM_OCALL, %rdi
	je .Lreturn_from_ocall

	# move stack address to both urts_orig_stack and urts_stack
	mov %rsp, %gs:SGX_URTS_INITIAL_STACK
	mov %rsp, %gs:SGX_URTS_STACK

	# switch the stack specified in TLS
	mov %gs:SGX_INITIAL_STACK, %rsp

	# exit target in RDX
	mov %rdx, %gs:SGX_EXIT_TARGET

	# debug counter register in R8
	mov %r8, %gs:SGX_DEBUG_REGISTER

	cmp $0, %rdi
	jne .Lhandle_ecall

	lea enclave_ecall_pal_main(%rip), %rbx
	jmp .Lcall_ecall

.Lhandle_ecall:
	lea ecall_table(%rip), %rbx
	mov (%rbx,%rdi,8), %rbx

.Lcall_ecall:
	mov %rsi, %rdi
	call *%rbx

	# never return to this point (should die)
	xor %rdi, %rdi
	xor %rsi, %rsi
	jmp .Leexit

.Lhandle_resume:
	# get some information from GPR
	mov %gs:SGX_GPR, %rbx

	# check if there is external event in R9
	cmp $0, %r9
	je .Lno_external_event_in_resume
	mov %r9, %rdi
	jmp .Lhandle_exception

.Lno_external_event_in_resume:
	xor %rdi, %rdi
	mov SGX_GPR_EXITINFO(%rbx), %edi
	test $0x80000000, %edi
	jnz .Lhandle_exception

#if SGX_HAS_FSGSBASE == 0
	mov %gs:SGX_FSBASE, %rdi
	cmp $0, %rdi
	je .Ljust_resume

	mov SGX_GPR_RSP(%rbx), %rsi
	sub $16, %rsi
	mov %rsi, SGX_GPR_RSP(%rbx)

	# try to push rip and fsbase onto the stack
	mov %rdi, (%rsi)
	mov SGX_GPR_RIP(%rbx), %rdi
	mov %rdi, 8(%rsi)

	# new RIP is the resume point
	lea .Lafter_resume(%rip), %rdi
	mov %rdi, SGX_GPR_RIP(%rbx)

.Ljust_resume:
#endif
	# clear the registers
	xor %rdi, %rdi
	xor %rsi, %rsi

	# exit address in RDX, mov it to RBX
	mov %rdx, %rbx
	mov $EEXIT, %rax
	ENCLU

#if SGX_HAS_FSGSBASE == 0
.Lafter_resume:
	mov %rax, -8(%rsp)
	pop %rax
	.byte 0xf3, 0x48, 0x0f, 0xae, 0xd0 /* WRFSBASE %RAX */
	mov -16(%rsp), %rax
	ret
#endif

.Lhandle_exception:
	mov SGX_GPR_RSP(%rbx), %rsi
	sub $0x90, %rsi

	# we have exitinfo in RDI, swap with the one on GPR
	# and dump into the context
	xchg %rdi, SGX_GPR_RDI(%rbx)
	mov %rdi, 0x38(%rsi)

	# dump the rest of context
	mov SGX_GPR_RAX(%rbx), %rdi
	mov %rdi, 0x00(%rsi)
	mov SGX_GPR_RCX(%rbx), %rdi
	mov %rdi, 0x08(%rsi)
	mov SGX_GPR_RDX(%rbx), %rdi
	mov %rdi, 0x10(%rsi)
	mov SGX_GPR_RBX(%rbx), %rdi
	mov %rdi, 0x18(%rsi)
	mov SGX_GPR_RSP(%rbx), %rdi
	mov %rdi, 0x20(%rsi)
	mov SGX_GPR_RBP(%rbx), %rdi
	mov %rdi, 0x28(%rsi)
	mov SGX_GPR_RSI(%rbx), %rdi
	mov %rdi, 0x30(%rsi)
	mov SGX_GPR_R8(%rbx), %rdi
	mov %rdi, 0x40(%rsi)
	mov SGX_GPR_R9(%rbx), %rdi
	mov %rdi, 0x48(%rsi)
	mov SGX_GPR_R10(%rbx), %rdi
	mov %rdi, 0x50(%rsi)
	mov SGX_GPR_R11(%rbx), %rdi
	mov %rdi, 0x58(%rsi)
	mov SGX_GPR_R12(%rbx), %rdi
	mov %rdi, 0x60(%rsi)
	mov SGX_GPR_R13(%rbx), %rdi
	mov %rdi, 0x68(%rsi)
	mov SGX_GPR_R14(%rbx), %rdi
	mov %rdi, 0x70(%rsi)
	mov SGX_GPR_R15(%rbx), %rdi
	mov %rdi, 0x78(%rsi)
	mov SGX_GPR_RFLAGS(%rbx), %rdi
	mov %rdi, 0x80(%rsi)
	mov SGX_GPR_RIP(%rbx), %rdi
	mov %rdi, 0x88(%rsi)

	mov %rsi, SGX_GPR_RSP(%rbx)
	mov %rsi, SGX_GPR_RSI(%rbx)

	# new RIP is the exception handler
	lea _DkExceptionHandler(%rip), %rdi
	mov %rdi, SGX_GPR_RIP(%rbx)

	# clear the registers
	xor %rdi, %rdi
	xor %rsi, %rsi

	# exit address in RDX, mov it to RBX
	mov %rdx, %rbx
	mov $EEXIT, %rax
	ENCLU


	.global sgx_ocall
	.type sgx_ocall, @function

sgx_ocall:
	push %rbp
	mov %rsp, %rbp

	sub $XSAVE_SIZE, %rsp
	and $XSAVE_ALIGN, %rsp

	fxsave (%rsp)

	push %rbx
	push %rdx
	push %rcx
	push %rsi
	push %rdi
	push %r8
	push %r9
	push %r10
	push %r11
	push %r12
	push %r13
	push %r14
	push %r15
	push %rbp
	pushfq

	mov %rsp, %gs:SGX_LAST_STACK

	jmp .Leexit

.Lexception_handler:
	
.Leexit:
	xor %rdx, %rdx
	xor %r8, %r8
	xor %r9, %r9
	xor %r10, %r10
	xor %r11, %r11
	xor %r12, %r12
	xor %r13, %r13
	xor %r14, %r14
	xor %r15, %r15
	xor %rbp, %rbp

	mov %gs:SGX_URTS_STACK, %rsp
	and $STACK_ALIGN, %rsp

	mov %gs:SGX_EXIT_TARGET, %rbx
	mov %gs:SGX_AEP, %rcx
	mov $EEXIT, %rax
	ENCLU

.Lreturn_from_ocall:
	# save ocall return value
	mov %rsi, %gs:SGX_LAST_OCALL_RESULT

	# check if there is external event in R9
	cmp $0, %r9
	je .Lno_external_event
	mov %r9, %gs:SGX_EXTERNAL_EVENT

.Lno_external_event:

	# restore the stack
	mov %gs:SGX_LAST_STACK, %rsp

	popfq
	pop %rbp
	pop %r15
	pop %r14
	pop %r13
	pop %r12
	pop %r11
	pop %r10
	pop %r9
	pop %r8
	pop %rdi
	pop %rsi
	pop %rcx
	pop %rdx
	pop %rbx

	fxrstor (%rsp)

	mov %gs:SGX_FSBASE, %rax
	cmp $0, %rax
	je .Lno_fsbase
	.byte 0xf3, 0x48, 0x0f, 0xae, 0xd0 /* WRFSBASE %RAX */
.Lno_fsbase:

	mov %gs:SGX_LAST_OCALL_RESULT, %rax
	leave
	ret

/*
 * sgx_report:
 * Generate SGX hardware signed report.
 */
	.global sgx_report
	.type sgx_report, @function

sgx_report:
	.cfi_startproc

	push %rbx
	push %rcx
	mov %rdi, %rbx
	mov %rsi, %rcx
	mov $EREPORT, %rax
	ENCLU
	pop %rcx
	pop %rbx
	ret

	.cfi_endproc
	.size sgx_report, .-sgx_report

/*
 * sgx_getkey:
 * Retreive SGX hardware enclave cryptography key.
 */
	.global sgx_getkey
	.type sgx_getkey, @function

sgx_getkey:
	.cfi_startproc

	push %rbx
	push %rcx
	mov %rdi, %rbx
	mov %rsi, %rcx
	mov $EGETKEY, %rax
	ENCLU
	pop %rcx
	pop %rbx
	ret

	.cfi_endproc
	.size sgx_getkey, .-sgx_getkey

/*
 * rdrand:
 * Get hardware generated random value.
 */
	.global rdrand
	.type rdrand, @function

rdrand:
	.cfi_startproc
.Lretry_rdrand:
	.byte 0x0f, 0xc7, 0xf0 /* RDRAND %EAX */
	jnc .Lretry_rdrand
	ret

	.cfi_endproc
	.size rdrand, .-rdrand

/*
 * rdfsbase:
 * read FS register (allowed in enclaves).
 */
	.global rdfsbase
	.type rdfsbase, @function

rdfsbase:
	.cfi_startproc

	.byte 0xf3, 0x48, 0x0f, 0xae, 0xc0 /* RDFSBASE %RAX */
	ret

	.cfi_endproc
	.size rdfsbase, .-rdfsbase

/*
 * wrfsbase:
 * modify FS register (allowed in enclaves).
 */
	.global wrfsbase
	.type wrfsbase, @function

wrfsbase:
	.cfi_startproc

	.byte 0xf3, 0x48, 0x0f, 0xae, 0xd7 /* WRFSBASE %RDI */
	ret

	.cfi_endproc
	.size wrfsbase, .-wrfsbase
