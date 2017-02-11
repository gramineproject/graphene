#include "sgx_arch.h"
#include "sgx_tls.h"

	.extern ecall_table
	.extern enclave_ecall_pal_main

	.global enclave_entry
	.type enclave_entry, @function

enclave_entry:
	# On EENTER/ERESUME, RAX is the current SSA, RBX is the address of TCS,
	# RCX is the address of AEP. Other registers are not trusted.

	# current SSA is in RAX (Trusted)
	cmp $0, %rax
	jne .Lhandle_resume

	# TCS is in RBX (Trusted)

	# AEP address in RCX (Trusted)
	mov %rcx, %gs:SGX_AEP

	# The following code is hardened to defend attacks from untrusted host.
	# Any states given by the host instead of the ISA must be assumed
	# potentially malicious.
	#
	# For instance, Jo Van Bulck contributed a detailed vulnerability report
	# in https://github.com/oscarlab/graphene/issues/28. (Fixed)
	# Brief description of the vulnerabilities:
	# The previous implementation does not check the index of entry
	# functions (RDI at enclave entry) given by the untrusted PAL.
	# An attacker can cause overflow/underflow to jump to random
	# locaion in enclaves. Moreover, we used a specific index
	# (RETURN_FROM_OCALL) to tell if the control flow is returned
	# from a OCALL in the untrusted PAL. Attackers can manipulate RDI
	# to deceive the trusted PAL.

	# A safe design: check if %gs:SGX_EXIT_TARGET is ever assigned
	mov %gs:SGX_EXIT_TARGET, %rcx
	cmp $0, %rcx
	jne .Lreturn_from_ocall

	# PAL convention:
	# RDI - index in ecall_table
	# RSI - prointer to ecall arguments
	# RDX - exit target
	# RCX (former RSP) - The unstrusted stack
	# R8  - enclave base

	# calculate enclave base = RBX (trusted) - %gs:SGX_TCS_OFFSET
	sub %gs:SGX_TCS_OFFSET, %rbx
	mov %rbx, %r8

	# push untructed stack address to RCX
	mov %rsp, %rcx

	# switch to enclve stack: enclave base + %gs:SGX_INITIAL_STACK_OFFSET
	add %gs:SGX_INITIAL_STACK_OFFSET, %rbx
	mov %rbx, %rsp

	# clear the rest of register states
	xor %rax, %rax
	xor %rbx, %rbx
	xor %r9,  %r9
	xor %r10, %r10
	xor %r11, %r11
	xor %r12, %r12
	xor %r13, %r13
	xor %r14, %r14
	xor %r15, %r15

	# register states need to be carefully checked, so we move the handling
	# to handle_ecall() in enclave_ecalls.c
	call handle_ecall

	# never return to this point (should die)
	xor %rdi, %rdi
	xor %rsi, %rsi
	jmp .Leexit

.Lhandle_resume:
	# PAL convention:
	# RDI - external event

	# get some information from GPR
	mov %gs:SGX_GPR, %rbx

	mov %rdi, %rsi
	xor %rdi, %rdi
	mov SGX_GPR_EXITINFO(%rbx), %edi
	test $0x80000000, %edi
	jnz .Lhandle_exception

	mov %esi, %edi
	# use external event - only the first 8 bits count
	and $0xff, %edi
	cmp $0, %edi
	jne .Lhandle_exception

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
	mov %rbx, -8(%rsp)
	pop %rbx
	.byte 0xf3, 0x48, 0x0f, 0xae, 0xd3 /* WRFSBASE %RBX */
	mov -16(%rsp), %rbx
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

	mov 8(%rbp), %rax
	push %rax	# previous RIP
	pushfq
	push %r15
	push %r14
	push %r13
	push %r12
	push %r11
	push %r10
	push %r9
	push %r8
	push %rdi
	push %rsi
	mov (%rbp), %rax
	push %rax	# previous RBP
	lea 16(%rbp), %rax
	push %rax	# previous RSP
	push %rbx
	push %rdx
	push %rcx
	# no RAX

	mov %rsp, %rbp
	sub $XSAVE_SIZE,  %rsp
	and $XSAVE_ALIGN, %rsp
	fxsave (%rsp)

	push %rbp
	mov %rsp, %gs:SGX_STACK

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

	mov %gs:SGX_USTACK, %rsp
	and $STACK_ALIGN, %rsp

	mov %gs:SGX_EXIT_TARGET, %rbx
	mov %gs:SGX_AEP, %rcx
	mov $EEXIT, %rax
	ENCLU

.Lreturn_from_ocall:
	# PAL convention:
	# RDI - return value
	# RSI - external event (if there is any)

	mov %rdi, %rax

	# restore FSBASE if necessary
	mov %gs:SGX_FSBASE, %rbx
	cmp $0, %rbx
	je .Lno_fsbase
	.byte 0xf3, 0x48, 0x0f, 0xae, 0xd3 /* WRFSBASE %RBX */
.Lno_fsbase:

	# restore the stack
	mov %gs:SGX_STACK, %rsp

	pop %rbp
	fxrstor (%rsp)
	mov %rbp, %rsp

	cmp $0, %rsi
	je .Lno_external_event
	push %rax
	mov %rsi, %rdi
	mov %rsp, %rsi
	call _DkHandleExternelEvent
	pop %rax
.Lno_external_event:

	pop %rcx
	pop %rdx
	pop %rbx
	add $16, %rsp	# skip RSP and RBP
	pop %rsi
	pop %rdi
	pop %r8
	pop %r9
	pop %r10
	pop %r11
	pop %r12
	pop %r13
	pop %r14
	pop %r15
	popfq
	add $8, %rsp	# skip RIP
	pop %rbp
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
