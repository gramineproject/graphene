#include "sgx_arch.h"
#include "asm-offsets.h"

	.extern ecall_table
	.extern enclave_ecall_pal_main

	.global enclave_entry
	.type enclave_entry, @function

enclave_entry:
	# On EENTER/ERESUME, RAX is the current SSA, RBX is the address of TCS,
	# RCX is the address of AEP. Other registers are not trusted.

	# current SSA is in RAX (Trusted)
	cmpq $0, %rax
	jne .Lhandle_resume

	# TCS is in RBX (Trusted)

	# AEP address in RCX (Trusted)
	movq %rcx, %gs:SGX_AEP

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
	movq %gs:SGX_EXIT_TARGET, %rcx
	cmpq $0, %rcx
	jne .Lreturn_from_ocall

	# PAL convention:
	# RDI - index in ecall_table
	# RSI - prointer to ecall arguments
	# RDX - exit target
	# RCX (former RSP) - The unstrusted stack
	# R8  - enclave base

	# calculate enclave base = RBX (trusted) - %gs:SGX_TCS_OFFSET
	subq %gs:SGX_TCS_OFFSET, %rbx
	movq %rbx, %r8

	# push untructed stack address to RCX
	movq %rsp, %rcx

	# switch to enclve stack: enclave base + %gs:SGX_INITIAL_STACK_OFFSET
	addq %gs:SGX_INITIAL_STACK_OFFSET, %rbx
	movq %rbx, %rsp

	# clear the rest of register states
	xorq %rax, %rax
	xorq %rbx, %rbx
	xorq %r9,  %r9
	xorq %r10, %r10
	xorq %r11, %r11
	xorq %r12, %r12
	xorq %r13, %r13
	xorq %r14, %r14
	xorq %r15, %r15

	# register states need to be carefully checked, so we move the handling
	# to handle_ecall() in enclave_ecalls.c
	callq handle_ecall

	# never return to this point (should die)
	xorq %rdi, %rdi
	xorq %rsi, %rsi
	jmp .Leexit

.Lhandle_resume:
	# PAL convention:
	# RDI - external event

	# get some information from GPR
	movq %gs:SGX_GPR, %rbx

	movq %rdi, %rsi
	xorq %rdi, %rdi
	movl SGX_GPR_EXITINFO(%rbx), %edi
	testl $0x80000000, %edi
	jnz .Lhandle_exception

	movl %esi, %edi
	# use external event - only the first 8 bits count
	andl $0xff, %edi
	cmpl $0, %edi
	jne .Lhandle_exception

	# clear the registers
	xorq %rdi, %rdi
	xorq %rsi, %rsi

	# exit address in RDX, mov it to RBX
	movq %rdx, %rbx
	movq $EEXIT, %rax
	ENCLU

	## There is a race between host signal delivery and restoring %rsp
	## in this entry code. We must be careful to setup %rsp.
	##
	## Race scenario
	## 1. We are inside the enclave but %rsp isn't restored yet to something
	##    inside the enclave. That's for example the case when returning from
	##    an ocall.
	## 2. The enclave gets interrupted. The not restored %rsp is pushed into
	##    SGX_GPR_RSP by the processor.
	## 3. The host enters the enclave again and indicated that there's a new
	##    signal.
	## 4. The code after .Lhandle_exception pushes stuff on the untrusted
	##    stack (because SGX_GPR_RSP points there) and then diverts %rip to
	##    execute the event handler after ERESUME (which will use the untrusted
	##    stack).
	##
	## The solution is to have a "fallback" value stored in SGX_STACK.
	## If SGX_STACK == 0, then %rsp was correctly restored during
	## Lreturn_from_ocall and the interrupt happened after that, so the CPU
	## pushed the restored %rsp into SGX_GPR_RSP, thus we can safely use
	## SGX_GPR_RSP.
	## However, if SGX_STACK != 0, this indicates that the interrupt came
	## before xchgq %rsp, %gs:SGX_STACK and %rsp was not yet restored,
	## so the CPU pushed some untrusted %rsp into SGX_GPR_RSP. Thus, we
	## cannot trust value in SGX_GPR_RSP and should fall-back to using
	## SGX_STACK (which was updated with the last known good in-enclave
	## %rsp during Leexit).
.Lhandle_exception:
	movq SGX_GPR_RSP(%rbx), %rsi
	movq %gs:SGX_STACK, %rax
	cmpq $0, %rax
	je 1f
	movq %rax, %rsi
1:
	subq $SGX_CONTEXT_SIZE, %rsi

	# we have exitinfo in RDI, swap with the one on GPR
	# and dump into the context
	xchgq %rdi, SGX_GPR_RDI(%rbx)
	movq %rdi, SGX_CONTEXT_RDI(%rsi)

	# dump the rest of context
	movq SGX_GPR_RAX(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RAX(%rsi)
	movq SGX_GPR_RCX(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RCX(%rsi)
	movq SGX_GPR_RDX(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RDX(%rsi)
	movq SGX_GPR_RBX(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RBX(%rsi)
	movq SGX_GPR_RSP(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RSP(%rsi)
	movq SGX_GPR_RBP(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RBP(%rsi)
	movq SGX_GPR_RSI(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RSI(%rsi)
	/* rdi is saved above */
	movq SGX_GPR_R8(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R8(%rsi)
	movq SGX_GPR_R9(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R9(%rsi)
	movq SGX_GPR_R10(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R10(%rsi)
	movq SGX_GPR_R11(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R11(%rsi)
	movq SGX_GPR_R12(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R12(%rsi)
	movq SGX_GPR_R13(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R13(%rsi)
	movq SGX_GPR_R14(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R14(%rsi)
	movq SGX_GPR_R15(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_R15(%rsi)
	movq SGX_GPR_RFLAGS(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RFLAGS(%rsi)
	movq SGX_GPR_RIP(%rbx), %rdi
	movq %rdi, SGX_CONTEXT_RIP(%rsi)

	movq %rsi, SGX_GPR_RSP(%rbx)
	movq %rsi, SGX_GPR_RSI(%rbx)

	# new RIP is the exception handler
	leaq _DkExceptionHandler(%rip), %rdi
	movq %rdi, SGX_GPR_RIP(%rbx)

	# clear the registers
	xorq %rdi, %rdi
	xorq %rsi, %rsi

	# exit address in RDX, mov it to RBX
	movq %rdx, %rbx
	movq $EEXIT, %rax
	ENCLU


	.global sgx_ocall
	.type sgx_ocall, @function

sgx_ocall:
	pushq %rbp
	movq %rsp, %rbp

	movq 8(%rbp), %rax
	pushq %rax	# previous RIP
	pushfq
	pushq %r15
	pushq %r14
	pushq %r13
	pushq %r12
	pushq %r11
	pushq %r10
	pushq %r9
	pushq %r8
	pushq %rdi
	pushq %rsi
	movq (%rbp), %rax
	pushq %rax	# previous RBP
	leaq 16(%rbp), %rax
	pushq %rax	# previous RSP
	pushq %rbx
	pushq %rdx
	pushq %rcx
	# no RAX

	movq %rsp, %rbp
	subq $XSAVE_SIZE,  %rsp
	andq $XSAVE_ALIGN, %rsp
	fxsave (%rsp)

	pushq %rbp

	jmp .Leexit

.Leexit:
	xorq %rdx, %rdx
	xorq %r8, %r8
	xorq %r9, %r9
	xorq %r10, %r10
	xorq %r11, %r11
	xorq %r12, %r12
	xorq %r13, %r13
	xorq %r14, %r14
	xorq %r15, %r15
	xorq %rbp, %rbp

	movq %rsp, %gs:SGX_STACK
	movq %gs:SGX_USTACK, %rsp
	andq $STACK_ALIGN, %rsp

	movq %gs:SGX_EXIT_TARGET, %rbx
	movq %gs:SGX_AEP, %rcx
	movq $EEXIT, %rax
	ENCLU

.Lreturn_from_ocall:
	# PAL convention:
	# RDI - return value
	# RSI - external event (if there is any)

	movq %rdi, %rax

	# restore FSBASE if necessary
	movq %gs:SGX_FSBASE, %rbx
	cmpq $0, %rbx
	je .Lno_fsbase
	.byte 0xf3, 0x48, 0x0f, 0xae, 0xd3 /* WRFSBASE %RBX */
.Lno_fsbase:

	# restore the stack
	movq $0, %rsp
	xchgq %rsp, %gs:SGX_STACK

	popq %rbp
	fxrstor (%rsp)
	movq %rbp, %rsp

	cmpq $0, %rsi
	je .Lno_external_event
	pushq %rax
	movq %rsi, %rdi
	movq %rsp, %rsi
	callq _DkHandleExternalEvent
	popq %rax
.Lno_external_event:

	popq %rcx
	popq %rdx
	popq %rbx
	addq $16, %rsp	# skip RSP and RBP
	popq %rsi
	popq %rdi
	popq %r8
	popq %r9
	popq %r10
	popq %r11
	popq %r12
	popq %r13
	popq %r14
	popq %r15
	popfq
	addq $8, %rsp	# skip RIP
	popq %rbp
	retq

/*
 * sgx_report:
 * Generate SGX hardware signed report.
 */
	.global sgx_report
	.type sgx_report, @function

sgx_report:
	.cfi_startproc

	pushq %rbx
	pushq %rcx
	movq %rdi, %rbx
	movq %rsi, %rcx
	movq $EREPORT, %rax
	ENCLU
	popq %rcx
	popq %rbx
	retq

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

	pushq %rbx
	pushq %rcx
	movq %rdi, %rbx
	movq %rsi, %rcx
	movq $EGETKEY, %rax
	ENCLU
	popq %rcx
	popq %rbx
	retq

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
	retq

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
	retq

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
	retq

	.cfi_endproc
	.size wrfsbase, .-wrfsbase
