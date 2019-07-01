#include "pal_linux_defs.h"
#include "sgx_arch.h"

#include "asm-offsets.h"

	.extern tcs_base

	.global sgx_ecall
	.type sgx_ecall, @function

sgx_ecall:
	# put entry address in RDX
	leaq sgx_entry(%rip), %rdx

	# other arguments: RDI - code, RSI - ms

.Ldo_ecall:
	# RBX has to be the TCS of the thread
	movq current_tcs@gottpoff(%rip), %rbx
	movq %fs:(%rbx), %rbx

	# RCX has to be the AEP (Asynchronous Exit Pointer)
	leaq async_exit_pointer(%rip), %rcx

	movq $EENTER, %rax
	ENCLU

	.global async_exit_pointer
	.type async_exit_pointer, @function

async_exit_pointer:
	ENCLU

	.global sgx_raise
	.type sgx_raise, @function

sgx_raise:
	leaq .Lafter_resume(%rip), %rdx
	jmp .Ldo_ecall

.Lafter_resume:
	retq

sgx_entry:
	# arguments: RDI - code, RSI - ms

	.cfi_startproc
	leaq ocall_table(%rip), %rbx
	movq (%rbx,%rdi,8), %rbx
	movq %rsi, %rdi

	pushq %rbp
	.cfi_adjust_cfa_offset 8
	movq %rsp, %rbp
	.cfi_offset %rbp, -16
	.cfi_def_cfa_register %rbp
	andq $~0xF, %rsp  # Required by System V AMD64 ABI.

	callq *%rbx

	movq %rbp, %rsp
	popq %rbp
	.cfi_def_cfa %rsp, 8

	movq %rax, %rdi
	# Not interrupted
	xorq %rsi, %rsi

	.global sgx_entry_return
	.type sgx_entry_return, @function

sgx_entry_return:
	# return to enclave, arguments:
	# RDI - return value
	# RSI - external event
	jmp .Ldo_ecall
	.cfi_endproc

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
