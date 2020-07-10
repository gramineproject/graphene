#include "pal_linux_defs.h"
#include "sgx_arch.h"

#include "asm-offsets.h"

	.extern tcs_base

	.global sgx_ecall
	.type sgx_ecall, @function

sgx_ecall:
	# put entry address in RDX
	leaq .Lsgx_entry(%rip), %rdx

	# other arguments: RDI - code, RSI - ms

.Ldo_ecall_callee_save:
	pushq %rbx
	pushq %rbp
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15

.Ldo_ecall:
	# increment per-thread EENTER counter for stats
	lock incq %gs:PAL_TCB_URTS_EENTER_CNT

	# RBX has to be the TCS of the thread
	movq %gs:PAL_TCB_URTS_TCS, %rbx

	# RCX has to be the AEP (Asynchronous Exit Pointer)
	leaq async_exit_pointer(%rip), %rcx

	movq $EENTER, %rax
	ENCLU

	# currently only ECALL_THREAD_RESET returns
.Lafter_resume:
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbp
	popq %rbx
	retq

	.global async_exit_pointer
	.type async_exit_pointer, @function

async_exit_pointer:
	# increment per-thread AEX counter for stats
	lock incq %gs:PAL_TCB_URTS_AEX_CNT
	# fall-through to ERESUME

	.global eresume_pointer
	.type eresume_pointer, @function

eresume_pointer:
	ENCLU   # perform ERESUME

	.global async_exit_pointer_end
	.type async_exit_pointer_end, @function

async_exit_pointer_end:

	.global sgx_raise
	.type sgx_raise, @function

sgx_raise:
	leaq .Lafter_resume(%rip), %rdx
	jmp .Ldo_ecall_callee_save

.Lsgx_entry:
	# arguments: RDI - code, RSI - ms
	.cfi_startproc

	# increment per-thread EEXIT counter for stats
	lock incq %gs:PAL_TCB_URTS_EEXIT_CNT

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
