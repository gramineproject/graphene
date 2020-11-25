#include "pal_linux_defs.h"
#include "sgx_arch.h"

#include "asm-offsets.h"

	.extern tcs_base

	.global sgx_ecall
	.type sgx_ecall, @function

sgx_ecall:
	.cfi_startproc

	# put entry address in RDX
	leaq .Lsgx_entry(%rip), %rdx

	# other arguments: RDI - code, RSI - ms

.Ldo_ecall_callee_save:
	pushq %rbx
	.cfi_adjust_cfa_offset 8
	pushq %rbp
	.cfi_adjust_cfa_offset 8
	pushq %r12
	.cfi_adjust_cfa_offset 8
	pushq %r13
	.cfi_adjust_cfa_offset 8
	pushq %r14
	.cfi_adjust_cfa_offset 8
	pushq %r15
	.cfi_adjust_cfa_offset 8

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
	.cfi_adjust_cfa_offset -8
	popq %r14
	.cfi_adjust_cfa_offset -8
	popq %r13
	.cfi_adjust_cfa_offset -8
	popq %r12
	.cfi_adjust_cfa_offset -8
	popq %rbp
	.cfi_adjust_cfa_offset -8
	popq %rbx
	.cfi_adjust_cfa_offset -8
	retq
	.cfi_endproc

	.global async_exit_pointer
	.type async_exit_pointer, @function

async_exit_pointer:
	.cfi_startproc
	.cfi_undefined %rip

	# increment per-thread AEX counter for stats
	lock incq %gs:PAL_TCB_URTS_AEX_CNT

#ifdef DEBUG
	# Save ERESUME parameters
	pushq %rax
	.cfi_adjust_cfa_offset 8
	pushq %rbx
	.cfi_adjust_cfa_offset 8
	pushq %rcx
	.cfi_adjust_cfa_offset 8

	# Align stack (required by System V AMD64 ABI)
	movq %rsp, %rbp
	.cfi_def_cfa_register %rbp
	andq $~0xF, %rsp

	# Call sgx_profile_sample with %rdi = TCS
	movq %rbx, %rdi
	call sgx_profile_sample

	# Restore stack
	movq %rbp, %rsp
	.cfi_def_cfa_register %rsp

	# Restore ERESUME parameters
	popq %rcx
	.cfi_adjust_cfa_offset -8
	popq %rbx
	.cfi_adjust_cfa_offset -8
	popq %rax
	.cfi_adjust_cfa_offset -8
#endif

	.cfi_endproc

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
