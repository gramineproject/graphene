#include "pal_linux_defs.h"
#include "sgx_arch.h"

	.extern tcs_base

	.global sgx_ecall
	.type sgx_ecall, @function

sgx_ecall:
	# put entry address in RDX
	lea sgx_entry(%rip), %rdx

	# other arguments: RDI - code, RSI - ms

.Ldo_ecall:
	# RBX has to be the TCS of the thread
	mov current_tcs@gottpoff(%rip), %rbx
	mov %fs:(%rbx), %rbx

	# RCX has to be the AEP (Asynchronous Exit Pointer)
	lea async_exit_pointer(%rip), %rcx

	mov $EENTER, %rax
	ENCLU

	.global async_exit_pointer
	.type async_exit_pointer, @function

#if SGX_HAS_FSGSBASE == 0
async_exit_pointer:
	# because ERESUME doesn't restore FS/GS, we must do EENTER

	mov current_tcs@gottpoff(%rip), %rbx
	mov %fs:(%rbx), %rbx

	lea double_async_exit(%rip), %rcx

	# put the exit address in RDX
	lea .Lreal_resume(%rip), %rdx

	mov $EENTER, %rax
	ENCLU

.Lreal_resume:
	# RBX has to be the TCS of the thread
	mov current_tcs@gottpoff(%rip), %rbx
	mov %fs:(%rbx), %rbx

	# RCX has to be the AEP (Asynchronous Exit Pointer)
	lea async_exit_pointer(%rip), %rcx

	mov $ERESUME, %rax
	ENCLU

	.global double_async_exit
	.type double_async_exit, @function

double_async_exit:
	ENCLU
#else
async_exit_pointer:
	ENCLU

	.global sgx_raise
	.type sgx_raise, @function

sgx_raise:
	lea .Lafter_resume(%rip), %rdx
	jmp .Ldo_ecall

.Lafter_resume:
	retq
#endif

sgx_entry:
	# arguments: RDI - code, RSI - ms

	lea ocall_table(%rip), %rbx
	mov (%rbx,%rdi,8), %rbx
	mov %rsi, %rdi
	call *%rbx

	mov %rax, %rdi
	# Not interrupted
	xor %rsi, %rsi

	.global sgx_entry_return
	.type sgx_entry_return, @function

sgx_entry_return:
	# return to enclave, arguments:
	# RDI - return value
	# RSI - externel event
	jmp .Ldo_ecall

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
