#include "sgx_arch.h"
#include "asm-offsets.h"

# In some cases, like bogus parameters passed to enclave_entry, it's tricky to
# return cleanly (passing the correct return address to EEXIT, OCALL_EXIT can
# be interrupted, etc.). Since those cases should only ever happen with a
# malicious urts, just go into an endless loop.
.macro FAIL_LOOP
.Lfail_loop\@:
	jmp .Lfail_loop\@
.endm

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

	# This thread can be interrupted but then the above check branches to
	# .Lhandle_resume. So the outside can't re-enter the checks below in
	# the middle.

	# Only jump to .Lreturn_from_ocall if we have prepared the stack for
	# it.
	cmpq $0, %gs:SGX_OCALL_PREPARED
	jne .Lreturn_from_ocall

	# Ecalls are only used to start a thread (either the main or an
	# additional thread). So per thread we should only get exactly one
	# ecall. Enforce this here.
	cmpq $0, %gs:SGX_ECALL_CALLED
	je 1f
	FAIL_LOOP
1:
	movq $1, %gs:SGX_ECALL_CALLED

	# PAL convention:
	# RDI - ECALL number
	# RSI - prointer to ecall arguments
	# RDX - exit target
	# RCX (former RSP) - The unstrusted stack
	# R8  - enclave base

	# calculate enclave base = RBX (trusted) - %gs:SGX_TCS_OFFSET
	subq %gs:SGX_TCS_OFFSET, %rbx
	movq %rbx, %r8

	# push untrusted stack address to RCX
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

	# handle_ecall will only return when invalid parameters has been passed.
	FAIL_LOOP

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

.Lhandle_exception:
	# If this enclave thread has not been initialized yet, we should not
	# try to call an event handler yet.
	cmpq $0, %gs:SGX_READY_FOR_EXCEPTIONS
	jne 1f
	FAIL_LOOP
1:

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

	# %rbx SGX_GPR base address from TLS
	movq SGX_GPR_RSP(%rbx), %rsi
	movq %gs:SGX_STACK, %rax
	cmpq $0, %rax
	je 1f
	movq %rax, %rsi
1:

	movq %gs:SGX_SIG_STACK_LOW, %rax
	cmpq %rax, %rsi
	jbe .Lout_of_signal_stack
	movq %gs:SGX_SIG_STACK_HIGH, %rax
	cmpq %rax, %rsi
	ja .Lout_of_signal_stack
	jmp .Lon_signal_stack

.Lout_of_signal_stack:
	movq %gs:SGX_SIG_STACK_HIGH, %rsi
        /* staring from new stack. there is no red zone used.
         * offset it below calculation */
	addq $REDZONE_SIZE, %rsi

	/* 8 is to avoid redzone clobber */
#define STACK_PADDING_SIZE	(PAL_FP_XSTATE_MAGIC2_SIZE + 8)
#define STACK_FRAME_SUB \
	(SGX_CONTEXT_SIZE + REDZONE_SIZE + STACK_PADDING_SIZE)
.Lon_signal_stack:
	movq xsave_size@GOTPCREL(%rip), %rax
	movl (%rax), %eax
	addq $STACK_FRAME_SUB, %rax
	subq %rax, %rsi
	# Align xsave area to 64 bytes after sgx_context_t
	# SGX_CONTEXT_SIZE = sizeof(sgx_context_t) = 144
	# PAL_XSTATE_ALIGN = 64
	# SGX_CONTEXT_XSTATE_ALIGN_SUB=SGX_CONTEXT_SIZE % PAL_XSTATE_ALIGN = 16
	# unfortunatley gas doesn't understand
	# $(SGX_CONTEXT_SIZE % PAL_XSTATE_ALIGN)
	andq $~(PAL_XSTATE_ALIGN - 1), %rsi
	subq $SGX_CONTEXT_XSTATE_ALIGN_SUB, %rsi

	# we have exitinfo in RDI, swap with the one on GPR
	# and dump into the context
	xchgq %rdi, SGX_GPR_RDI(%rbx) # 1st argument for _DkExceptionHandler()
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
	movq %rsi, SGX_GPR_RSI(%rbx) ## 2nd argument for _DkExceptionHandler()

	/* TODO: save EXINFO in MISC region */

	# new RIP is the exception handler
	leaq _DkExceptionHandler(%rip), %rdi
	movq %rdi, SGX_GPR_RIP(%rbx)

	# FP registers are saved on entry of _DkExceptionHandler()

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
	##
	## input:
	## %rdi: code
	## %rsi: void * ms
	##
	## sgx_context_t:
	##   rax = 0: place holder
	##   rcx
	##   ...
	##   rflags
	##   rip
	## xsave area
	##   xregs
	## (padding)
	## ---
	## previous rbp
	## previous rip: pushed by callq
	##

	pushq %rbp
	movq %rsp, %rbp

	## switch to signal stack if not yet.
	movq %gs:SGX_SIG_STACK_LOW, %rax
	cmpq %rax, %rsp
	jbe .Lout_of_signal_stack_ocall
	movq %gs:SGX_SIG_STACK_HIGH, %rax
	cmpq %rax, %rsp
	ja .Lout_of_signal_stack_ocall
	jmp .Lon_signal_stack_ocall

.Lout_of_signal_stack_ocall:
	movq %gs:SGX_SIG_STACK_HIGH, %rsp

.Lon_signal_stack_ocall:

	movq xsave_size@GOTPCREL(%rip), %rax
	movl (%rax), %eax
	addq $STACK_PADDING_SIZE, %rax
	subq %rax, %rsp
	andq $~(PAL_XSTATE_ALIGN - 1), %rsp

	pushq %rdx
	pushq %rdi
	movq %rsp, %rdi
	addq $2 * 8, %rdi	/* adjust pushq %rdx; pushq %rdi above */
	callq save_xregs
	popq %rdi
	popq %rdx

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
	pushq $0        # place holder for RAX

	movq $1, %gs:SGX_OCALL_PREPARED

.Leexit:
	movq %rdi, %rbx
	movq SYNTHETIC_STATE@GOTPCREL(%rip), %rdi
	callq restore_xregs
	movq %rbx, %rdi

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

	# It's ok to use the untrusted stack and exit target below without
	# checks since the processor will ensure that after exiting enclave
	# mode in-enclave memory can't be accessed.

	movq %gs:SGX_USTACK, %rsp
	andq $STACK_ALIGN, %rsp

	movq %gs:SGX_EXIT_TARGET, %rbx
	movq $EEXIT, %rax
	ENCLU

.Lreturn_from_ocall:
	# PAL convention:
	# RDI - return value
	# RSI - external event (if there is any)

	movq $0, %gs:SGX_OCALL_PREPARED

	# restore the stack
	movq $0, %rsp
	xchgq %rsp, %gs:SGX_STACK

	## sgx_context_t::rax = %rdi
	movq %rdi, (%rsp) # return value

	# restore FSBASE if necessary
	movq %gs:SGX_FSBASE, %rbx
	cmpq $0, %rbx
	je .Lno_fsbase
	.byte 0xf3, 0x48, 0x0f, 0xae, 0xd3 /* WRFSBASE %RBX */
.Lno_fsbase:
	movq %rsi, %rdi	## %rdi = PAL_NUM event <- RSI
	movq %rsp, %rsi	## %rsi = sgx_context_t * uc
	movq %rsp, %rdx
	addq $SGX_CONTEXT_SIZE, %rdx ## %rdx = PAL_XREGS_STATE * xregs_state
	callq _DkHandleExternalEvent
	## NOTREACHED

	# void __restore_sgx_context (sgx_context_t *uc)
	# __attribute__((noreturn))
	.global __restore_sgx_context
	.type __restore_sgx_context, @function
__restore_sgx_context:
	movq %rdi, %rsp

	popq %rax
	popq %rcx
	popq %rdx
	popq %rbx
	addq $8, %rsp /* don't popq RSP yet */
	popq %rbp
	popq %rsi
	popq %rdi
	popq %r8
	popq %r9
	popq %r10
	popq %r11
	popq %r12
	popq %r13

	/* store saved %rip at -REDZONE-8(%saved rsp).
	 * notice sizeof(sgx_context_t) = 144 > 128 = REDZONE_SIZE.
	 */
	## see the definition of sgx_context_t
	## currently %rsp is pointing to %r14
	movq -10 * 8(%rsp), %r14 # %r14 = saved %rsp
	movq 3 * 8(%rsp), %r15	 # %r15 = saved %rip
	movq %r15, - REDZONE_SIZE - 8(%r14)

	popq %r14
	popq %r15
	popfq

	/* avoid to clobber red zone */
	subq $(REDZONE_SIZE + 8), -13 * 8(%rsp)
	movq -13 * 8(%rsp), %rsp
	retq $REDZONE_SIZE

	# void save_xregs(uint64_t xsave_area)
	.global save_xregs
	.type save_xregs, @function
save_xregs:
	fwait
	movq xsave_enabled@GOTPCREL(%rip), %rax
	movl (%rax), %eax
	cmpl $0, %eax
	jz 1f

	## clear xsave header
	movq $0, XSAVE_HEADER_OFFSET + 0 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 1 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 2 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 3 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 4 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 5 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 6 * 8(%rdi)
	movq $0, XSAVE_HEADER_OFFSET + 7 * 8(%rdi)

	movl $0xffffffff, %eax
	movl $0xffffffff, %edx
	xsave64 (%rdi)
	retq
1:
	fxsave64 (%rdi)
	retq


	# void restore_xregs(uint64_t xsave_area)
	.global restore_xregs
	.type restore_xregs, @function
restore_xregs:
	movq xsave_enabled@GOTPCREL(%rip), %rax
	movl (%rax), %eax
	cmpl $0, %eax
	jz 1f

	movl $0xffffffff, %eax
	movl $0xffffffff, %edx
	xrstor64 (%rdi)
	retq
1:
	fxrstor64 (%rdi)
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
