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
	# On EENTER, RAX is the current SSA index (aka CSSA),
	# RBX is the address of TCS, RCX is the address of AEP.
	# Other registers are not trusted.

	# x86-64 sysv abi requires %rFLAGS.DF = 0 on entry to function call.
	cld

	cmpq $0, %rax
	jne .Lhandle_resume

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

	# Nested exceptions at the host-OS level are disallowed:
	# - Synchronous exceptions are assumed to never happen during
	#   handle_resume;
	# - Asynchronous signals are not nested by benign host OS because
	#   we mask asynchronous signals on signal handler.
	# If malicious host OS injects a nested signal, CSSA != 1 and we
	# fail execution.
	# This FAIL_LOOP is assertion only because
	# currently this is also enforced by EENTER because NSSA == 2
	cmpq $1, %rax
	je 1f
	FAIL_LOOP
1:

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

	jmp .Lclear_and_eexit

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
	## %rsp before EEXIT in sgx_ocall).

	movq SGX_GPR_RSP(%rbx), %rsi
	movq %gs:SGX_STACK, %rax
	cmpq $0, %rax
	je 1f
	movq %rax, %rsi
1:
	subq $(SGX_CONTEXT_SIZE + RED_ZONE_SIZE), %rsi

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

	# Pass pointer to sgx_context_t to _DkExceptionHandler
	movq %rsi, SGX_GPR_RSI(%rbx)

	# Align the stack for _DkExceptionHandler
	andq $STACK_ALIGN, %rsi
	movq %rsi, SGX_GPR_RSP(%rbx)

	# new RIP is the exception handler
	leaq _DkExceptionHandler(%rip), %rdi
	movq %rdi, SGX_GPR_RIP(%rbx)

	# clear the registers
	xorq %rdi, %rdi
	xorq %rsi, %rsi

	# exit address in RDX, mov it to RBX
	movq %rdx, %rbx
	# fallthrough

	# Clear other registers and similar state and then call EEXIT
	#
	# Arguments for EEXIT/untrusted code (not cleared):
	#
	#     %rbx: exit target
	#     %rsp: untrusted stack
	#     %rdi, %rsi: (optional) arguments to untrusted code.
.Lclear_and_eexit:

	# Clear "extended" state (FPU aka x87, SSE, AVX, ...).

	leaq .Lxrstor_init_arg(%rip), %rcx
	# pal_sec.enclave_attributes.xfrm will always be zero before
	# init_enclave has been called by pal_linux_main. So during early init
	# nothing should use features not covered by fxrstor, like AVX.
	movq (pal_sec + PAL_SEC_ENCLAVE_ATTRIBUTES + SGX_ARCH_ATTRIBUTES_XFRM)(%rip), %rax
	testq $XSAVE_NON_FX_MASK, %rax
	je 1f
	mov $0xffffffff, %edx
	mov $0xffffffff, %eax
	xrstor (%rcx)
	jmp 2f
1:
	fxrstor (%rcx)
2:

	# %rax is argument to EEXIT
	# %rbx is argument to EEXIT
	# %rcx is set to AEP by EEXIT
	xorq %rdx, %rdx
	# %rsi, %rdi are arguments to the untrusted code
	xorq %rbp, %rbp
	# %rsp points to untrusted stack
	xorq %r8, %r8
	xorq %r9, %r9
	xorq %r10, %r10
	xorq %r11, %r11
	xorq %r12, %r12
	xorq %r13, %r13
	xorq %r14, %r14
	subq %r15, %r15 # use sub to set flags to a fixed value

	movq $EEXIT, %rax
	ENCLU

	ud2 # We should never get here.

	# fxsave/xsave area to reset extended state.
	#
	# The first 512 B are used by fxrstor. We set FCW = 0x037f and MXCSR =
	# 0x1f80 and the rest to 0 (same values as xrstor uses in
	# initialization mode).
	#
	# The fxsave area is followed by the 64 B xsave header. We use the
	# "compact" format (XCOMP_BV[63] = 1). Since the rest of XSTATE_BV and
	# XCOMP_BV are 0s, xrstor initializes all components (assuming it's
	# called with RFBM set to all 1s). The fxsave area is ignored (because
	# we request initialization not restore). And thanks to the compact
	# format we don't need to provide anything after the header.
.section .rodata
	.balign 64
.Lxrstor_init_arg:
	.byte 0x7f, 0x03 	# FCW
	.skip 6, 0
	.byte 0x80, 0x1f, 0, 0 	# MXCSR
	.skip 500, 0	 	# rest of fxstore area

	.skip 15, 0	 	# XSTATE_BV and XCOMP_BV[55:0]
	.byte 0x80	 	# XCOMP_BV[63:56] i.e. "compact" format
	.skip 48, 0	 	# rest of xsave header
.previous

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

	movq $1, %gs:SGX_OCALL_PREPARED

	movq %rsp, %gs:SGX_STACK

	# It's ok to use the untrusted stack and exit target below without
	# checks since the processor will ensure that after exiting enclave
	# mode in-enclave memory can't be accessed.

	movq %gs:SGX_USTACK, %rsp
	andq $STACK_ALIGN, %rsp

	movq %gs:SGX_EXIT_TARGET, %rbx
	jmp .Lclear_and_eexit

.Lreturn_from_ocall:
	# PAL convention:
	# RDI - return value
	# RSI - external event (if there is any)

	movq $0, %gs:SGX_OCALL_PREPARED

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

/*
 * Restore an sgx_context_t as generated by .Lhandle_exception. Execution will
 * continue as specified by the rip in the context.
 *
 * It is required that:
 *
 *     %rdi == *(%rdi + SGX_CONTEXT_RSP) - (SGX_CONTEXT_SIZE + RED_ZONE_SIZE)
 *
 * This holds for the original sgx_context allocated by .Lhandle_exception.
 * restore_sgx_context is a safe wrapper which checks this.
 */
	.global _restore_sgx_context
	.type _restore_sgx_context, @function

_restore_sgx_context:
	movq SGX_CONTEXT_RAX(%rdi), %rax
	movq SGX_CONTEXT_RCX(%rdi), %rcx
	movq SGX_CONTEXT_RDX(%rdi), %rdx
	movq SGX_CONTEXT_RBX(%rdi), %rbx
	# For %rsp see below.
	movq SGX_CONTEXT_RBP(%rdi), %rbp
	movq SGX_CONTEXT_RSI(%rdi), %rsi
	# For %rdi see below.
	movq SGX_CONTEXT_R8(%rdi), %r8
	movq SGX_CONTEXT_R9(%rdi), %r9
	movq SGX_CONTEXT_R10(%rdi), %r10
	movq SGX_CONTEXT_R11(%rdi), %r11
	movq SGX_CONTEXT_R12(%rdi), %r12
	movq SGX_CONTEXT_R13(%rdi), %r13
	movq SGX_CONTEXT_R14(%rdi), %r14
	movq SGX_CONTEXT_R15(%rdi), %r15

	# We need to make sure that %rsp - RED_ZONE_SIZE never points above
	# anything we still need. Otherwise .Lhandle_exception might mess with
	# it. SGX_CONTEXT_RDI - SGX_CONTEXT_RFLAGS <= RED_ZONE_SIZE, see
	# sgx_arch.h.
	leaq SGX_CONTEXT_RFLAGS(%rdi), %rsp
	popfq # remember to not touch any flags after here

	movq SGX_CONTEXT_RDI(%rdi), %rdi
	# Now %rdi is restored so we need to use the stack to access the
	# context.

	# Now pop %rip and fix stack pointer in one operation (to avoid
	# problems with nesting, see comment above). SGX_CONTEXT_RIP is
	# directly after SGX_CONTEXT_RFLAGS, see sgx_arch.h. Note that retq
	# decreases %rsp by 8 for the poped %rip additionaly to the passed
	# offset.
	retq $(SGX_CONTEXT_SIZE + RED_ZONE_SIZE - SGX_CONTEXT_RIP - 8)
