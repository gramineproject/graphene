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

.macro CHECK_IF_SIGNAL_STACK_IS_USED stack_reg, label_on_stack, label_out_of_stack
	cmpq %gs:SGX_SIG_STACK_LOW, \stack_reg
	jb \label_out_of_stack
	cmpq %gs:SGX_SIG_STACK_HIGH, \stack_reg
	ja \label_out_of_stack
	jmp \label_on_stack
.endm

	.global enclave_entry
	.type enclave_entry, @function

enclave_entry:
	.cfi_startproc

	# On EENTER, RAX is the current SSA index (aka CSSA), RBX is the address of
	# TCS, RCX is the address of IP following EENTER. Other regs are not trusted.

	# x86-64 sysv abi requires %rFLAGS.DF = 0 on entry to function call.
	cld

	cmpq $0, %rax
	jne .Lprepare_resume

	# ECALL return address in RCX (filled by EENTER hardware flow)
	movq %rcx, %gs:SGX_ECALL_RETURN_ADDR

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
	# .Lprepare_resume. So the outside can't re-enter the checks below in
	# the middle.

	# Only jump to .Lreturn_from_ocall if we have prepared the stack for
	# it.
	cmpq $0, %gs:SGX_PRE_OCALL_STACK
	jne .Lreturn_from_ocall

	# PAL convention:
	# RDI - ECALL number
	# RSI - pointer to ecall arguments
	# RDX - exit target
	# RCX - enclave base

	cmpq $ECALL_THREAD_RESET, %rdi
	je .Lhandle_thread_reset

	# Except ecall_thread_reset, ecalls are only used to start a thread (main
	# or additional threads). We already checked for case of ecall_thread_reset,
	# so at this point we should only get exactly one ecall per thread
	cmpq $0, %gs:SGX_THREAD_STARTED
	je 1f
	FAIL_LOOP
1:
	movq $1, %gs:SGX_THREAD_STARTED

	# calculate enclave base = RBX (trusted) - %gs:SGX_TCS_OFFSET
	mov %rbx, %rcx
	subq %gs:SGX_TCS_OFFSET, %rcx

	# switch to enclave stack
	movq %gs:SGX_INITIAL_STACK_ADDR, %rsp

	# clear the rest of register states
	xorq %rax, %rax
	xorq %rbx, %rbx
	xorq %r8, %r8
	xorq %r9,  %r9
	xorq %r10, %r10
	xorq %r11, %r11
	xorq %r12, %r12
	xorq %r13, %r13
	xorq %r14, %r14
	xorq %r15, %r15

	# clear the Alignment Check flag (%rFLAGS.AC) to prevent #AC-fault side channel;
	# this overrides 8B on enclave stack but stack is not used at this point anyway
	pushfq
	andq $(~RFLAGS_AC), (%rsp)
	popfq

	# Clear "extended" state (FPU aka x87, SSE, AVX, ...).
	# TODO: We currently clear only state covered by FXRSTOR but not by XRSTOR
	#       (e.g., no clearing of YMM/ZMM regs). This is because we didn't read
	#       the value of XFRM yet, so we don't know whether XRSTOR is safe at
	#       this point.
	leaq g_xsave_reset_state(%rip), %rax
	fxrstor (%rax)
	xorq %rax, %rax

	# register states need to be carefully checked, so we move the handling
	# to handle_ecall() in enclave_ecalls.c
	callq handle_ecall

	# handle_ecall will only return when invalid parameters has been passed.
	FAIL_LOOP

	# clear TLS variables for thread reuse
.Lhandle_thread_reset:
	movq $0, %gs:SGX_READY_FOR_EXCEPTIONS

	# Assertion: thread is reset only after special-case OCALL_EXIT.
	cmpq $0, %gs:SGX_OCALL_EXIT_CALLED
	jne 1f
	FAIL_LOOP
1:

	# At this point, the thread has completely exited from the point of view
	# of LibOS. We can now set *clear_child_tid to 0, which will trigger
	# async worker thread in LibOS, which will wake up parent thread if any.
	cmpq $0, %gs:SGX_CLEAR_CHILD_TID
	je 1f
	movq %gs:SGX_CLEAR_CHILD_TID, %rbx
	movl $0, (%rbx)

1:
	# Signals are impossible at this point: benign untrusted runtime blocks
	# all signals (see sgx_ocall_exit()), and even if malicious one doesn't
	# block them, signals are ignored due to SGX_READY_FOR_EXCEPTIONS = 0.
	movq $0, %gs:SGX_THREAD_STARTED
	movq $0, %gs:SGX_OCALL_EXIT_CALLED
	movq $0, %gs:SGX_PRE_OCALL_STACK

	# Instead of jumping to .Lclear_and_eexit, simply perform EEXIT because
	# there is no modified state to clear in this "thread-reset" code path.
	movq %gs:SGX_ECALL_RETURN_ADDR, %rbx
	movq $EEXIT, %rax
	ENCLU

.Lprepare_resume:
	# PAL convention:
	# RDI - external event

	# Nested exceptions at the host-OS level are disallowed:
	# - Synchronous exceptions are assumed to never happen during
	#   prepare_resume;
	# - Asynchronous signals are not nested by benign host OS because
	#   we mask asynchronous signals on signal handler.
	# If malicious host OS injects a nested signal, CSSA != 1 and we go
	# into FAIL_LOOP. Currently this check is assertion only because it
	# is also enforced by EENTER since enclave is created with NSSA=2.
	cmpq $1, %rax
	je 1f
	FAIL_LOOP
1:

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

.Lignore_exception:
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

	# Beware of races between host signal delivery and handling %rsp in
	# this entry code. Consider the following scenario:
	#
	# 1. We are inside the enclave but %rsp isn't restored yet to something
	#    inside the enclave. That's for example the case when returning from
	#    an ocall.
	# 2. The enclave gets interrupted. The not restored %rsp is pushed into
	#    SGX_GPR_RSP by the processor.
	# 3. The host enters the enclave again and indicates that there's a new
	#    signal.
	# 4. SGX_GPR_RSP points to the untrusted stack
	#
	# The below code should be fine since it detects an interrupted ocall
	# and restores %rsp from SGX_PRE_OCALL_STACK before exception handling
	# (see below for full details)

	# The stack swap logic does not need to be atomic because nested
	# exceptions are disallowed by SGX due to TCS.NSSA == 2 (thus,
	# .Lhandle_exception logic cannot be nested)

	# Check if we got interrupted during an ocall case (except OCALL_EXIT),
	# i.e. SGX_PRE_OCALL_STACK is set.
	movq %gs:SGX_PRE_OCALL_STACK, %rsi
	cmpq $0, %rsi
	jne .Lhandle_interrupted_ocall

	# If this is not the case check if OCALL_EXIT has been called. If this
	# is not the case setup the exception handler for the non-ocall case.
	cmpq $0, %gs:SGX_OCALL_EXIT_CALLED
	je .Lsetup_exception_handler

	# We are interrupted during the never-returning OCALL_EXIT. Because the
	# thread is going to exit anyway, we can ignore this exception.
	jmp .Lignore_exception

.Lhandle_interrupted_ocall:
	# At this point, we are in the exception handler and
	# SGX_PRE_OCALL_STACK=<trusted pointer to enclave stack>. I.e. we are
	# interrupted during handling of enclave's sgx_ocall/return_from_ocall
	# assembly code.
	#
	# Triggering the exception handler while SGX_PRE_OCALL_STACK != 0 would
	# be problematic because it could itself issue nested ocalls. This
	# would mean the SGX_PRE_OCALL_STACK logic would need to handle
	# nesting.
	#
	# Instead if we're in such situation, we emulate it as if %rip reached to
	# the safe point, .Lreturn_from_ocall_after_stack_restore.
	#
	# Ocall sequence:
	#  1. call sgx_ocall()
	#  2. SGX_PRE_OCALL_STACK=%rsp: save trusted stack
	#  3. EEXIT
	#  4. untrusted PAL which issues real host system call
	#  5. EENTER (and start from enclave_entry)
	#  6. .Lreturn_from_ocall:
	#  7. (%rsp, SGX_STACK) = (SGX_STACK, 0): restore trusted stack
	#  8. .Lreturn_from_ocall_after_stack_restore:
	#  9. call _DkHandleExternalEvent() if interrupted
	# 10. return from sgx_ocall() to the caller
	#
	# It is also required that sgx_ocall() be atomic regarding to async exception.
	# When host async signal arrives, sgx_ocall() should result in EINTR.
	#
	# There are three possibilities when exactly host async signal arrives:
	# A. before exiting enclave to perform host syscall
	# B. after exiting enclave and before re-entering enclave
	#    (i.e., during untrusted execution of host syscall)
	# C. after re-entering enclave but before returning to sgx_ocall().
	#
	# Note that Case A didn't even issue host syscall, Case B may have
	# interrupted host syscall (but maybe interrupt came after successful
	# host syscall), and Case C was interrupted after successful host
	# syscall. In Case C, the result of host system call must be preserved
	# to be replayed in later invocation.
	#
	# On host async signal we treat these cases as follows:
	# A. right-before EEXIT (2. in above sequence, before 2. got executed
	# 			 we don't land here):
	#	 - set EINTR and forward %rip to exception handler
	# B. during untrusted PAL (3. - 4. in above sequence):
	#	 - code in _DkTerminateSighandler() must handle this case
	#	 TODO: fix _DkTerminateSighandler() to not lose the result of successful
	#		   system call.
	# C. right-after EENTER (5. - 7. in above sequence):
	#	 - ocall succeeded, forward %rip to exception handler

	# Find out which of cases A, B, or C happened:
	# - copy rip at which the enclave was interrupted into %rax,
	# - copy the boundaries between cases A, B, and C into %r11,
	# - compare enclave's rip against these boundaries (%rax vs %r11).
	movq SGX_GPR_RIP(%rbx), %rax
	leaq .Locall_about_to_eexit_begin(%rip), %r11
	cmpq %r11, %rax
	jb .Lhandle_interrupted_ocall_case_c
	leaq .Locall_about_to_eexit_end(%rip), %r11
	cmpq %r11, %rax
	jae .Lhandle_interrupted_ocall_case_c

	# Case A. We are right-before EEXIT for ocall in between
	# [.Locall_about_to_eexit_begin, .Locall_about_to_eexit_end)
	# Skip EEXIT as if ocall returned EINTR.
	# If there is registered signal handler for the current exception,
	# _DkHandleExternalEvent() will be called (and thus we need to save
	# %rdi = <external event>) before returning from ocall.
	movq $-EINTR, SGX_GPR_RDI(%rbx) # return value for .Lreturn_from_ocall
	# fallthrough to Case C.

	# This code cannot land in Case B because:
	# (1) this code path (.Lhandle_exception) is triggered only if we haven't
	# yet exited the enclave when signal arrived, and
	# (2) in Case B, we exited the enclave and signal arrived while in
	# untrusted code. The two conditions cannot be true at the same time,
	# so Case B never happens here (Case B results in return_from_ocall code
	# path below).

.Lhandle_interrupted_ocall_case_c:
	# Case C. We are right-after EENTER returning from successful ocall.
	# Move %rip to .Lreturn_from_ocall_after_stack_restore and let
	# _DkHandleExternalEvent() handle the exception.
	# SGX_GPR_RDI(%rbx): don't touch successful ocall result.
	movq %rdi, SGX_GPR_RSI(%rbx) # external event for .Lreturn_from_ocall
	leaq .Lreturn_from_ocall_after_stack_restore(%rip), %rax
	movq %rax, SGX_GPR_RIP(%rbx)
	movq %rsi, SGX_GPR_RSP(%rbx)
	movq $0, %gs:SGX_PRE_OCALL_STACK
	andq $(~(RFLAGS_DF | RFLAGS_AC)), SGX_GPR_RFLAGS(%rbx)
	jmp .Leexit_exception

.Lsetup_exception_handler:
	# The thread got interrupted outside of ocall handling (see above for
	# that special case). We inject a call to _DkExceptionHandler into the
	# interrupted thread which will handle the exception on ERESUME.

	# The last instructions of _restore_sgx_context need to be atomic for
	# the code below (see _restore_sgx_context for more details). So
	# emulate this if we were interrupted there.
	leaq .Ltmp_rip_saved0(%rip), %rax
	cmpq %rax, SGX_GPR_RIP(%rbx)
	je .Lemulate_tmp_rip_saved0

	leaq .Ltmp_rip_saved1(%rip), %rax
	cmpq %rax, SGX_GPR_RIP(%rbx)
	je .Lemulate_tmp_rip_saved1

	leaq .Ltmp_rip_saved2(%rip), %rax
	cmpq %rax, SGX_GPR_RIP(%rbx)
	je .Lemulate_tmp_rip_saved2

	jmp .Lemulate_tmp_rip_end

.Lemulate_tmp_rip_saved0:
	# emulate movq SGX_CPU_CONTEXT_R15 - SGX_CPU_CONTEXT_RIP(%rsp), %r15
	movq SGX_GPR_RSP(%rbx), %rax
	movq SGX_CPU_CONTEXT_R15 - SGX_CPU_CONTEXT_RIP(%rax), %rax
	movq %rax, SGX_GPR_R15(%rbx)
.Lemulate_tmp_rip_saved1:
	# emulate movq SGX_CPU_CONTEXT_RSP - SGX_CPU_CONTEXT_RIP(%rsp), %rsp
	movq SGX_GPR_RSP(%rbx), %rax
	movq SGX_CPU_CONTEXT_RSP - SGX_CPU_CONTEXT_RIP(%rax), %rax
	movq %rax, SGX_GPR_RSP(%rbx)
.Lemulate_tmp_rip_saved2:
	# emulate jmp *%gs:SGX_TMP_RIP
	movq %gs:SGX_TMP_RIP, %rax
	movq %rax, SGX_GPR_RIP(%rbx)
.Lemulate_tmp_rip_end:

	movq SGX_GPR_RSP(%rbx), %rsi

	CHECK_IF_SIGNAL_STACK_IS_USED %rsi, .Lon_signal_stack, .Lout_of_signal_stack

.Lout_of_signal_stack:
	movq %gs:SGX_SIG_STACK_HIGH, %rsi
	# When switching to the not yet used signal stack we don't need to reserve
	# a redzone. So move the stack pointer up here to undo the move down below.
	addq $RED_ZONE_SIZE, %rsi

	# Setup stack for the signal handler, _DkExceptionHandler().
	# _restore_sgx_context() must be used to return back to the
	# original context.
	# Stack layout:
	#     8-bytes padding: (8 mod 16) bytes aligned for x86 ABI
	#                      NOTE: there is no saved rip to return.
	#     sgx_cpu_context_t: 144 bytes
	#     xsave area: PAL_XSTATE_ALIGN=64 bytes aligned
	#     padding if necessary
	#     RED_ZONE unless newly switching to signal stack
#define STACK_PADDING_SIZE (PAL_FP_XSTATE_MAGIC2_SIZE + 8)
#define STACK_FRAME_SUB \
	(SGX_CPU_CONTEXT_SIZE + RED_ZONE_SIZE + STACK_PADDING_SIZE)
.Lon_signal_stack:
	movl g_xsave_size(%rip), %eax
	addq $STACK_FRAME_SUB, %rax
	subq %rax, %rsi

	# Align xsave area to 64 bytes after sgx_cpu_context_t
	andq $~(PAL_XSTATE_ALIGN - 1), %rsi
	subq $SGX_CPU_CONTEXT_XSTATE_ALIGN_SUB, %rsi

	# we have exitinfo in RDI, swap with the one on GPR
	# and dump into the context
	xchgq %rdi, SGX_GPR_RDI(%rbx) # 1st argument for _DkExceptionHandler()
	movq %rdi, SGX_CPU_CONTEXT_RDI(%rsi)

	# dump the rest of context
	movq SGX_GPR_RAX(%rbx), %rdi
	movq %rdi, SGX_CPU_CONTEXT_RAX(%rsi)
	movq SGX_GPR_RCX(%rbx), %rdi
	movq %rdi, SGX_CPU_CONTEXT_RCX(%rsi)
	movq SGX_GPR_RDX(%rbx), %rdi
	movq %rdi, SGX_CPU_CONTEXT_RDX(%rsi)
	movq SGX_GPR_RBX(%rbx), %rdi
	movq %rdi, SGX_CPU_CONTEXT_RBX(%rsi)
	movq SGX_GPR_RSP(%rbx), %rdi
	movq %rdi, SGX_CPU_CONTEXT_RSP(%rsi)
	movq SGX_GPR_RBP(%rbx), %rdi
	movq %rdi, SGX_CPU_CONTEXT_RBP(%rsi)
	movq SGX_GPR_RSI(%rbx), %rdi
	movq %rdi, SGX_CPU_CONTEXT_RSI(%rsi)
	/* rdi is saved above */
	movq SGX_GPR_R8(%rbx), %rdi
	movq %rdi, SGX_CPU_CONTEXT_R8(%rsi)
	movq SGX_GPR_R9(%rbx), %rdi
	movq %rdi, SGX_CPU_CONTEXT_R9(%rsi)
	movq SGX_GPR_R10(%rbx), %rdi
	movq %rdi, SGX_CPU_CONTEXT_R10(%rsi)
	movq SGX_GPR_R11(%rbx), %rdi
	movq %rdi, SGX_CPU_CONTEXT_R11(%rsi)
	movq SGX_GPR_R12(%rbx), %rdi
	movq %rdi, SGX_CPU_CONTEXT_R12(%rsi)
	movq SGX_GPR_R13(%rbx), %rdi
	movq %rdi, SGX_CPU_CONTEXT_R13(%rsi)
	movq SGX_GPR_R14(%rbx), %rdi
	movq %rdi, SGX_CPU_CONTEXT_R14(%rsi)
	movq SGX_GPR_R15(%rbx), %rdi
	movq %rdi, SGX_CPU_CONTEXT_R15(%rsi)
	movq SGX_GPR_RFLAGS(%rbx), %rdi
	movq %rdi, SGX_CPU_CONTEXT_RFLAGS(%rsi)
	movq SGX_GPR_RIP(%rbx), %rdi
	movq %rdi, SGX_CPU_CONTEXT_RIP(%rsi)

	# Pass pointer to sgx_cpu_context_t and PAL_XREGS_STATE to _DkExceptionHandler
	movq %rsi, SGX_GPR_RSI(%rbx) # 2nd argument for _DkExceptionHandler()
	movq %rsi, SGX_GPR_RDX(%rbx)
	addq $SGX_CPU_CONTEXT_SIZE, SGX_GPR_RDX(%rbx) # 3rd argument for _DkExceptionHandler()
	# TODO: save EXINFO in MISC region

	# x86-64 sysv abi requires 16B alignment of stack before call instruction
	# which implies a (8 mod 16)B alignment on function entry (due to implicit
	# push %rip). Since we already aligned xsave area above, this requirement
	# is satisfied.
	subq $8, %rsi
	movq %rsi, SGX_GPR_RSP(%rbx)

	# clear SSA.GPRSGX.EXITINFO; we used it to identify HW exception (if any),
	# and a scenario is possible where the same SSA is re-used to handle more
	# signals that arrive right after this exception, so we must clear state
	movq $0, SGX_GPR_EXITINFO(%rbx)

	# clear RFLAGS.DF to conform to the SysV ABI, clear RFLAGS.AC to prevent
	# the #AC-fault side channel
	andq $(~(RFLAGS_DF | RFLAGS_AC)), SGX_GPR_RFLAGS(%rbx)

	# new RIP is the exception handler
	leaq _DkExceptionHandler(%rip), %rdi
	movq %rdi, SGX_GPR_RIP(%rbx)

	# dump the XSAVE region (XMM/YMM/etc part of context); SGX saves it at the
	# very beginning of the SSA frame; note that __restore_xregs / __save_xregs
	# clobber RDX so need to stash it in RBX
	movq %rdx, %rbx
	movq %gs:SGX_SSA, %rdi
	leaq 1f(%rip), %r11
	jmp __restore_xregs
1:
	leaq SGX_CPU_CONTEXT_SIZE + 8(%rsi), %rdi
	leaq 2f(%rip), %r11
	jmp __save_xregs
2:
	movq %rbx, %rdx

.Leexit_exception:
	# clear the registers
	xorq %rdi, %rdi
	xorq %rsi, %rsi

	# exit address in RDX, mov it to RBX
	movq %rdx, %rbx
	jmp .Lclear_and_eexit

	.cfi_endproc

	.global sgx_ocall
	.type sgx_ocall, @function

sgx_ocall:
	# arguments:
	#   RDI: OCALL number (code)
	#   RSI: OCALL args on untrusted stack (ms)
	#
	# sgx_cpu_context_t:
	#   RAX = 0: place holder
	#   RCX
	#   ...
	#   RFLAGS
	#   RIP
	# xsave area
	#   xregs
	# (padding)
	# --- stack may be non-contiguous as we may switch the stack to signal stack
	# previous RBX
	# previous RBP
	# previous RIP: pushed by callq

	.cfi_startproc
	pushq %rbp
	.cfi_adjust_cfa_offset 8
	movq %rsp, %rbp
	.cfi_offset %rbp, -16
	.cfi_def_cfa_register %rbp
	pushq %rbx
	.cfi_offset %rbx, -24

	CHECK_IF_SIGNAL_STACK_IS_USED %rsp, .Lon_signal_stack_ocall, .Lout_of_signal_stack_ocall

.Lout_of_signal_stack_ocall:
	movq %gs:SGX_SIG_STACK_HIGH, %rsp

.Lon_signal_stack_ocall:
	movl g_xsave_size(%rip), %eax
	addq $STACK_PADDING_SIZE, %rax
	subq %rax, %rsp
	andq $~(PAL_XSTATE_ALIGN - 1), %rsp

	pushq %rdx
	pushq %rdi
	movq %rsp, %rdi
	addq $2 * 8, %rdi # adjust pushq %rdx; pushq %rdi above
	callq save_xregs
	popq %rdi
	popq %rdx

	movq 8(%rbp), %rax
	pushq %rax # previous RIP
	pushfq

	# Under GDB, single-stepping sets Trap Flag (TP) of EFLAGS,
	# thus TP=1 is stored on pushfq above. Upon consequent popfq,
	# TP is 1, resulting in spurious trap. Reset TP here.
	andq $~0x100, (%rsp)

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
	pushq %rax # previous RBP
	leaq 16(%rbp), %rax
	pushq %rax # previous RSP
	pushq %rbx
	pushq %rdx
	pushq %rcx
	pushq $0 # placeholder for RAX

	# OCALL_EXIT should never return (see sgx_ocall_exit(): it always exits
	# the thread). Skip setting SGX_PRE_OCALL_STACK to land in special-case
	# of ECALL_THREAD_RESET (issued in sgx_ocall_exit()) later. Note that if
	# there is an interrupt (which usually would result in a simulated
	# return of -EINTR), it will be silently ignored via
	# .Lignore_exception.
	cmpq $OCALL_EXIT, %rdi
	jne 1f
	movq $1, %gs:SGX_OCALL_EXIT_CALLED
	jmp .Locall_about_to_eexit_begin
1:

	movq %rsp, %gs:SGX_PRE_OCALL_STACK

.Locall_about_to_eexit_begin:
	# From here .Lhandle_exception can mess with our state (%rip and %rsp).
	# We therefore need to be extremely careful when making changes here.
	#
	# It's ok to use the untrusted stack and exit target below without
	# checks since the processor will ensure that after exiting enclave
	# mode in-enclave memory can't be accessed.

	movq %gs:SGX_USTACK, %rsp

#ifdef DEBUG
	# Push %rip of some code inside __morestack() on untrusted stack.
	leaq .Lfor_cfa_debug_info(%rip), %r8
	pushq %r8
#endif

	movq %gs:SGX_EXIT_TARGET, %rbx
	.cfi_endproc
	# fallthrough

	# Clear other registers and similar state and then call EEXIT
	#
	# Arguments for EEXIT/untrusted code (not cleared):
	#
	#     %rbx: exit target
	#     %rsp: untrusted stack
	#     %rdi, %rsi: (optional) arguments to untrusted code.
.Lclear_and_eexit:

	.cfi_startproc
	# Clear "extended" state (FPU aka x87, SSE, AVX, ...).

	# g_pal_sec.enclave_attributes.xfrm will always be zero before
	# init_enclave has been called by pal_linux_main. So during early init
	# nothing should use features not covered by fxrstor, like AVX.

	cmpl $0, g_xsave_enabled(%rip)
	jne 1f
	fxrstor64 g_xsave_reset_state(%rip)
	jmp 2f
1:
	mov $0xffffffff, %eax
	mov %eax, %edx
	xrstor64 g_xsave_reset_state(%rip)
2:

	# %rax is argument to EEXIT
	# %rbx is argument to EEXIT
	# %rcx is set to AEP by EEXIT
	# %rsi, %rdi are arguments to the untrusted code

#ifdef DEBUG
	# Store pointer to context in RDX, for the SGX profiler.
	movq %gs:SGX_PRE_OCALL_STACK, %rdx

	# Keep callee-saved registers in order to recover stack later (see __morestack() below).
#else
	# In non-debug mode, clear these registers to prevent information leaks.
	xorq %rdx, %rdx
	xorq %rbp, %rbp
	xorq %r12, %r12
	xorq %r13, %r13
	xorq %r14, %r14
	xorq %r15, %r15
#endif

	# %rsp points to untrusted stack
	xorq %r8, %r8
	xorq %r9, %r9
	xorq %r10, %r10
	subq %r11, %r11  # use sub to set flags to a fixed value

	movq $EEXIT, %rax
	ENCLU
.Locall_about_to_eexit_end:

	ud2 # We should never get here.
	jmp .Locall_about_to_eexit_end
	.cfi_endproc

.Lreturn_from_ocall:
	# PAL convention:
	# RDI - return value
	# RSI - external event (if there is any)

	# restore the stack
	movq %gs:SGX_PRE_OCALL_STACK, %rsp
	movq $0, %gs:SGX_PRE_OCALL_STACK
.Lreturn_from_ocall_after_stack_restore:

	# sgx_cpu_context_t::rax = %rdi
	movq %rdi, SGX_CPU_CONTEXT_RAX(%rsp) # return value

	# restore FSBASE if necessary
	movq %gs:SGX_FSBASE, %rbx
	cmpq $0, %rbx
	je .Lno_fsbase
	.byte 0xf3, 0x48, 0x0f, 0xae, 0xd3 /* WRFSBASE %RBX */
.Lno_fsbase:

	# Check if there was a signal
	cmpq $0, %rsi
	je .Lno_external_event
	cmpq $PAL_EVENT_NUM_BOUND, %rsi
	jb .Lexternal_event
.Lno_external_event:
	movq %rsp, %rdi # %rdi = sgx_cpu_context_t* uc
	movq %rsp, %rsi
	addq $SGX_CPU_CONTEXT_SIZE, %rsi # %rsi = PAL_XREGS_STATE* xregs_state
	# _restore_sgx_context restores rflags and fp registers. So we don't have to
	# sanitize them like below.
	jmp _restore_sgx_context
	# NOTREACHED

.Lexternal_event:
	# clear the Alignment Check flag (%rFLAGS.AC) to prevent #AC-fault side channel;
	pushfq
	andq $(~RFLAGS_AC), (%rsp)
	popfq

	leaq g_xsave_reset_state(%rip), %rdi
	callq restore_xregs

	movq %rsi, %rdi # 1st argument = PAL_NUM event
	movq %rsp, %rsi # 2nd argument = sgx_cpu_context_t* uc
	leaq SGX_CPU_CONTEXT_SIZE(%rsp), %rdx # 3rd argument = PAL_XREGS_STATE* xregs_state
	callq _DkHandleExternalEvent
	# NOTREACHED

	# noreturn void _restore_sgx_context(sgx_cpu_context_t* uc, PAL_XREGS_STATE* xsave_area);
	# Restore an sgx_cpu_context_t as generated by .Lhandle_exception. Execution will
	# continue as specified by the rip in the context.
	# If RDI (uc) points into the signal stack we need to ensure that
	# until the last read from there RSP points there or
	# .Lsetup_exception_handler might mess with it because it would think
	# that the signal stack is not in use. In this case we assume that RSP
	# points into the signal stack when we get called.
	# (Also keep the redzone in mind, see asserts for sgx_cpu_context_t in sgx_arch.h)
	.global _restore_sgx_context
	.type _restore_sgx_context, @function
_restore_sgx_context:
	.cfi_startproc
	xchgq %rdi, %rsi
	callq restore_xregs

	movq %rsi, %r15

	movq SGX_CPU_CONTEXT_RAX(%r15), %rax
	movq SGX_CPU_CONTEXT_RCX(%r15), %rcx
	movq SGX_CPU_CONTEXT_RDX(%r15), %rdx
	movq SGX_CPU_CONTEXT_RBX(%r15), %rbx
	# For %rsp see below.
	movq SGX_CPU_CONTEXT_RBP(%r15), %rbp
	movq SGX_CPU_CONTEXT_RSI(%r15), %rsi
	movq SGX_CPU_CONTEXT_RDI(%r15), %rdi
	movq SGX_CPU_CONTEXT_R8(%r15), %r8
	movq SGX_CPU_CONTEXT_R9(%r15), %r9
	movq SGX_CPU_CONTEXT_R10(%r15), %r10
	movq SGX_CPU_CONTEXT_R11(%r15), %r11
	movq SGX_CPU_CONTEXT_R12(%r15), %r12
	movq SGX_CPU_CONTEXT_R13(%r15), %r13
	movq SGX_CPU_CONTEXT_R14(%r15), %r14
	# R15 will be restored below

	leaq SGX_CPU_CONTEXT_RFLAGS(%r15), %rsp
	popfq

	# See the comment at .Lsetup_exception_handler.
	#
	# The use of SGX_TMP_RIP (enclave_tls::tmp_rip per-enclave-thread field) must be atomic.
	# Consider a data race:
	# (1) thread handles a previous exception in SSA=0,
	# (2) thread is done and returns from exception handler via restore_sgx_context(),
	# (3) in the middle of _restore_sgx_context() a new exception arrives,
	# (4) the exception handler for this new exception is prepared in SSA=1,
	# (5) thread returns back to SSA=0 and handles this new exception,
	# (6) thread is done and returns from exception handler via _restore_sgx_context()
	# and updates SGX_TMP_RIP (overwrites enclave_tls::tmp_rip). Now the thread returned in
	# the middle of _restore_sgx_context() and will try to jmp *%gs:SGX_TMP_RIP but this value
	# is lost, and SIGILL/SEGFAULT follows.
	#
	# The last 4 instructions that restore RIP, RSP and R15 (needed
	# as tmp reg) need to be atomic from the point of view of
	# .Lsetup_exception_handler.
	#
	# The reason is that .Lsetup_exception_handler can interrupt us in the
	# middle and the nested exception handler that it injects would mess
	# with %gs:SGX_TMP_RIP when it calls us to return (%gs:SGX_TMP_RIP is a
	# single memory location per thread, so not re-entry save).
	#
	# Since they are not atomic, .Lsetup_exception_handler will emulate this
	# behavior if it gets called while executing them (see there).

	# RSP currently points to RIP so need relative addressing to restore RIP, R15, and RSP
	movq SGX_CPU_CONTEXT_RIP - SGX_CPU_CONTEXT_RIP(%rsp), %r15
	movq %r15, %gs:SGX_TMP_RIP
.Ltmp_rip_saved0:
	movq SGX_CPU_CONTEXT_R15 - SGX_CPU_CONTEXT_RIP(%rsp), %r15
.Ltmp_rip_saved1:
	movq SGX_CPU_CONTEXT_RSP - SGX_CPU_CONTEXT_RIP(%rsp), %rsp
.Ltmp_rip_saved2:
	jmp *%gs:SGX_TMP_RIP
	.cfi_endproc

	# void __save_xregs(PAL_XREGS_STATE* xsave_area)
	#   RDI: argument: pointer to xsave_area
	#   R11: return address: in order to not touch stack
	#                        In some situations, stack isn't available.
	#   RAX, RDX: clobbered
	.global __save_xregs
	.type __save_xregs, @function
__save_xregs:
	.cfi_startproc
	movl g_xsave_enabled(%rip), %eax
	cmpl $0, %eax
	jz 1f

	# clear xsave header
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
	jmp *%r11
1:
	fxsave64 (%rdi)
	jmp *%r11
	.cfi_endproc

	# void save_xregs(PAL_XREGS_STATE* xsave_area)
	.global save_xregs
	.type save_xregs, @function
save_xregs:
	.cfi_startproc
	popq %r11
	jmp __save_xregs
	.cfi_endproc

	# void restore_xregs(const PAL_XREGS_STATE* xsave_area)
	#   RDI: argument: pointer to xsave_area
	#   R11: return address: in order to not touch stack
	#                        In some situations, stack isn't available.
	#   RAX, RDX: clobbered
	.global __restore_xregs
	.type __restore_xregs, @function
__restore_xregs:
	.cfi_startproc
	movl g_xsave_enabled(%rip), %eax
	cmpl $0, %eax
	jz 1f

	movl $0xffffffff, %eax
	movl $0xffffffff, %edx
	xrstor64 (%rdi)
	jmp *%r11
1:
	fxrstor64 (%rdi)
	jmp *%r11
	.cfi_endproc

	# void restore_xregs(const PAL_XREGS_STATE* xsave_area)
	.global restore_xregs
	.type restore_xregs, @function
restore_xregs:
	.cfi_startproc
	popq %r11
	jmp __restore_xregs
	.cfi_endproc

#ifdef DEBUG
	# CFI "trampoline" to make GDB happy. GDB normally does not handle switching stack in the
	# middle of backtrace (which is what happens when we exit the enclave), unless the function
	# doing it is called __morestack.
	#
	# To make GDB backtrace work, we make sure that the first function outside of enclave
	# (sgx_entry) has a return address on stack, pointing inside __morestack. We will not actually
	# return to this function (sgx_entry performs EENTER to go back to enclave), but GDB will make a
	# stack frame for it.
	#
	# The function contains CFI directives to make sure that all callee-saved registers can be
	# recovered. They should reflect the situation during EEXIT in code above.

	.global __morestack
	.type __morestack, @function
__morestack:
	.cfi_startproc

	# Callee-saved registers:

	# RIP, RSP: deduced from current RBP (which was not cleared in debug mode)
	.cfi_def_cfa %rbp, 16

	# RBP, RBX: saved on stack (at the beginning of sgx_ocall)
	.cfi_offset %rbp, -16
	.cfi_offset %rbx, -24

	# R12, R13, R14, R15: not changed (not cleared in debug mode)

	nop
.Lfor_cfa_debug_info:
	nop

	.cfi_endproc
#endif
