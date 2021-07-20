#include "asm-offsets.h"
#include "sgx_arch.h"

.intel_syntax noprefix

.macro DIE
.Linf_loop\@:
    ud2
    jmp .Linf_loop\@
.endm

.global enclave_entry
.type enclave_entry, @function
.align 0x10
enclave_entry:
    .cfi_startproc
    .cfi_undefined rsp
    .cfi_undefined rip
    lea rsp, [rip + g_default_rflags]
    popfq

    inc BYTE PTR gs:[SGX_CSSA]

    test rax, rax
    jz enclave_entry_ecall
    cmp rax, 1
    je enclave_entry_event
    # unreachable, just sanity check
    DIE
    .cfi_endproc

.type enclave_entry_ecall, @function
enclave_entry_ecall:
    # rbx - TCS address, rcx - return address, both trusted
    # rdi - ecall index, rsi - ecall args, both untrused
    .cfi_startproc
    mov rsp, gs:[SGX_INITIAL_STACK_ADDR]
    xor ebp, ebp

    fldcw [rip + g_xsave_reset_state + XSAVE_FPUCWD_OFFSET]
    ldmxcsr [rip + g_xsave_reset_state + XSAVE_MXCSR_OFFSET]

    mov gs:[SGX_ECALL_RETURN_ADDR], rcx

    # void handle_ecall(long ecall_index,       // rdi, already set
    #                   void* ecall_args,       // rsi, already set
    #                   void* enclave_base_addr // rdx
    # );
    mov rdx, rbx
    sub rdx, gs:[SGX_TCS_OFFSET]
    call handle_ecall
    # handle_ecall returns only on errors, but we have no good way to handle them
    DIE
    .cfi_endproc

.type enclave_entry_event, @function
enclave_entry_event:
    # rbx - TCS address, rcx - return address, both trusted
    # rdi - event code, untrusted
    .cfi_startproc
    mov rbx, rcx
    cmp QWORD PTR gs:[SGX_READY_FOR_EXCEPTIONS], 0
    je enclave_exit

    mov rsp, gs:[SGX_SIG_STACK_TOP]
    xor ebp, ebp

    fldcw [rip + g_xsave_reset_state + XSAVE_FPUCWD_OFFSET]
    ldmxcsr [rip + g_xsave_reset_state + XSAVE_MXCSR_OFFSET]

    mov rdx, gs:[SGX_SSA]
    lea rsi, [rdx + SSA_FRAME_SIZE - SGX_GPR_SIZE]

    # all 3 args already set
    call _DkExceptionHandler

    # rbx already set
    jmp enclave_exit
    .cfi_endproc

.global enclave_thread_finished
.type enclave_thread_finished, @function
.align 0x10
enclave_thread_finished:
    .cfi_startproc
    mov QWORD PTR gs:[SGX_READY_FOR_EXCEPTIONS], 0
    mov rax, gs:[SGX_CLEAR_CHILD_TID]
    test rax, rax
    jz .Lskip_ctid_clear
    mov DWORD PTR [rax], 0
.Lskip_ctid_clear:
    mov rbx, gs:[SGX_ECALL_RETURN_ADDR]
    jmp enclave_exit
    .cfi_endproc

.type enclave_exit, @function
.align 0x10
enclave_exit:
    # rbx - return address
    .cfi_startproc
    mov eax, [rip + g_xsave_enabled]
    test eax, eax
    jz .Lfxrstor

    mov eax, 0xffffffff
    mov edx, 0xffffffff
    xrstor64 [rip + g_xsave_reset_state]
    jmp .Lclear_rest

.Lfxrstor:
    fxrstor64 [rip + g_xsave_reset_state]

.Lclear_rest:
    lea rsp, [rip + g_default_rflags]
    popfq

    movzx eax, BYTE PTR gs:[SGX_CSSA]
    mov edx, SSA_FRAME_SIZE
    mul rdx
    mov rdx, gs:[SGX_SSA]
    mov rsp, [rdx + rax - SGX_GPR_SIZE + SGX_GPR_URSP]

    # rax and rbx are used below
    xor ecx, ecx
    xor edx, edx
    xor edi, edi
    xor esi, esi
    xor ebp, ebp
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11
    xor r12, r12
    xor r13, r13
    xor r14, r14
    xor r15, r15

    mov eax, EEXIT
    dec BYTE PTR gs:[SGX_CSSA]
    enclu
    /* Unreachable. */
    .cfi_endproc

.global sgx_ocall
.type sgx_ocall, @function
.global sgx_ocall_div
.type sgx_ocall_div, @function
.align 0x10
sgx_ocall:
    .cfi_startproc
    mov rcx, gs:[SGX_URTS_OCALL_ARGS]
    movzx eax, BYTE PTR gs:[SGX_CSSA]
    dec eax
    mov edx, OCALL_ARGS_SIZE
    mul edx
    add rcx, rax

#ifdef DEBUG
# seriously, **** gdb
.global __morestack
.type __morestack, @function
__morestack:
#endif

    mov [rcx + OCALL_ARGS_CODE], rdi
    mov [rcx + OCALL_ARGS_ARGS], rsi
    mov rdi, [rcx + OCALL_ARGS_PTR]
    xor eax, eax
    xor edx, edx
    mov BYTE PTR [rcx + OCALL_ARGS_IS_OCALL], 1
sgx_ocall_div:
    idiv DWORD PTR [rdi]
    mov rax, [rcx + OCALL_ARGS_CODE]
    ret
    .cfi_endproc
