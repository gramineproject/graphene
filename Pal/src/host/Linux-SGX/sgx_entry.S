#include "asm-offsets.h"
#include "sgx_arch.h"

.intel_syntax noprefix

.global sgx_ecall
.type sgx_ecall, @function
.global sgx_ecall_pre_cssa_dec
.type sgx_ecall_pre_cssa_dec, @function
.align 0x10
sgx_ecall:
    .cfi_startproc

    push r15
    .cfi_adjust_cfa_offset 8
    push r14
    .cfi_adjust_cfa_offset 8
    push r13
    .cfi_adjust_cfa_offset 8
    push r12
    .cfi_adjust_cfa_offset 8
    push rbx
    .cfi_adjust_cfa_offset 8
    push rbp
    .cfi_adjust_cfa_offset 8

    mov rbx, gs:[PAL_TCB_URTS_TCS]
    lea rcx, [rip + async_exit_pointer]
    mov rax, EENTER

    inc QWORD PTR gs:[PAL_TCB_URTS_EENTER_CNT]
    inc BYTE PTR gs:[PAL_TCB_URTS_CSSA]
    enclu
sgx_ecall_pre_cssa_dec:
    dec BYTE PTR gs:[PAL_TCB_URTS_CSSA]

    pop rbp
    .cfi_adjust_cfa_offset -8
    pop rbx
    .cfi_adjust_cfa_offset -8
    pop r12
    .cfi_adjust_cfa_offset -8
    pop r13
    .cfi_adjust_cfa_offset -8
    pop r14
    .cfi_adjust_cfa_offset -8
    pop r15
    .cfi_adjust_cfa_offset -8

    ret
    .cfi_endproc

.global async_exit_pointer
.type async_exit_pointer, @function
.align 0x10
async_exit_pointer:
    .cfi_startproc
    .cfi_undefined rip
    .cfi_undefined rbp
    mov rbp, rsp
    and rsp, ~0xf

    mov r15, gs:[PAL_TCB_URTS_SELF]
    add r15, PAL_TCB_URTS_OCALL_ARGS_OFF

    movzx eax, BYTE PTR gs:[PAL_TCB_URTS_CSSA]
    dec eax
    mov edx, OCALL_ARGS_SIZE
    mul edx
    add r15, rax

    xor eax, eax
    # lock just to be explicit
    lock xchg [r15 + OCALL_ARGS_IS_OCALL], al
    test eax, eax
    jnz .Laex_is_ocall

    inc QWORD PTR gs:[PAL_TCB_URTS_AEX_CNT]
#ifdef DEBUG
    mov rdi, rbx
    call sgx_profile_sample_aex
#endif
    jmp .Laex_eresume

.Laex_is_ocall:
#ifdef DEBUG
    sub rsp, 0x10
    mov rdi, rbx
    mov rsi, rsp
    call get_sgx_gpr_addr
    lea rdx, [rip + Lmorestack_for_gdb_bt]
    mov [rsp + 8], rdx
    .cfi_def_cfa rsp, 0
    .cfi_rel_offset rbp, 0
    .cfi_rel_offset rip, 8
    mov rdx, [rsp]
#endif

    mov rdi, [r15 + OCALL_ARGS_CODE]
    mov rsi, [r15 + OCALL_ARGS_ARGS]
    call sgx_entry
    mov [r15 + OCALL_ARGS_CODE], rax

    mov rdi, r15
    call fixup_ocall_args_ptrs
#ifdef DEBUG
    add rsp, 0x10
#endif

.Laex_eresume:
    mov DWORD PTR gs:[PAL_TCB_URTS_LAST_ASYNC_EVENT], 0
    mov rsp, rbp

    lea rcx, [rip + async_exit_pointer]
    # rbx already set
    mov rax, ERESUME
    enclu
    # Unreachable
    .cfi_endproc

.global sgx_raise
.type sgx_raise, @function
sgx_raise:
    jmp sgx_ecall

.global eresume_pointer
.type eresume_pointer, @function
eresume_pointer:
    enclu

#ifdef DEBUG
.global __morestack
.type __morestack, @function
__morestack:
    .cfi_startproc
    .cfi_def_cfa rbp, 0
    .cfi_rel_offset rip, SGX_GPR_RIP
    .cfi_rel_offset rbp, SGX_GPR_RBP
    .cfi_rel_offset rsp, SGX_GPR_RSP
    .cfi_rel_offset rbx, SGX_GPR_RBX
    .cfi_rel_offset r12, SGX_GPR_R12
    .cfi_rel_offset r13, SGX_GPR_R13
    .cfi_rel_offset r14, SGX_GPR_R14
    .cfi_rel_offset r15, SGX_GPR_R15
    nop
Lmorestack_for_gdb_bt:
    nop
    .cfi_endproc
#endif
