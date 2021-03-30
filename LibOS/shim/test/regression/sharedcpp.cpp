#include <iostream>

extern "C" void f2() {
    throw std::runtime_error("test runtime error");
}

extern "C" void f1();
__asm__ (
".global f1\n"
".type f1, @function\n"
"f1:\n"
".cfi_startproc\n"
"push %rbp\n"
".cfi_adjust_cfa_offset 8\n"
".cfi_rel_offset %rbp, 0\n"
"push %rbx\n"
".cfi_adjust_cfa_offset 8\n"
".cfi_rel_offset %rbx, 0\n"
"push %r15\n"
".cfi_adjust_cfa_offset 8\n"
".cfi_rel_offset %r15, 0\n"
"push %r14\n"
".cfi_adjust_cfa_offset 8\n"
".cfi_rel_offset %r14, 0\n"
"push %r13\n"
".cfi_adjust_cfa_offset 8\n"
".cfi_rel_offset %r13, 0\n"
"push %r12\n"
".cfi_adjust_cfa_offset 8\n"
".cfi_rel_offset %r12, 0\n"
"sub $8, %rsp\n"
".cfi_adjust_cfa_offset 8\n"

"mov $0x111, %rbp\n"
"mov $0x222, %rbx\n"
"mov $0x333, %r15\n"
"mov $0x444, %r14\n"
"mov $0x555, %r13\n"
"mov $0x666, %r12\n"
"call f2\n"

"add $8, %rsp\n"
".cfi_adjust_cfa_offset -8\n"
"pop %r12\n"
".cfi_adjust_cfa_offset -8\n"
".cfi_restore %r12\n"
"pop %r13\n"
".cfi_adjust_cfa_offset -8\n"
".cfi_restore %r13\n"
"pop %r14\n"
".cfi_adjust_cfa_offset -8\n"
".cfi_restore %r14\n"
"pop %r15\n"
".cfi_adjust_cfa_offset -8\n"
".cfi_restore %r15\n"
"pop %rbx\n"
".cfi_adjust_cfa_offset -8\n"
".cfi_restore %rbx\n"
"pop %rbp\n"
".cfi_adjust_cfa_offset -8\n"
".cfi_restore %rbp\n"
"ret\n"
".cfi_endproc\n"
);

extern "C" void f0() {
    try {
        f1();
    } catch (const std::exception& e) {
        std::cout << "Exception '" << e.what() << "' caught" << std::endl;
    }
}
