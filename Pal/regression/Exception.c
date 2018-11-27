/* This Hello World simply print out "Hello World" */

#include <stdatomic.h>
#include <inttypes.h>

#include "pal.h"
#include "pal_debug.h"

void handler1 (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    pal_printf("Arithmetic Exception Handler 1: 0x%08lx, rip = 0x%08lx\n",
               arg, context->rip);

    while (*(unsigned char *) context->rip != 0x90)
        context->rip++;

    DkExceptionReturn(event);
}

void handler2 (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    pal_printf("Arithmetic Exception Handler 2: 0x%08lx, rip = 0x%08lx\n",
               arg, context->rip);

    while (*(unsigned char *) context->rip != 0x90)
        context->rip++;

    DkExceptionReturn(event);
}

void handler3 (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    pal_printf("Memory Fault Exception Handler: 0x%08lx, rip = 0x%08lx\n",
               arg, context->rip);

    while (*(unsigned char *) context->rip != 0x90)
        context->rip++;

    DkExceptionReturn(event);
}

atomic_bool handler4_called = false;

void handler4(PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    pal_printf("Arithmetic Exception Handler 4: 0x%" PRIx64 ", rip = 0x%" PRIx64 "\n", arg, context->rip);

    while (*(unsigned char *) context->rip != 0x90)
        context->rip++;

    handler4_called = true;

    DkExceptionReturn(event);
}


static void red_zone_test() {
    uint64_t res = 0;

    // First call some function to ensure that gcc doesn't use the red zone
    // itself.
    pal_printf("Testing red zone...\n");

    __asm__ volatile (
            // Fill the red zone with a pattern (0xaa 0xa9 0xa8 ...)
            "movq $-128, %%rax\n"
            "movq $0xaa, %%rbx\n"
            "1:\n"
            "movb %%bl, (%%rsp, %%rax, 1)\n"
            "decq %%rbx\n"
            "incq %%rax\n"
            "jnz 1b\n"

            // Trigger exception
            "movq $1, %%rax\n"
            "cqo\n"
            "movq $0, %%rbx\n"
            "divq %%rbx\n"
            "nop\n"

            // Calculate sum of pattern
            "movq $-128, %%rax\n"
            "movq $0, %%rbx\n"
            "movq $0, %%rcx\n"
            "1:\n"
            "movb (%%rsp, %%rax, 1), %%bl\n"
            "addq %%rbx, %%rcx\n"
            "incq %%rax\n"
            "jnz 1b\n"
            "movq %%rcx, %q0\n"
            : "=rm"(res)
            :
            : "rax", "rbx", "rcx", "rdx", "cc", "memory");

    if (!handler4_called) {
        pal_printf("Exception handler was not called!\n");
        return;
    }

    if (res != 13632) {
        pal_printf("Sum over red zone (%lu) doesn't match!\n", res);
        return;
    }

    pal_printf("Red zone test ok.\n");
}

int main (void)
{
    volatile long i;

    DkSetExceptionHandler(handler1, PAL_EVENT_ARITHMETIC_ERROR);
    i = 0;
    i = 1 / i;
    __asm__ volatile("nop");

    DkSetExceptionHandler(handler2, PAL_EVENT_ARITHMETIC_ERROR);
    i = 0;
    i = 1 / i;
    __asm__ volatile("nop");

    DkSetExceptionHandler(handler3, PAL_EVENT_MEMFAULT);
    *(volatile long *) 0x1000 = 0;
    __asm__ volatile("nop");

    DkSetExceptionHandler(handler4, PAL_EVENT_ARITHMETIC_ERROR);
    red_zone_test();

    return 0;
}
