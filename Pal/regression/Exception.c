/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* This Hello World simply print out "Hello World" */

#include "pal.h"
#include "pal_debug.h"

void handler1 (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    pal_printf("Div-by-Zero Exception Handler 1: %p, rip = %p\n",
               arg, context->rip);

    while (*(unsigned char *) context->rip != 0x90)
        context->rip++;

    DkExceptionReturn(event);
}

void handler2 (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    pal_printf("Div-by-Zero Exception Handler 2: %p, rip = %p\n",
               arg, context->rip);

    while (*(unsigned char *) context->rip != 0x90)
        context->rip++;

    DkExceptionReturn(event);
}

void handler3 (PAL_PTR event, PAL_NUM arg, PAL_CONTEXT * context)
{
    pal_printf("Memory Fault Exception Handler: %p, rip = %p\n",
               arg, context->rip);

    while (*(unsigned char *) context->rip != 0x90)
        context->rip++;

    DkExceptionReturn(event);
}

int main (void)
{
    volatile long i;

    DkSetExceptionHandler(handler1, PAL_EVENT_DIVZERO);
    i = 0;
    i = 1 / i;
    __asm__ volatile("nop");

    DkSetExceptionHandler(handler2, PAL_EVENT_DIVZERO);
    i = 0;
    i = 1 / i;
    __asm__ volatile("nop");

    DkSetExceptionHandler(handler3, PAL_EVENT_MEMFAULT);
    *(volatile long *) 0x1000 = 0;
    __asm__ volatile("nop");

    return 0;
}
