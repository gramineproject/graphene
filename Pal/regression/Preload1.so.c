/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal.h"
#include "pal_debug.h"

void preload_func1 (void)
{
    pal_printf("Preloaded Function 1 Called\n");
}

int main (int argc, char ** argv, char ** envp)
{
    pal_printf("Binary 1 Preloaded\n");
    return 0;
}
