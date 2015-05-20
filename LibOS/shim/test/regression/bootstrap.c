/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdio.h>

int main(int argc, const char ** argv, const char ** envp)
{
    printf("User Program Started\n");

    printf("# of Arguments: %d\n", argc);

    for (int i = 0 ; i < argc ; i++)
        printf("argv[%d] = %s\n", i, argv[i]);

    return 0;
}
