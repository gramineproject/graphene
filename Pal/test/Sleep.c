/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* This Hello World simply print out "Hello World" */

#include "pal.h"
#include "pal_debug.h"

char str[13];

int main (int argc, char ** argv, char ** envp)
{
    long sleeping = 3000000;

    if (argc > 1) {
        const char * c = argv[1];
        sleeping = 0;
        while (*c) {
            if ((*c) > '9' || (*c) < '0')
                break;
            sleeping *= 10;
            sleeping += (*c) - '0';
            c++;
        }
    }

    pal_printf("Enter Main Thread\n");

    if (sleeping) {
        pal_printf("Sleeping %ld microsecond...\n", sleeping);
        DkThreadDelayExecution(sleeping);
    } else {
        while (1);
    }

    pal_printf("Leave Main Thread\n");
    return 0;
}
