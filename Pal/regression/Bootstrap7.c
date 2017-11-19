/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal_debug.h"

int main (int argc, char ** argv, char ** envp)
{
    /* check if the programriables in the manifest should appear  is loaded */
    pal_printf("User Program Started\n");

    /* check control block */
    /* print all environmental variables */
    /* environmental variables in Manifest should appear */
    for (int i = 0; envp[i]; i++) {
        pal_printf("%s\n", envp[i]);    
    }

    return 0;
}
