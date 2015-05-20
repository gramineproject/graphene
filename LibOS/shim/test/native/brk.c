/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char ** argv)
{
    char * mem = malloc(40);
    sprintf(mem, "Hello world (%s)!\n", argv[0]);
    printf("%s", mem);
    return 0;
}
