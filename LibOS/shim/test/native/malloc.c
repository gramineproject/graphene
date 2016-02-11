/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdlib.h>
#include <stdio.h>

int main(int argc, char ** argv)
{
    for (int i = 0 ; i < 100000 ; i++) {
        malloc(16);
        malloc(32);
        malloc(64);
        malloc(128);
        malloc(256);
        malloc(512);
    }
    return 0;
}
