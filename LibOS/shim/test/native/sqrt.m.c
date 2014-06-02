/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include <stdio.h>
#include <math.h>

int main(int argc, char ** argv) {
    float x;

    printf("enter a float: ");
    fflush(stdin);
    scanf("%f", &x);
    printf("sqrt(x) = %f\n", sqrt(x));

    return 0;
}
