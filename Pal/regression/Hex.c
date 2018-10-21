/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

#include "pal.h"
#include "pal_debug.h"
#include "api.h"
#include "hex.h"

int main() {
    char x[] = {0xde, 0xad, 0xbe, 0xef};
    char y[] = {0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd};
    pal_printf("Hex test 1 is %s\n", alloca_bytes2hexstr(x));
    pal_printf("Hex test 2 is %s\n", alloca_bytes2hexstr(y));
    return 0;
}
